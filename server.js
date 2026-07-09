// QA AI Platform — Local Proxy (Claude AI + Jira)
// Run with: node server.js
// Keep this terminal open while using the app.
//
// ── DevOps Deployment ────────────────────────────────────────────────────────
// Branch  : platform_side
// To run  :
//   git clone https://github.com/mohammadaghbar-boop/qa-ai-platform.git
//   cd qa-ai-platform
//   git checkout platform_side
//   docker compose up
//
// Access  : http://server-ip:3456
//
// Notes   :
//   - Port 3456 (override with PORT env var)
//   - k6 is bundled inside Docker — no separate install needed
//   - Sessions are in-memory — if container restarts, members must log out and back in
//   - Per-member credentials (Jira, etc.) are managed inside the app
//   - Optional .env (see .env.example) sets ANTHROPIC_API_KEY for non-interactive Claude CLI billing
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

// Prevent unhandled errors from crashing the server
process.on('uncaughtException', err => console.error('[Server] Uncaught exception:', err.message));
process.on('unhandledRejection', err => console.error('[Server] Unhandled rejection:', err && err.message));

// In-memory session store: token -> { memberId, jiraUrl, jiraAuth, createdAt }
const sessions = new Map();
function createSession(memberId, jiraUrl, jiraEmail, jiraToken) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    memberId,
    jiraUrl:  jiraUrl  || '',
    jiraAuth: (jiraEmail && jiraToken) ? Buffer.from(jiraEmail + ':' + jiraToken).toString('base64') : '',
    createdAt: Date.now()
  });
  return token;
}
function getSession(req) {
  const token = req.headers['x-session-token'];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() - s.createdAt > API_SESSION_TTL) { sessions.delete(token); return null; }
  return s;
}

// Hourly cleanup of expired sessions across all stores
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions)      if (now - s.createdAt > API_SESSION_TTL)   sessions.delete(t);
  for (const [t, s] of adminSessions) if (now - s.createdAt > ADMIN_SESSION_TTL) adminSessions.delete(t);
  for (const [t, s] of memberSessions) if (now - (s.createdAt || 0) > ADMIN_SESSION_TTL) memberSessions.delete(t);
}, 60 * 60 * 1000);

/* ── Configuration ──────────────────────────────────────────────────────── */
const PORT              = parseInt(process.env.PORT) || 3456;
const MAX_BODY          = 20 * 1024 * 1024; // 20 MB per request
const REQ_TIMEOUT       = 30000;            // 30 s for outgoing HTTP requests
const API_SESSION_TTL   = 24 * 60 * 60 * 1000; // 24 h — API/Jira credential sessions
const ADMIN_SESSION_TTL =  8 * 60 * 60 * 1000; // 8 h  — admin + member login sessions

// Empty MCP config — prevents claude CLI from using MCP tools (e.g. Atlassian)
const EMPTY_MCP = path.join(os.tmpdir(), 'qa-platform-no-mcp.json');
fs.writeFileSync(EMPTY_MCP, JSON.stringify({ mcpServers: {} }));

/* ── Rate limiter (login endpoints) ─────────────────────────────────────── */
const loginAttempts = new Map(); // ip -> { count, resetAt }
function checkRateLimit(ip) {
  return true; // TEMPORARILY DISABLED for testing — re-enable before rolling out to the team
  const now = Date.now();
  let e = loginAttempts.get(ip);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + 15 * 60 * 1000 };
  e.count++;
  loginAttempts.set(ip, e);
  return e.count <= 10; // 10 attempts per 15 min
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of loginAttempts) if (now > e.resetAt) loginAttempts.delete(ip);
}, 5 * 60 * 1000);

/* ── Input validators & sanitizers ──────────────────────────────────────── */
function sanitizeFilename(name) {
  return String(name || 'file').replace(/[^\w.\-]/g, '_').slice(0, 100);
}
function sanitizeK6Duration(d) {
  return /^\d+[smh]$/.test(String(d || '')) ? String(d) : '30s';
}
function isValidHttpUrl(s) {
  try { const u = new URL(s); return u.protocol === 'http:' || u.protocol === 'https:'; } catch { return false; }
}
// SSRF guard: only allow public HTTPS Jira URLs
function isValidJiraUrl(s) {
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|169\.254\.)/.test(h)) return false;
    return true;
  } catch { return false; }
}
// SSRF guard for git remotes: public HTTPS only — blocks file://, ext::, ssh:// tricks and internal IPs
function isValidGitUrl(s) {
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|169\.254\.)/.test(h)) return false;
    if (s.startsWith('-')) return false;
    return true;
  } catch { return false; }
}

/* ── File-based data store (admin dashboard sync) ───────────────────────── */
const DATA_DIR  = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'qa-platform-db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

/* ── Credential encryption (AES-256-GCM, server key in data/server.key) ─── */
const KEY_FILE = path.join(DATA_DIR, 'server.key');
let _encKey;
if (fs.existsSync(KEY_FILE)) {
  _encKey = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
} else {
  _encKey = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, _encKey.toString('hex'));
  console.log('  ℹ  New encryption key generated at data/server.key — back this file up.');
}
function encryptField(text) {
  const iv  = crypto.randomBytes(12);
  const c   = crypto.createCipheriv('aes-256-gcm', _encKey, iv);
  const enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return iv.toString('hex') + ':' + c.getAuthTag().toString('hex') + ':' + enc.toString('hex');
}
function decryptField(stored) {
  const [ivH, tagH, dataH] = stored.split(':');
  const d = crypto.createDecipheriv('aes-256-gcm', _encKey, Buffer.from(ivH, 'hex'));
  d.setAuthTag(Buffer.from(tagH, 'hex'));
  return d.update(Buffer.from(dataH, 'hex')) + d.final('utf8');
}
function encryptMemberCredentials(jiraUrl, jiraEmail, jiraToken) {
  return {
    jiraUrl:   jiraUrl   ? encryptField(jiraUrl)   : '',
    jiraEmail: jiraEmail ? encryptField(jiraEmail) : '',
    jiraToken: jiraToken ? encryptField(jiraToken) : ''
  };
}
function decryptMemberCredentials(member) {
  const c = member.credentials;
  if (!c) return null;
  try {
    return {
      jiraUrl:   c.jiraUrl   ? decryptField(c.jiraUrl)   : '',
      jiraEmail: c.jiraEmail ? decryptField(c.jiraEmail) : '',
      jiraToken: c.jiraToken ? decryptField(c.jiraToken) : ''
    };
  } catch { return null; }
}
function loadServerDB() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch {}
  return { sessions: [], bugs: [], perfResults: [], coverage: [], members: [], adminPasswordHash: null, adminPasswordIsDefault: true };
}
function saveServerDB(db) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}
let serverDB = loadServerDB();

function hashPasswordSecure(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(p, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}
function verifyPassword(p, stored) {
  if (!stored) return false;
  if (stored.startsWith('scrypt:')) {
    const parts = stored.split(':');
    if (parts.length !== 3) return false;
    const [, salt, hash] = parts;
    try {
      const derived = crypto.scryptSync(p, salt, 64).toString('hex');
      return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(hash, 'hex'));
    } catch { return false; }
  }
  // Legacy SHA-256 — constant-time compare
  const legacy = crypto.createHash('sha256').update(p).digest('hex');
  return legacy.length === stored.length &&
    crypto.timingSafeEqual(Buffer.from(legacy, 'hex'), Buffer.from(stored, 'hex'));
}

// Set default admin password to 'admin' on first run
if (!serverDB.adminPasswordHash) {
  serverDB.adminPasswordHash = hashPasswordSecure('admin');
  serverDB.adminPasswordIsDefault = true;
  saveServerDB(serverDB);
  console.log('');
  console.log('  ℹ  Default admin credentials: admin / admin');
  console.log('  You will be prompted to change the password on first login.');
  console.log('');
}
// Migration: existing db without the isDefault flag — reset to admin so forced change runs
if (serverDB.adminPasswordIsDefault === undefined) {
  serverDB.adminPasswordHash = hashPasswordSecure('admin');
  serverDB.adminPasswordIsDefault = true;
  saveServerDB(serverDB);
  console.log('');
  console.log('  ℹ  Admin password reset to default (admin). Change it on next login.');
  console.log('');
}

// In-memory admin sessions (cleared on server restart — admin re-logs in)
const adminSessions = new Map();
// Member sessions — persisted to disk so server restarts don't log members out
const MEMBER_SESSIONS_FILE = path.join(__dirname, 'data', 'member-sessions.json');
const memberSessions = (() => {
  const m = new Map();
  try {
    const raw = JSON.parse(fs.readFileSync(MEMBER_SESSIONS_FILE, 'utf8'));
    const cutoff = Date.now() - 8 * 60 * 60 * 1000;
    for (const [k, v] of Object.entries(raw)) {
      if (v.createdAt > cutoff) m.set(k, v);
    }
  } catch {}
  return m;
})();
function saveMemberSessions() {
  try {
    fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
    const obj = {};
    for (const [k, v] of memberSessions) obj[k] = v;
    fs.writeFileSync(MEMBER_SESSIONS_FILE, JSON.stringify(obj));
  } catch {}
}
// Playwright codegen sessions
const codegenSessions = new Map();
// Expire codegen sessions older than 2 hours and kill any lingering processes
setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 60 * 1000;
  for (const [id, s] of codegenSessions) {
    if (s.startedAt < cutoff) {
      if (s.status === 'running') { try { s.proc.kill(); } catch {} }
      codegenSessions.delete(id);
    }
  }
}, 30 * 60 * 1000);

/* ── Attached-project repo cache (frontend/backend Git URLs) ─────────────── */
const REPO_CACHE_DIR = path.join(os.tmpdir(), 'qa-platform-repo-cache');
if (!fs.existsSync(REPO_CACHE_DIR)) fs.mkdirSync(REPO_CACHE_DIR, { recursive: true });
const REPO_CONTEXT_MAX_CHARS = 60000; // cap combined source dump fed to the AI prompt
const REPO_CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.vue', '.html']);
const REPO_SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', 'out']);

function repoCacheDirFor(url) {
  return path.join(REPO_CACHE_DIR, crypto.createHash('sha1').update(url).digest('hex'));
}
// git's stderr mixes progress noise ("Cloning into '...'", "remote: Enumerating objects...")
// with the actual problem, and the real fatal/error/warning line is not reliably the last one
// — e.g. "warning: Clone succeeded, but checkout failed" is followed by a "and retry with
// 'git restore ...'" hint line. Prefer lines that actually say fatal:/error:/warning:; only
// fall back to "last non-empty line" if none of those are present. A spawn-level error (a
// real timeout, git missing) always takes priority — it means there is no useful git output.
function extractGitError(r) {
  if (r.error) return r.error.code === 'ETIMEDOUT' ? 'git operation timed out' : r.error.code === 'ENOENT' ? 'git is not installed on the server' : r.error.message;
  const lines = (r.stderr || Buffer.from('')).toString('utf8').trim().split('\n').map(l => l.trim()).filter(Boolean);
  const problemLines = lines.filter(l => /^(fatal|error|warning):/i.test(l));
  if (problemLines.length) return problemLines.join(' ');
  return lines[lines.length - 1] || 'unknown error';
}
// Fast reachability check without a full clone. GIT_TERMINAL_PROMPT=0 stops git from
// hanging on an interactive credential prompt for private/unreachable repos.
function checkGitReachable(url) {
  const { spawnSync } = require('child_process');
  const r = spawnSync('git', ['ls-remote', '--exit-code', url, 'HEAD'], {
    timeout: 12000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }
  });
  if (r.error || r.status !== 0) return { ok: false, error: extractGitError(r) };
  return { ok: true };
}
function syncRepoCache(url) {
  const { spawnSync } = require('child_process');
  const dir = repoCacheDirFor(url);
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
  // Always re-clone fresh rather than `git pull` an existing shallow clone — shallow history
  // has no common ancestor to merge against and reliably produces "refusing to merge unrelated
  // histories" on a second pull, even against the exact same unchanged remote.
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  fs.mkdirSync(dir, { recursive: true });
  // core.longpaths=true: without it, Windows' 260-char MAX_PATH silently breaks checkout on
  // repos with deeply nested paths ("unable to create file ...: Filename too long"), even
  // though an interactive shell's git may succeed due to a different resolved gitconfig.
  const r = spawnSync('git', ['-c', 'core.longpaths=true', 'clone', '--depth', '1', url, dir], { timeout: 120000, env });
  if (r.error || r.status !== 0) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    return { ok: false, error: 'Failed to clone repo: ' + extractGitError(r) };
  }
  return { ok: true, dir };
}
// Walk the cloned repo and build a size-capped text bundle for the AI prompt.
function collectRepoContext(dir) {
  const parts = [];
  let total = 0, truncated = false;
  const pkgFile = path.join(dir, 'package.json');
  if (fs.existsSync(pkgFile)) {
    const pkg = fs.readFileSync(pkgFile, 'utf8').slice(0, 2000);
    parts.push(`--- package.json ---\n${pkg}`);
    total += pkg.length;
  }
  const walk = (d) => {
    if (truncated) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (truncated) return;
      if (e.name.startsWith('.') || REPO_SKIP_DIRS.has(e.name)) continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!REPO_CODE_EXT.has(path.extname(e.name))) continue;
      let content;
      try { content = fs.readFileSync(full, 'utf8'); } catch { continue; }
      const rel = path.relative(dir, full);
      const chunk = `--- ${rel} ---\n${content}\n`;
      if (total + chunk.length > REPO_CONTEXT_MAX_CHARS) { truncated = true; return; }
      parts.push(chunk); total += chunk.length;
    }
  };
  walk(dir);
  return { context: parts.join('\n'), truncated };
}

/* ── Claude AI (via Claude CLI — no API key required) ───────────────────── */
function callClaude(messages, system, maxTokens=4000) {
  return new Promise((resolve, reject) => {
    const fullPrompt = messages.map(m =>
      (m.role === 'user' ? 'Human' : 'Assistant') + ': ' + m.content
    ).join('\n\n');
    const isWin = process.platform === 'win32';
    const claudeCmd = isWin ? 'cmd' : 'claude';
    // --allowedTools "" disables every built-in tool (Write/Edit/Bash/Read/...) — without it, the
    // CLI can decide on its own to try editing a file in its cwd, hit a permission gate it can't
    // resolve headlessly, and dump the resulting "I need permission to write it..." dialogue into
    // what should have been pure generated text. This call must never be agentic, only text-in/text-out.
    //
    // The system role is passed via the CLI's own --system-prompt flag, NOT concatenated as a fake
    // "[System: ...]" text block in front of the conversation — that shape is textbook prompt
    // injection (an untrusted-looking system directive embedded in user content), and the model can
    // correctly refuse the entire request on sight when it spots that pattern, especially once
    // real repo source is also in the prompt (from the attached-project feature) making the whole
    // thing look like an injection test case rather than a legitimate instruction.
    const baseArgs = ['-p', '--output-format', 'text', '--effort', 'low', '--strict-mcp-config', '--mcp-config', EMPTY_MCP, '--allowedTools', ''];
    if (system) baseArgs.push('--system-prompt', system);
    const claudeArgs = isWin
      ? ['/c', process.env.APPDATA + '\\npm\\claude.cmd', ...baseArgs]
      : baseArgs;
    const proc = spawn(claudeCmd, claudeArgs, { shell: false, env: process.env });
    let output = '', error = '';
    proc.stdin.write(fullPrompt);
    proc.stdin.end();
    proc.stdout.on('data', d => output += d.toString());
    proc.stderr.on('data', d => error  += d.toString());
    const timer = setTimeout(() => {
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { shell: true, stdio: 'ignore' });
        } else {
          proc.kill('SIGTERM');
        }
      } catch {}
      reject(new Error('AI request timed out after 10 minutes. Try selecting fewer test cases at once.'));
    }, 600000);
    proc.on('close', code => {
      clearTimeout(timer);
      if (code === 0 && output.trim()) resolve(output.trim());
      else reject(new Error(error.trim() || 'claude CLI returned no output (exit ' + code + ')'));
    });
    proc.on('error', err => { clearTimeout(timer); reject(new Error('Could not start claude CLI: ' + err.message)); });
  });
}

/* ── UI Design Testing helpers ───────────────────────────────────────────── */
function parseFigmaUrl(urlStr) {
  try {
    let s = (urlStr || '').trim();
    // Auto-add https:// if missing
    if (s && !s.startsWith('http')) s = 'https://' + s;
    const u = new URL(s);
    if (!u.hostname.endsWith('figma.com')) return null;
    // Accept /design/, /file/, /proto/, /board/
    const match = u.pathname.match(/\/(design|file|proto|board)\/([a-zA-Z0-9_-]+)/);
    if (!match) return null;
    const fileKey = match[2];
    let nodeId = u.searchParams.get('node-id') || null;
    if (nodeId) nodeId = nodeId.replace(/-/g, ':');
    return { fileKey, nodeId };
  } catch { return null; }
}

function figmaRequest(apiPath, figmaToken) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: 'api.figma.com', path: apiPath, method: 'GET', timeout: REQ_TIMEOUT,
      headers: { 'X-Figma-Token': figmaToken, 'Accept': 'application/json' }
    };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', chunk => data += chunk.toString());
      res.on('end', () => { try { const body = JSON.parse(data); if (res.statusCode !== 200) console.log('[Figma RAW]', res.statusCode, JSON.stringify(body)); resolve({ status: res.statusCode, body }); } catch { console.log('[Figma RAW non-JSON]', res.statusCode, data.substring(0,200)); reject(new Error('Invalid JSON from Figma API')); } });
    });
    req.on('timeout', () => { req.destroy(new Error('Figma API timeout')); });
    req.on('error', reject);
    req.end();
  });
}

function downloadImageUrl(imageUrl) {
  const doFetch = (urlStr) => new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const mod = u.protocol === 'https:' ? https : http;
    const opts = { hostname: u.hostname, path: u.pathname + u.search, method: 'GET', timeout: REQ_TIMEOUT, headers: { 'Accept': 'image/png,image/*' } };
    const req = mod.request(opts, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return doFetch(res.headers.location).then(resolve).catch(reject);
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('timeout', () => { req.destroy(new Error('Image download timeout')); });
    req.on('error', reject);
    req.end();
  });
  return doFetch(imageUrl);
}

function callClaudeWithImages(prompt, imagePaths = []) {
  return new Promise((resolve, reject) => {
    const isWin = process.platform === 'win32';
    const claudeExe = isWin ? (process.env.APPDATA + '\\npm\\claude.cmd') : 'claude';
    const mcpFlags = ['--strict-mcp-config', '--mcp-config', EMPTY_MCP];
    const baseArgs = ['-p', '--verbose', '--output-format', 'stream-json', '--input-format', 'stream-json', '--effort', 'low', ...mcpFlags];
    // Build stream-json message with images
    const content = [];
    for (const imgPath of imagePaths) {
      try {
        const imgData = fs.readFileSync(imgPath).toString('base64');
        const ext = path.extname(imgPath).toLowerCase();
        const mediaType = (ext === '.jpg' || ext === '.jpeg') ? 'image/jpeg' : 'image/png';
        content.push({ type: 'image', source: { type: 'base64', media_type: mediaType, data: imgData } });
      } catch (e) { console.error('[UID] Failed to read image:', imgPath, e.message); }
    }
    content.push({ type: 'text', text: prompt });
    const msgJson = JSON.stringify({ type: 'user', message: { role: 'user', content } });
    // Write to temp file then stream into stdin to handle large image data
    const tmpInput = path.join(os.tmpdir(), 'qa_claude_in_' + crypto.randomBytes(6).toString('hex') + '.json');
    fs.writeFileSync(tmpInput, msgJson + '\n', 'utf8');
    const claudeArgs = isWin
      ? ['/c', claudeExe, ...baseArgs]
      : baseArgs;
    const proc = spawn(isWin ? 'cmd' : 'claude', claudeArgs, { shell: false, env: process.env });
    let output = '', error = '';
    proc.stdout.on('data', d => output += d.toString());
    proc.stderr.on('data', d => error  += d.toString());
    // Suppress EPIPE — Claude CLI may close stdin before we finish streaming
    proc.stdin.on('error', () => {});
    // Stream file into stdin (handles large payloads without pipe buffer overflow)
    const inputStream = fs.createReadStream(tmpInput);
    inputStream.pipe(proc.stdin);
    inputStream.on('error', err => { try { proc.stdin.destroy(); } catch {} reject(new Error('Input stream error: ' + err.message)); });
    const cleanup = () => { try { fs.unlinkSync(tmpInput); } catch {} };
    const timer = setTimeout(() => {
      cleanup();
      try { if (isWin) { spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { shell: true, stdio: 'ignore' }); } else { proc.kill('SIGTERM'); } } catch {}
      reject(new Error('AI request timed out after 10 minutes.'));
    }, 600000);
    proc.on('close', code => {
      clearTimeout(timer); cleanup();
      if (code === 0 && output.trim()) {
        // Parse stream-json output — concatenate all text deltas
        let text = '';
        for (const line of output.split('\n')) {
          const t = line.trim();
          if (!t) continue;
          try {
            const ev = JSON.parse(t);
            if (ev.type === 'content_block_delta' && ev.delta && ev.delta.type === 'text_delta') {
              text += ev.delta.text || '';
            } else if (ev.type === 'result' && ev.result) {
              // Fallback: top-level result field
              text = ev.result;
            }
          } catch {}
        }
        if (text.trim()) resolve(text.trim());
        else resolve(output.trim()); // fallback: return raw if parsing yields nothing
      } else {
        reject(new Error(error.trim() || 'claude CLI returned no output (exit ' + code + ')'));
      }
    });
    proc.on('error', err => { clearTimeout(timer); cleanup(); reject(new Error('Could not start claude CLI: ' + err.message)); });
  });
}

/* ── Jira Proxy ─────────────────────────────────────────────────────────── */
function proxyJira(jiraUrl, jiraPath, method, auth, body) {
  return new Promise((resolve, reject) => {
    if (!jiraUrl || !isValidJiraUrl(jiraUrl)) {
      reject(new Error('Invalid Jira URL. Must be a public HTTPS address.')); return;
    }
    // Use only the origin (protocol + hostname) — strip any path the user may have pasted
    const baseUrl = new URL(jiraUrl).origin;
    // Paths starting with /rest/ but not /rest/api/3 are raw plugin paths (e.g. AIOTest, Zephyr)
    const fullPath = jiraPath.startsWith('/rest/') && !jiraPath.startsWith('/rest/api/')
      ? baseUrl + jiraPath
      : baseUrl + '/rest/api/3' + jiraPath;
    const url  = new URL(fullPath);
    const opts = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   method,
      timeout:  REQ_TIMEOUT,
      headers:  {
        'Authorization': 'Basic ' + auth,
        'Content-Type':  'application/json',
        'Accept':        'application/json'
      }
    };
    const req = https.request(opts, res => {
      const chunks = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const data = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          reject(new Error('Jira ' + res.statusCode + ': ' + data.slice(0, 200)));
        } else {
          try {
            const parsed = JSON.parse(data);
            // Debug: log description field info to server console
            if (parsed && parsed.fields !== undefined) {
              const desc = parsed.fields.description;
              const rendered = parsed.renderedFields?.description;
              console.log('[Jira] fields.description:', desc === null ? 'NULL' : desc === undefined ? 'UNDEFINED' : (typeof desc === 'string' ? `string(${desc.length})` : `ADF(${JSON.stringify(desc).length}b)`));
              console.log('[Jira] renderedFields.description:', rendered == null ? 'ABSENT' : `html(${rendered.length})`);
            }
            resolve(parsed);
          }
          catch (e) { reject(new Error('Jira response parse error: ' + e.message)); }
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('Jira request timed out')); });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

/* ── Jira Attachment Upload ─────────────────────────────────────────────── */
function attachToJira(jiraUrl, issueKey, auth, files) {
  return new Promise((resolve, reject) => {
    if (!jiraUrl || !isValidJiraUrl(jiraUrl)) {
      reject(new Error('Invalid Jira URL.')); return;
    }
    const boundary = '----QAPlatformBoundary' + Date.now().toString(16);
    const parts = [];
    for (const file of files) {
      const m = file.dataUrl.match(/^data:([^;]+);base64,(.+)$/);
      if (!m) continue;
      const safeFilename = sanitizeFilename(file.name);
      const fileData = Buffer.from(m[2], 'base64');
      parts.push(
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${safeFilename}"\r\nContent-Type: ${m[1]}\r\n\r\n`, 'utf8'),
        fileData,
        Buffer.from('\r\n', 'utf8')
      );
    }
    if (parts.length === 0) { resolve(false); return; }
    parts.push(Buffer.from(`--${boundary}--\r\n`, 'utf8'));
    const body = Buffer.concat(parts);
    const url = new URL(jiraUrl + '/rest/api/3/issue/' + issueKey + '/attachments');
    const opts = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   'POST',
      timeout:  REQ_TIMEOUT,
      headers: {
        'Authorization':      'Basic ' + auth,
        'X-Atlassian-Token':  'no-check',
        'Content-Type':       `multipart/form-data; boundary=${boundary}`,
        'Content-Length':     body.length
      }
    };
    const req = https.request(opts, res => {
      let data = ''; res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 400) reject(new Error('Jira attach ' + res.statusCode + ': ' + data.slice(0, 200)));
        else resolve(true);
      });
    });
    req.on('timeout', () => { req.destroy(new Error('Jira attachment upload timed out')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/* ── Playwright Test Runner ─────────────────────────────────────────────── */
// Resolve the exact Playwright binary installed in THIS project. Going through `npx`
// risks resolving a different cached copy of the `playwright` package than the
// `@playwright/test` the spec files require — two singleton test registries then collide
// with "Playwright Test did not expect test.describe() to be called here".
function playwrightCmd(args) {
  const localBin = path.join(__dirname, 'node_modules', '.bin', process.platform === 'win32' ? 'playwright.cmd' : 'playwright');
  // These are all spawned with {shell:true} — Node does not auto-quote the command string in
  // that mode, so a path containing spaces (e.g. ".../QA AI Platform/node_modules/...") gets
  // split apart by the shell unless quoted here.
  if (fs.existsSync(localBin)) return { cmd: localBin.includes(' ') ? `"${localBin}"` : localBin, args };
  return { cmd: 'npx', args: ['playwright', ...args] };
}

function runPlaywrightTests(files, onLine) {
  const emit = onLine || (() => {});
  return new Promise((resolve) => {
    const runId  = crypto.randomBytes(16).toString('hex');
    const tmpDir = path.join(os.tmpdir(), 'qa_pw_' + runId);
    const resultJsonPath = path.join(tmpDir, 'pw-result.json');
    const cleanup = () => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} };

    try {
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name:'qa-run', version:'1.0.0', private:true }));
      // The uploaded test.config.js is never actually read by Playwright (it only auto-loads a file
      // literally named playwright.config.js/.ts/.mjs), so any baseURL the frontend generated there
      // was silently ignored — every relative page.goto('/path') then failed with "Cannot navigate
      // to invalid URL". Pull the baseURL back out of it and put it in the config Playwright actually uses.
      const uploadedConfig = files?.['test.config.js'] || '';
      const baseUrlMatch = uploadedConfig.match(/baseURL\s*:\s*["']([^"']+)["']/);
      const baseURL = baseUrlMatch ? baseUrlMatch[1] : null;
      // 'list' reporter streams live per-test progress to stdout; 'json' reporter writes the
      // structured result to a file so stdout stays clean for live streaming to the client.
      const pwConfig = `module.exports = { testDir: '.', timeout: 60000, use: { headless: true${baseURL ? `, baseURL: ${JSON.stringify(baseURL)}` : ''} }, reporter: [['list'], ['json', { outputFile: ${JSON.stringify(resultJsonPath)} }]] };`;
      fs.writeFileSync(path.join(tmpDir, 'playwright.config.js'), pwConfig);
      const safeBase = path.resolve(tmpDir) + path.sep;
      for (const [filePath, content] of Object.entries(files || {})) {
        if (filePath.endsWith('.md')) continue;
        const full = path.resolve(tmpDir, filePath);
        if (!full.startsWith(safeBase)) { console.warn('[Playwright] Blocked path traversal:', filePath); continue; }
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, String(content));
      }
    } catch (e) { cleanup(); resolve({ lines:['Error writing test files: '+e.message], passed:[], failed:[], error:e.message }); return; }

    const lines = [];
    // Parsed live from the 'list' reporter's own output as each test finishes — this is the
    // ONLY reliable source of pass/fail when the run gets killed by our timeout, because the json
    // reporter only writes resultJsonPath on a clean process exit. Without this, a timeout on a
    // long suite reports "0 passed" even though most tests genuinely passed before the cutoff.
    const liveResults = [];
    const TEST_LINE_RE = /^\s*(ok|x|-)\s+\d+\s+\S+\s+›\s+(.+?)(?:\s+\([\d.]+m?s\))?\s*$/;
    const pushLine = (l) => {
      lines.push(l); emit(l);
      const m = l.match(TEST_LINE_RE);
      if (m) liveResults.push({ status: m[1], title: m[2].trim() });
    };
    // CI=1 prevents Playwright from waiting for interactive input.
    // stdio: ignore stdin so npx/playwright never block waiting for keyboard input on Windows.
    const spawnEnv = { ...process.env, CI: '1', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1', NPM_CONFIG_YES: 'true' };
    // Help Node resolve @playwright/test from wherever it is installed (global npm, etc.)
    try {
      const pwResolved = require.resolve('@playwright/test');
      const nmDir = pwResolved.slice(0, pwResolved.indexOf(path.sep + '@playwright' + path.sep + 'test'));
      if (nmDir) spawnEnv.NODE_PATH = nmDir + (process.env.NODE_PATH ? path.delimiter + process.env.NODE_PATH : '');
    } catch {}
    // Also try global npm node_modules on Windows
    if (!spawnEnv.NODE_PATH && process.platform === 'win32' && process.env.APPDATA) {
      const globalNm = path.join(process.env.APPDATA, 'npm', 'node_modules');
      if (fs.existsSync(globalNm)) spawnEnv.NODE_PATH = globalNm + (process.env.NODE_PATH ? path.delimiter + process.env.NODE_PATH : '');
    }
    // Pre-check: verify playwright CLI is reachable (fast fail — no download)
    const { spawnSync } = require('child_process');
    const versionCmd = playwrightCmd(['--version']);
    const preCheck = spawnSync(versionCmd.cmd, versionCmd.args, {
      cwd: tmpDir, shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: spawnEnv, timeout: 15000
    });
    if (preCheck.status !== 0 || preCheck.error) {
      cleanup();
      resolve({ lines: [], passed: [], failed: [], error: 'not_installed' });
      return;
    }

    emit('▶ Launching Playwright…');
    const testCmd = playwrightCmd(['test']);
    const proc = spawn(testCmd.cmd, testCmd.args, {
      cwd: tmpDir, shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: spawnEnv
    });
    let stdoutBuf = '', stderrBuf = '';
    const flush = (bufRef, chunk) => {
      bufRef.buf += chunk;
      const parts = bufRef.buf.split('\n');
      bufRef.buf = parts.pop(); // keep the trailing partial line for the next chunk
      for (const l of parts) if (l.trim()) pushLine(l.replace(/\x1b\[[0-9;]*m/g, '')); // strip ANSI color codes
    };
    const stdoutRef = { buf: '' }, stderrRef = { buf: '' };
    proc.stdout.on('data', d => flush(stdoutRef, d.toString()));
    proc.stderr.on('data', d => flush(stderrRef, d.toString()));

    const killProc = () => {
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { shell: true, stdio: 'ignore' });
        } else {
          proc.kill('SIGTERM');
        }
      } catch {}
    };

    // 20 min — large suites (dozens of real-browser tests) can legitimately take well over 5 min;
    // the old limit was killing runs mid-way before Playwright even printed its failure details.
    const timer = setTimeout(() => {
      killProc(); cleanup();
      pushLine('✗ Test run timed out after 20 minutes');
      // The json reporter never got to write its file — fall back to what we parsed live so tests
      // that genuinely passed before the timeout aren't misreported as failed.
      const passed = liveResults.filter(r => r.status === 'ok').map(r => r.title);
      const failed = liveResults.filter(r => r.status === 'x').map(r => ({ title: r.title, error: 'Run timed out before full details were captured — see execution log' }));
      resolve({ lines, passed, failed, error: 'timeout' });
    }, 1200000);

    proc.on('close', (code) => {
      clearTimeout(timer);
      if (stdoutRef.buf.trim()) pushLine(stdoutRef.buf.replace(/\x1b\[[0-9;]*m/g, ''));
      if (stderrRef.buf.trim()) pushLine(stderrRef.buf.replace(/\x1b\[[0-9;]*m/g, ''));
      let passed = [], failed = [];
      const globalErrors = [];
      try {
        const results = JSON.parse(fs.readFileSync(resultJsonPath, 'utf8'));
        const walk = (suites) => {
          for (const suite of suites || []) {
            for (const spec of suite.specs || []) {
              const title = [suite.title, spec.title].filter(Boolean).join(' › ');
              if (spec.ok) passed.push(title);
              else failed.push({ title, error: (spec.tests?.[0]?.results?.[0]?.errors?.[0]?.message||'Failed').slice(0,300) });
            }
            walk(suite.suites);
          }
        };
        walk(results.suites);
        // Collect global errors — e.g. test file failed to load (import errors go here, not suites)
        for (const err of results.errors || []) {
          globalErrors.push((err.message || String(err)).slice(0, 400));
        }
      } catch {}
      // json reporter file was missing/unparseable despite a clean process exit — fall back to
      // what was parsed live rather than silently reporting everything as failed.
      if (passed.length === 0 && failed.length === 0 && liveResults.length > 0) {
        passed = liveResults.filter(r => r.status === 'ok').map(r => r.title);
        failed = liveResults.filter(r => r.status === 'x').map(r => ({ title: r.title, error: 'See execution log for details' }));
      }
      cleanup();

      // Surface global errors so the user knows WHY 0 tests ran
      if (globalErrors.length > 0) {
        globalErrors.forEach(e => pushLine('✗ ' + e));
        pushLine('Playwright reported global errors:');
        // Detect @playwright/test module not found — treat as not_installed
        const errText = globalErrors.join('\n').toLowerCase();
        if (errText.includes("cannot find module") && errText.includes('playwright')) {
          resolve({ lines, passed: [], failed: [], error: 'not_installed' });
          return;
        }
      }

      pushLine(''); pushLine('Results: '+passed.length+' passed, '+failed.length+' failed');
      resolve({ lines, passed, failed, error: null });
    });

    proc.on('error', e => {
      clearTimeout(timer); cleanup();
      resolve({ lines:[], passed:[], failed:[], error: e.code==='ENOENT'?'not_installed':e.message });
    });
  });
}

/* ── Performance Test (k6) ─────────────────────────────────────────────── */
function generateK6Script({ testType, method, apiUrl, vus, duration, ramp, p95Threshold, authType, token, basicUsername, basicPassword, requestBody, expectedStatus, csvUsers, variables, customHeaders }) {
  const m    = ['get','post','put','patch','delete'].includes((method||'').toLowerCase()) ? (method||'GET').toLowerCase() : 'get';
  const vusN = parseInt(vus) || 100;
  const p95N = parseInt(p95Threshold) || 2000;
  const exp  = parseInt(expectedStatus) || 200;

  // Configurable variables — e.g. {{auctionItemId}} in the URL, or an API key
  // in a custom header — so the same test can target a different
  // record/environment/key per project without editing the script. Each
  // becomes a k6 __ENV var with the given default.
  const VAR_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
  // Names that would collide with identifiers the generated script already
  // declares (import bindings, k6 globals, JS reserved words) — allowing
  // these would produce a duplicate-declaration SyntaxError at k6-run time.
  const RESERVED_VAR_NAMES = new Set([
    'http', 'check', 'sleep', 'options', '__creds', '__ENV', '__VU', '__ITER',
    'import', 'export', 'default', 'const', 'let', 'var', 'function', 'return',
    'class', 'new', 'delete', 'typeof', 'void', 'this', 'true', 'false', 'null', 'undefined',
  ]);
  const safeVars = Array.isArray(variables)
    ? variables.filter(v => v && VAR_NAME_RE.test(v.name) && !RESERVED_VAR_NAMES.has(v.name)).slice(0, 20)
    : [];
  const varDefaults = Object.fromEntries(safeVars.map(v => [v.name, String(v.value ?? '')]));
  const placeholderRe = /\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g;
  const resolvedUrl = String(apiUrl || '').replace(placeholderRe, (_, n) => varDefaults[n] ?? '');

  // Validate and sanitize URL and durations
  const urlTemplate = isValidHttpUrl(resolvedUrl) ? String(apiUrl) : 'http://localhost';
  const safeDur  = sanitizeK6Duration(duration);
  const safeRamp = sanitizeK6Duration(ramp);

  const varDecls = safeVars
    .map(v => `const ${v.name} = __ENV.${v.name} || ${JSON.stringify(String(v.value ?? ''))};`)
    .join('\n');
  // Turns a string that may contain {{variableName}} into a JS source
  // expression: a template literal (so it stays live/__ENV-overridable) when
  // variables are configured, otherwise a plain JSON-escaped string literal.
  // Backslashes, backticks, and ${ in the source content are escaped BEFORE
  // substituting placeholders, so arbitrary user input (a pasted API key, a
  // URL) can never break out of the template literal or inject a live
  // expression — only the ${name} we insert ourselves stays unescaped.
  const toScriptExpr = (str) => {
    const s = String(str || '');
    if (!safeVars.length) return JSON.stringify(s);
    const escaped = s.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
    return '`' + escaped.replace(placeholderRe, (_, n) => n in varDefaults ? '${' + n + '}' : '') + '`';
  };
  const urlExpr = toScriptExpr(urlTemplate);

  // Headers: built-in Content-Type/Accept + auth, plus arbitrary custom
  // headers (e.g. an API key header your auth type doesn't cover). Emitted
  // as a JS object-literal expression — not JSON.stringify — so header
  // values can also reference {{variables}}.
  const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
  const headerEntries = [
    { name: 'Content-Type', expr: JSON.stringify('application/json') },
    { name: 'Accept', expr: JSON.stringify('application/json') },
  ];
  if (authType === 'bearer' && token)
    headerEntries.push({ name: 'Authorization', expr: JSON.stringify('Bearer ' + token) });
  if (authType === 'basic' && basicUsername)
    headerEntries.push({ name: 'Authorization', expr: JSON.stringify('Basic ' + Buffer.from(basicUsername + ':' + (basicPassword || '')).toString('base64')) });
  const safeHeaders = Array.isArray(customHeaders)
    ? customHeaders.filter(h => h && HEADER_NAME_RE.test(h.name)).slice(0, 20)
    : [];
  safeHeaders.forEach(h => headerEntries.push({ name: h.name, expr: toScriptExpr(h.value) }));
  const headersExpr = '{' + headerEntries.map(h => JSON.stringify(h.name) + ':' + h.expr).join(',') + '}';

  const bodyArg = ['post', 'put', 'patch'].includes(m) && requestBody
    ? `, ${toScriptExpr(requestBody)}`
    : '';

  let stages;
  if (testType === 'stress') {
    const s25 = Math.ceil(vusN * 0.25), s50 = Math.ceil(vusN * 0.5), s75 = Math.ceil(vusN * 0.75);
    stages = `[{duration:'${safeRamp}',target:${s25}},{duration:'${safeDur}',target:${s25}},{duration:'${safeRamp}',target:${s50}},{duration:'${safeDur}',target:${s50}},{duration:'${safeRamp}',target:${s75}},{duration:'${safeDur}',target:${s75}},{duration:'${safeRamp}',target:${vusN}},{duration:'${safeDur}',target:${vusN}},{duration:'${safeRamp}',target:0}]`;
  } else {
    stages = `[{duration:'${safeRamp}',target:${vusN}},{duration:'${safeDur}',target:${vusN}},{duration:'${safeRamp}',target:0}]`;
  }

  if (authType === 'csv' && Array.isArray(csvUsers) && csvUsers.length > 0) {
    const encodedCreds = csvUsers.map(u =>
      Buffer.from((u.username || '') + ':' + (u.password || '')).toString('base64')
    );
    return `import http from 'k6/http';
import { check, sleep } from 'k6';
const __creds = ${JSON.stringify(encodedCreds)};
${varDecls}
export let options = {
  stages: ${stages},
  thresholds: { 'http_req_duration': ['p(95)<${p95N}'], 'http_req_failed': ['rate<0.05'] }
};
export default function () {
  const headers = ${headersExpr};
  headers['Authorization'] = 'Basic ' + __creds[(__VU - 1) % __creds.length];
  const res = http.${m}(${urlExpr}${bodyArg}, { headers });
  check(res, { 'status ${exp}': r => r.status === ${exp} });
  sleep(1);
}`;
  }

  return `import http from 'k6/http';
import { check, sleep } from 'k6';
${varDecls}
export let options = {
  stages: ${stages},
  thresholds: { 'http_req_duration': ['p(95)<${p95N}'], 'http_req_failed': ['rate<0.05'] }
};
export default function () {
  const res = http.${m}(${urlExpr}${bodyArg}, { headers: ${headersExpr} });
  check(res, { 'status ${exp}': r => r.status === ${exp} });
  sleep(1);
}`;
}

function runK6(scriptPath) {
  return new Promise((resolve, reject) => {
    const summaryPath = scriptPath + '.summary.json';
    const proc = spawn('k6', ['run', '--summary-export', summaryPath, '--new-machine-readable-summary', '--no-color', scriptPath], { shell: true });
    let stderr = '';
    proc.stderr.on('data', d => stderr += d.toString());
    proc.on('close', code => {
      try {
        if (!fs.existsSync(summaryPath))
          throw new Error(stderr.slice(0, 300) || 'k6 produced no output (exit ' + code + ')');
        const sum = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
        console.log('[Perf] k6 summary keys:', JSON.stringify(sum.results?.metrics?.map(m=>m.name) || Object.keys(sum.metrics||{})));
        const httpErrors = (sum.results?.metrics||[]).filter(m=>m.name?.startsWith('http_req'));
        httpErrors.forEach(m => console.log('[Perf] metric', m.name, JSON.stringify(m.values)));
        try { fs.unlinkSync(summaryPath); } catch {}
        // k6 v1.7+ uses sum.results.metrics array; older versions use sum.metrics object
        const findMetric = name => {
          if (Array.isArray(sum.results?.metrics))
            return sum.results.metrics.find(m => m.name === name)?.values || {};
          return sum.metrics?.[name]?.values || {};
        };
        const dur  = findMetric('http_req_duration');
        const req  = findMetric('http_reqs');
        const fail = findMetric('http_req_failed');
        resolve({
          passed: code === 0,
          metrics: {
            totalRequests: Math.round(req.count  || 0),
            rps:           parseFloat((req.rate   || req.count / Math.max(1, parseFloat(sum.config?.duration) || 1) || 0).toFixed(2)),
            avgDuration:   parseFloat((dur.avg   || 0).toFixed(2)),
            minDuration:   parseFloat((dur.min   || 0).toFixed(2)),
            maxDuration:   parseFloat((dur.max   || 0).toFixed(2)),
            p50:           parseFloat((dur.med   || dur['p50'] || dur['p(50)'] || 0).toFixed(2)),
            p90:           parseFloat((dur['p90'] || dur['p(90)'] || 0).toFixed(2)),
            p95:           parseFloat((dur['p95'] || dur['p(95)'] || 0).toFixed(2)),
            p99:           parseFloat((dur['p99'] || dur['p(99)'] || 0).toFixed(2)),
            errorRate:     parseFloat(((fail.rate || 0) * 100).toFixed(2))
          }
        });
      } catch (e) { reject(new Error(e.message)); }
    });
    proc.on('error', e => reject(new Error(
      e.code === 'ENOENT'
        ? 'k6 is not installed. Install it from https://k6.io/docs/get-started/installation/'
        : 'Failed to start k6: ' + e.message
    )));
  });
}

/* ── HTTP Server ────────────────────────────────────────────────────────── */
const server = http.createServer((req, res) => {
  // Security headers on every response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'none'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self' https://unpkg.com https://cdnjs.cloudflare.com; " +
    "img-src 'self' data: blob:; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';"
  );

  // CORS: only allow same-origin requests (app and API share the same host:port)
  const origin = req.headers['origin'];
  const host   = req.headers['host'];
  if (origin && host && origin.includes(host)) {
    res.setHeader('Access-Control-Allow-Origin',  origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token, X-Admin-Token, X-Member-Token');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  /* ── Codegen status (GET — requires session) ── */
  if (req.method === 'GET' && req.url.startsWith('/api/codegen/status/')) {
    if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
    const sessionId = req.url.split('/api/codegen/status/')[1];
    const s = codegenSessions.get(sessionId);
    if (!s) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ status: 'not_found' })); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: s.status, script: s.script || null })); return;
  }

  /* ── Members list (GET — requires admin token) ── */
  if (req.method === 'GET' && req.url === '/api/members') {
    const adminToken = req.headers['x-admin-token'];
    if (!adminToken || !adminSessions.has(adminToken)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' })); return;
    }
    const safe = (serverDB.members || []).map(({ passwordHash, ...m }) => m);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(safe)); return;
  }

  /* ── Admin data (GET — requires admin token) ── */
  if (req.method === 'GET' && req.url === '/api/admin/data') {
    const adminToken = req.headers['x-admin-token'];
    if (!adminToken || !adminSessions.has(adminToken)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    const safeDB = {
      ...serverDB,
      adminPasswordHash: undefined,
      members: (serverDB.members || []).map(({ passwordHash, ...m }) => m)
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(safeDB));
    return;
  }

  /* ── Serve app ── */
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
      res.writeHead(200, {
        'Content-Type':  'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma':        'no-cache'
      });
      res.end(html);
    } catch (e) {
      res.writeHead(500); res.end('Could not read app file: ' + e.message);
    }
    return;
  }

  /* ── Read body (with size limit) ── */
  let body = '';
  let bodySize = 0;
  req.on('data', chunk => {
    bodySize += chunk.length;
    if (bodySize > MAX_BODY) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Request body too large' }));
      req.destroy();
      return;
    }
    body += chunk;
  });
  req.on('end', async () => {
    /* ── /api/codegen/start (requires session) ── */
    if (req.method === 'POST' && req.url === '/api/codegen/start') {
      if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const parsed = JSON.parse(body);
        const { url } = parsed;
        if (!url || !isValidHttpUrl(url)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'A valid http/https URL is required' })); return;
        }
        const sessionId  = crypto.randomBytes(16).toString('hex');
        const outputFile = path.join(os.tmpdir(), `qa_codegen_${sessionId}.js`);
        const codegenCmd = playwrightCmd(['codegen', url, '--output', outputFile]);
        const proc = spawn(codegenCmd.cmd, codegenCmd.args, { shell: true });
        const session = { proc, outputFile, status: 'running', script: null, startedAt: Date.now() };
        codegenSessions.set(sessionId, session);
        proc.on('close', () => {
          try {
            if (fs.existsSync(outputFile)) {
              const src = fs.readFileSync(outputFile, 'utf8').trim();
              try { fs.unlinkSync(outputFile); } catch {}
              session.script = src || null;
              session.status = src ? 'done' : 'empty';
            } else {
              session.status = 'empty';
            }
          } catch { session.status = 'error'; }
          console.log('[Codegen] Session', sessionId, '→', session.status);
        });
        proc.on('error', e => {
          session.status = e.code === 'ENOENT' ? 'not_installed' : 'error';
          console.error('[Codegen] Error:', e.message);
        });
        console.log('[Codegen] Started session', sessionId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/codegen/:id (DELETE — cancel, requires session) ── */
    if (req.method === 'DELETE' && req.url.startsWith('/api/codegen/')) {
      if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      const sessionId = req.url.split('/api/codegen/')[1];
      const s = codegenSessions.get(sessionId);
      if (s) { try { s.proc.kill(); } catch {} codegenSessions.delete(sessionId); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true })); return;
    }

    /* ── /api/playwright/run (requires session) ──
       Streams newline-delimited JSON: {type:'line', line} as tests execute, then a
       single {type:'done', ...result} once the run finishes. */
    if (req.method === 'POST' && req.url === '/api/playwright/run') {
      if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no' });
      try {
        const parsed = JSON.parse(body);
        const result = await runPlaywrightTests(parsed.files || {}, (line) => {
          res.write(JSON.stringify({ type: 'line', line }) + '\n');
        });
        res.write(JSON.stringify({ type: 'done', ...result }) + '\n');
      } catch (e) {
        res.write(JSON.stringify({ type: 'done', error: e.message, lines: [], passed: [], failed: [] }) + '\n');
      }
      res.end();
      return;
    }

    /* ── /api/project/check-attachment (requires member session OR admin token) ──
       Checks whether the frontend/backend repo URLs configured on a project are
       reachable, and if so clones/refreshes a shallow cache and returns a
       size-capped source bundle to ground automated script generation. Used both by
       the QA workspace flow and the admin Projects page's "Test Connection" button. */
    if (req.method === 'POST' && req.url === '/api/project/check-attachment') {
      const adminToken = req.headers['x-admin-token'];
      const isAdmin = adminToken && adminSessions.has(adminToken);
      if (!isAdmin && !getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const { frontendRepoUrl, backendRepoUrl } = JSON.parse(body);
        const checkOne = (url) => {
          if (!url || !String(url).trim()) return null;
          const trimmed = String(url).trim();
          const name = trimmed.replace(/\.git$/, '').split('/').filter(Boolean).pop() || trimmed;
          if (!isValidGitUrl(trimmed)) return { url: trimmed, name, attached: true, reachable: false, error: 'Invalid or disallowed repository URL — must be a public https:// Git URL' };
          const reach = checkGitReachable(trimmed);
          if (!reach.ok) return { url: trimmed, name, attached: true, reachable: false, error: reach.error };
          const sync = syncRepoCache(trimmed);
          if (!sync.ok) return { url: trimmed, name, attached: true, reachable: false, error: sync.error };
          const { context, truncated } = collectRepoContext(sync.dir);
          return { url: trimmed, name, attached: true, reachable: true, context, truncated };
        };
        const frontend = checkOne(frontendRepoUrl);
        const backend  = checkOne(backendRepoUrl);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ frontend, backend }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/members/login ── */
    if (req.method === 'POST' && req.url === '/api/members/login') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (!checkRateLimit(ip)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too many login attempts. Please wait 15 minutes.' })); return;
      }
      try {
        const { email, password } = JSON.parse(body);
        if (!serverDB.members) serverDB.members = [];
        const member = serverDB.members.find(m => m.email === email);
        if (!member || !verifyPassword(password || '', member.passwordHash)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid credentials' })); return;
        }
        // Upgrade legacy SHA-256 hash to scrypt on first login
        if (!member.passwordHash.startsWith('scrypt:')) {
          member.passwordHash = hashPasswordSecure(password);
          saveServerDB(serverDB);
        }
        const token = crypto.randomBytes(32).toString('hex');
        memberSessions.set(token, { memberId: member.id, createdAt: Date.now() });
        saveMemberSessions();
        console.log('[Member] Login:', member.name);
        // Always create an API session — Jira creds used if saved, otherwise session still works for AI via CLI
        const creds = decryptMemberCredentials(member);
        const sessionToken = createSession(member.id, creds?.jiraUrl||'', creds?.jiraEmail||'', creds?.jiraToken||'');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, member: { id: member.id, name: member.name, email: member.email, role: member.role }, sessionToken }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/members (POST — admin creates member) ── */
    if (req.method === 'POST' && req.url === '/api/members') {
      try {
        const adminToken = req.headers['x-admin-token'];
        if (!adminToken || !adminSessions.has(adminToken)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' })); return;
        }
        const { name, email, password, role } = JSON.parse(body);
        if (!name || !email || !password) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'name, email and password are required' })); return;
        }
        if (password.length < 8) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Password must be at least 8 characters' })); return;
        }
        if (!serverDB.members) serverDB.members = [];
        if (serverDB.members.find(m => m.email === email)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'A member with this email already exists' })); return;
        }
        const member = { id: crypto.randomBytes(16).toString('hex'), name, email, role: role || 'QA Engineer', passwordHash: hashPasswordSecure(password), createdAt: Date.now() };
        serverDB.members.push(member);
        saveServerDB(serverDB);
        console.log('[Member] Created:', name);
        const { passwordHash, ...safe } = member;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(safe));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/members/:id/credentials (POST — member stores own credentials) ── */
    if (req.method === 'POST' && /^\/api\/members\/[^/]+\/credentials$/.test(req.url)) {
      try {
        const memberToken = req.headers['x-member-token'];
        const ms = memberToken ? memberSessions.get(memberToken) : null;
        if (!ms || Date.now() - ms.createdAt > ADMIN_SESSION_TTL) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' })); return;
        }
        const memberId = req.url.split('/')[3];
        if (ms.memberId !== memberId) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Forbidden' })); return;
        }
        const { jiraUrl, jiraEmail, jiraToken } = JSON.parse(body);
        const member = (serverDB.members || []).find(m => m.id === memberId);
        if (!member) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Member not found' })); return; }
        member.credentials = encryptMemberCredentials(jiraUrl || '', jiraEmail || '', jiraToken || '');
        saveServerDB(serverDB);
        const sessionToken = createSession(memberId, jiraUrl, jiraEmail, jiraToken);
        console.log('[Member] Credentials saved:', member.name);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, sessionToken }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/members/session/refresh (POST — renew API session from stored creds) ── */
    if (req.method === 'POST' && req.url === '/api/members/session/refresh') {
      try {
        const memberToken = req.headers['x-member-token'];
        const ms = memberToken ? memberSessions.get(memberToken) : null;
        if (!ms || Date.now() - ms.createdAt > ADMIN_SESSION_TTL) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized — please log in again' })); return;
        }
        const member = (serverDB.members || []).find(m => m.id === ms.memberId);
        const creds = member ? decryptMemberCredentials(member) : null;
        if (!creds) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No credentials configured' })); return;
        }
        const sessionToken = createSession(ms.memberId, creds.jiraUrl, creds.jiraEmail, creds.jiraToken);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionToken }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/members/:id (PUT — admin edits member) ── */
    if (req.method === 'PUT' && req.url.startsWith('/api/members/')) {
      try {
        const adminToken = req.headers['x-admin-token'];
        if (!adminToken || !adminSessions.has(adminToken)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' })); return;
        }
        const memberId = req.url.split('/api/members/')[1];
        const { name, email, role, password } = JSON.parse(body);
        if (!serverDB.members) serverDB.members = [];
        const idx = serverDB.members.findIndex(m => m.id === memberId);
        if (idx === -1) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Member not found' })); return; }
        serverDB.members[idx] = { ...serverDB.members[idx], name, email, role };
        if (password && password.length >= 8) {
          serverDB.members[idx].passwordHash = hashPasswordSecure(password);
        }
        saveServerDB(serverDB);
        const { passwordHash: _, ...safe } = serverDB.members[idx];
        console.log('[Member] Updated:', memberId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(safe));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/members/:id (DELETE — admin removes member) ── */
    if (req.method === 'DELETE' && req.url.startsWith('/api/members/')) {
      try {
        const adminToken = req.headers['x-admin-token'];
        if (!adminToken || !adminSessions.has(adminToken)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' })); return;
        }
        const memberId = req.url.split('/api/members/')[1];
        if (!serverDB.members) serverDB.members = [];
        serverDB.members = serverDB.members.filter(m => m.id !== memberId);
        saveServerDB(serverDB);
        console.log('[Member] Deleted:', memberId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/admin/login ── */
    if (req.method === 'POST' && req.url === '/api/admin/login') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (!checkRateLimit(ip)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too many login attempts. Please wait 15 minutes.' })); return;
      }
      try {
        const { password } = JSON.parse(body);
        if (!verifyPassword(password || '', serverDB.adminPasswordHash)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid credentials' }));
          return;
        }
        // Upgrade legacy SHA-256 hash to scrypt on first login
        if (!serverDB.adminPasswordHash.startsWith('scrypt:')) {
          serverDB.adminPasswordHash = hashPasswordSecure(password);
          saveServerDB(serverDB);
        }
        const token = crypto.randomBytes(32).toString('hex');
        adminSessions.set(token, { createdAt: Date.now() });
        console.log('[Admin] Login successful');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, isDefaultPassword: !!serverDB.adminPasswordIsDefault }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/admin/change-password ── */
    if (req.method === 'POST' && req.url === '/api/admin/change-password') {
      try {
        const adminToken = req.headers['x-admin-token'];
        if (!adminToken || !adminSessions.has(adminToken)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized' })); return;
        }
        const { currentPassword, newPassword } = JSON.parse(body);
        if (!verifyPassword(currentPassword || '', serverDB.adminPasswordHash)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Current password is incorrect' })); return;
        }
        if (!newPassword || newPassword.length < 8) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'New password must be at least 8 characters' })); return;
        }
        serverDB.adminPasswordHash = hashPasswordSecure(newPassword);
        serverDB.adminPasswordIsDefault = false;
        saveServerDB(serverDB);
        console.log('[Admin] Password changed');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/auth/session ── */
    if (req.method === 'POST' && req.url === '/api/auth/session') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (!checkRateLimit(ip)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too many attempts. Please wait 15 minutes.' })); return;
      }
      try {
        const { memberId, jiraUrl, jiraEmail, jiraToken } = JSON.parse(body);
        // Accept either a valid member token OR an existing session token (survives server restarts)
        const memberToken  = req.headers['x-member-token'];
        const sessionCheck = req.headers['x-session-token'];
        const ms  = memberToken  ? memberSessions.get(memberToken)  : null;
        const ses = sessionCheck ? getSession({ headers: { 'x-session-token': sessionCheck } }) : null;
        const validMember = ms && Date.now() - ms.createdAt <= ADMIN_SESSION_TTL && ms.memberId === memberId;
        const validSession = ses && ses.memberId === memberId;
        if (!validMember && !validSession) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized — please log in first' })); return;
        }
        // Validate Jira URL if provided
        if (jiraUrl && !isValidJiraUrl(jiraUrl)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid Jira URL. Must be a public HTTPS address.' }));
          return;
        }
        const sessionToken = createSession(memberId, jiraUrl, jiraEmail, jiraToken);
        console.log('[Auth] Session created');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionToken }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/ai ── */
    if (req.method === 'POST' && req.url === '/api/ai') {
      const session = getSession(req);
      if (!session) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const { messages, system, max } = JSON.parse(body);
        console.log('[AI]   Request received');
        const text = await callClaude(messages, system, max||4000);
        console.log('[AI]   Done');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ text }));
      } catch (e) {
        console.error('[AI]   Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/jira ── */
    if (req.method === 'POST' && req.url === '/api/jira') {
      const session = getSession(req);
      if (!session) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const parsed   = JSON.parse(body);
        const jiraUrl  = session.jiraUrl;
        const auth     = session.jiraAuth;
        const { path: jiraPath, method: jiraMethod, body: jiraBody } = parsed;
        console.log('[Jira] Request —', jiraMethod, jiraPath);
        const data = await proxyJira(jiraUrl, jiraPath, jiraMethod, auth, jiraBody);
        console.log('[Jira] Done');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      } catch (e) {
        console.error('[Jira] Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/jira/attach ── */
    if (req.method === 'POST' && req.url === '/api/jira/attach') {
      const session = getSession(req);
      if (!session) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const parsed  = JSON.parse(body);
        const jiraUrl = session.jiraUrl;
        const auth    = session.jiraAuth;
        const { issueKey, files } = parsed;
        if (!issueKey || !Array.isArray(files) || files.length === 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'issueKey and files are required' })); return;
        }
        console.log('[Jira] Attaching', files.length, 'file(s) to', issueKey);
        await attachToJira(jiraUrl, issueKey, auth, files);
        console.log('[Jira] Attachments uploaded to', issueKey);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        console.error('[Jira] Attach error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/perf (requires session) ── */
    if (req.method === 'POST' && req.url === '/api/perf') {
      if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const params    = JSON.parse(body);
        const tmpScript = path.join(os.tmpdir(), 'qa_k6_' + crypto.randomBytes(8).toString('hex') + '.js');
        fs.writeFileSync(tmpScript, generateK6Script(params));
        console.log('[Perf] Running k6 —', params.testName);
        const result = await runK6(tmpScript);
        try { fs.unlinkSync(tmpScript); } catch {}
        console.log('[Perf] Done — passed:', result.passed);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        console.error('[Perf] Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/sync (requires session) ── */
    if (req.method === 'POST' && req.url === '/api/sync') {
      if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const payload = JSON.parse(body);
        const { type } = payload;
        if (!['session','bug','perf','coverage'].includes(type)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid sync type' })); return;
        }
        const item = { id: crypto.randomBytes(8).toString('hex'), ...payload, syncedAt: Date.now() };
        if      (type === 'session')  serverDB.sessions.unshift(item);
        else if (type === 'bug')      serverDB.bugs.unshift(item);
        else if (type === 'perf')     serverDB.perfResults.unshift(item);
        else if (type === 'coverage') serverDB.coverage.unshift(item);
        ['sessions','bugs','perfResults','coverage'].forEach(k => {
          if (serverDB[k].length > 500) serverDB[k] = serverDB[k].slice(0, 500);
        });
        saveServerDB(serverDB);
        console.log('[Sync]', type, '-', payload.memberName, '/', payload.projectName);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
      return;
    }

    /* ── /api/ui-design/figma ── */
    if (req.method === 'POST' && req.url === '/api/ui-design/figma') {
      const _mToken = req.headers['x-member-token'];
      if (!_mToken || !memberSessions.has(_mToken)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required — please sign in' })); return; }
      try {
        const { figmaUrl, figmaToken: rawToken, nodeId: reqNodeId } = JSON.parse(body);
        const figmaToken = (rawToken || '').trim();
        if (!figmaUrl || !figmaToken) throw new Error('figmaUrl and figmaToken are required');
        const parsed = parseFigmaUrl(figmaUrl);
        if (!parsed) throw new Error('Invalid Figma URL. Paste the link directly from Figma (File → Share → Copy link). Accepted formats: figma.com/design/..., figma.com/file/..., figma.com/proto/...');
        const { fileKey } = parsed;
        const nodeId = reqNodeId || parsed.nodeId;
        console.log('[UID] Fetching Figma file:', fileKey, '| token prefix:', figmaToken.substring(0, 8) + '...');
        const fileResp = await figmaRequest(`/v1/files/${fileKey}?depth=2`, figmaToken);
        console.log('[UID] Figma API response status:', fileResp.status, '| body err:', fileResp.body?.err || fileResp.body?.message || 'none');
        if (fileResp.status === 403) throw new Error('Figma 403: token rejected. Make sure: (1) token starts with "figd_", (2) when creating it in Figma you selected "File content → Read" scope, (3) you have view access to this specific file.');
        if (fileResp.status === 404) throw new Error('Figma file not found. Check the URL.');
        if (fileResp.status !== 200) throw new Error('Figma API error: ' + (fileResp.body?.err || fileResp.status));
        const doc = fileResp.body.document;
        const pages = (doc?.children || []).map(p => ({ name: p.name, nodeId: p.id }));
        const frames = [];
        for (const page of doc?.children || []) {
          for (const child of page.children || []) {
            if (['FRAME','COMPONENT','SECTION'].includes(child.type)) {
              frames.push({ name: child.name, nodeId: child.id, pageName: page.name });
            }
          }
        }
        const targetNodeId = nodeId || frames[0]?.nodeId || pages[0]?.nodeId;
        let imageBase64 = null;
        if (targetNodeId) {
          const imgResp = await figmaRequest(`/v1/images/${fileKey}?ids=${encodeURIComponent(targetNodeId)}&format=png&scale=1.5`, figmaToken);
          if (imgResp.status === 200 && imgResp.body?.images) {
            const imgUrl = Object.values(imgResp.body.images)[0];
            if (imgUrl && imgUrl !== 'null') {
              const imgBuf = await downloadImageUrl(imgUrl);
              imageBase64 = imgBuf.toString('base64');
            }
          }
        }
        console.log('[UID] Figma ok — frames:', frames.length, '| image:', !!imageBase64);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ fileKey, pages, frames, selectedNodeId: targetNodeId, imageBase64 }));
      } catch (e) {
        console.error('[UID] Figma error:', e.message);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/ui-design/screenshot ── */
    if (req.method === 'POST' && req.url === '/api/ui-design/screenshot') {
      const _mToken = req.headers['x-member-token'];
      if (!_mToken || !memberSessions.has(_mToken)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required — please sign in' })); return; }
      try {
        const { url } = JSON.parse(body);
        if (!isValidHttpUrl(url)) throw new Error('Invalid URL');
        const outPath = path.join(os.tmpdir(), 'qa_uid_ss_' + crypto.randomBytes(8).toString('hex') + '.png');
        console.log('[UID] Taking screenshot of:', url);
        await new Promise((resolve, reject) => {
          const spawnEnv = { ...process.env, CI: '1', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1' };
          const proc = spawn('npx', ['playwright', 'screenshot', '--browser', 'chromium', '--full-page', url, outPath], { shell: process.platform === 'win32', env: spawnEnv });
          let stderr = '';
          proc.stderr.on('data', d => stderr += d.toString());
          const timer = setTimeout(() => { try { proc.kill(); } catch {} reject(new Error('Screenshot timed out')); }, 90000);
          proc.on('close', code => { clearTimeout(timer); if (code !== 0 || !fs.existsSync(outPath)) reject(new Error('Screenshot failed: ' + stderr.slice(0, 400))); else resolve(); });
          proc.on('error', err => { clearTimeout(timer); reject(new Error('Could not run playwright: ' + err.message)); });
        });
        const imgBuf = fs.readFileSync(outPath);
        try { fs.unlinkSync(outPath); } catch {}
        console.log('[UID] Screenshot ok — size:', imgBuf.length, 'bytes');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ imageBase64: imgBuf.toString('base64') }));
      } catch (e) {
        console.error('[UID] Screenshot error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/ui-design/analyze ── */
    if (req.method === 'POST' && req.url === '/api/ui-design/analyze') {
      const _mToken = req.headers['x-member-token'];
      if (!_mToken || !memberSessions.has(_mToken)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required — please sign in' })); return; }
      const tmpPaths = [];
      try {
        const { figmaImageBase64, screenshotBase64, pageUrl, figmaUrl, mode, jiraTicketKey, storyRequirements, storyFileImages, svgAssetNames } = JSON.parse(body);
        const linkedIssue = jiraTicketKey || 'UNMAPPED';
        const saveImg = (b64, prefix) => {
          const p = path.join(os.tmpdir(), prefix + crypto.randomBytes(6).toString('hex') + '.png');
          fs.writeFileSync(p, Buffer.from(b64, 'base64'));
          tmpPaths.push(p);
          return p;
        };
        if (mode === 'generate-cases') {
          if (!figmaImageBase64) throw new Error('figmaImageBase64 required');
          const figmaPath = saveImg(figmaImageBase64, 'qa_uid_fg_');
          // Save any uploaded story reference images as temp files
          const storyImgPaths = [];
          if (Array.isArray(storyFileImages)) {
            for (const sf of storyFileImages) {
              if (sf.base64) {
                const p = path.join(os.tmpdir(), 'qa_uid_ref_' + crypto.randomBytes(6).toString('hex') + '.png');
                fs.writeFileSync(p, Buffer.from(sf.base64, 'base64'));
                tmpPaths.push(p);
                storyImgPaths.push(p);
              }
            }
          }
          const allImagePaths = [figmaPath, ...storyImgPaths];
          console.log('[UID] Generating test cases — images:', allImagePaths.length, storyImgPaths.length > 0 ? `(+${storyImgPaths.length} reference)` : '');
          const prompt = `You are a world-class Senior QA Engineer & Business Analyst. Analyze the provided Figma UI design image${storyImgPaths.length > 0 ? ` and the ${storyImgPaths.length} additional reference image(s)` : ''} and generate a highly optimized, production-ready, maintainable Test Suite. Prioritize risk-based testing, data integrity, and system stability over high test case counts.

CONTEXT:
- Live Page URL: ${pageUrl || 'Not specified'}
- Figma Design Source: ${figmaUrl || 'Not specified'}
- Linked Jira Story: ${linkedIssue}${storyImgPaths.length > 0 ? `\n- Reference Images Provided: ${storyImgPaths.length} additional image(s) — treat as supplementary design/requirement visuals` : ''}${storyRequirements ? `
- Story Requirements / Acceptance Criteria:
${storyRequirements.split('\n').map(l => '  ' + l).join('\n')}` : ''}${Array.isArray(svgAssetNames)&&svgAssetNames.length>0?`\n- SVG Icon Assets (${svgAssetNames.length} files): ${svgAssetNames.join(', ')}\n  These are the actual SVG icon/asset files used in the design. Generate test cases that verify each icon referenced in the Figma design matches the correct SVG asset.`:''}

# Step 1: Deep Analysis (Pre-Generation)
Analyze the Figma design image${storyRequirements ? ' AND cross-reference the Story Requirements provided in CONTEXT' : ''} and extract:
- Acceptance Criteria: ${storyRequirements ? 'map every AC from the requirements above to at least 2 test cases each — missing an AC is a defect' : 'extract from the design and any visible text/labels'}
- Implicit Business Rules: unspoken logic, dependencies, state transitions visible in the design
- Data Flows & Constraints: field validations, boundaries, duplicates, permissions
- Regression Impact: effect on existing workflows and integrations
- Integration & SSO Dependencies: session expiry, token refresh, third-party redirects, behavior on timeout/failure
- Localization/RTL: this platform supports Arabic ONLY. Never generate English-language test cases. Validate Arabic rendering, full RTL layout integrity, mixed-direction content (LTR tokens such as URLs, protocol names, emails, and digits embedded inside Arabic sentences), correct punctuation placement in RTL context, truncation, and overflow.
- Figma Design Token Extraction (MANDATORY) — extract and document every element on every visible screen and state:
  * Typography: font family, size (px), weight, line height, text color (exact hex), alignment (right/left/center), decoration, transform
  * Colors: exact hex of every background, text, icon, border, divider, overlay, and state color — NEVER describe by name only
  * Spacing & Layout: padding of every container (top/right/bottom/left), margins and gaps, alignment, stacking order, grid/flex arrangement
  * Dimensions: width/height of components, bars, icons, badges, buttons; border radius; border width and color; shadows
  * Icons & Images: icon size, color, stroke vs fill, container shape, exact placement relative to text
  * Interactive Elements: every button, input, dropdown, checkbox, toggle, link — with ALL states (default, hover, pressed, focused, disabled, loading, error, success) and the visual spec of each state
  * Conditional & System States: show/hide elements, empty, loading, error, success states
  * RTL Composition: position of every element in RTL layout (right edge vs left edge), chevron/arrow directions, icon mirroring
  If any spec cannot be measured from the image, flag it explicitly — never guess values.

# Step 2: Test Coverage — "Lean QA"
Maximize coverage, minimize redundancy. Cover:
1. Happy Path / core workflows
2. Negative & edge cases
3. Security & permissions
4. Data integrity & API validation
5. Performance as testable assertions
6. Integration & session handling
7. Localization & RTL — Arabic-only; every mixed-direction and RTL case that carries real functional risk
8. Figma Design Comparison — every element and property extracted in Step 1 must have at least one test case. Design-comparison test cases MUST reference the concrete expected values extracted from the design (exact hex colors, font sizes/weights, dimensions in px, alignment, spacing). Example: "Verify that the banner bar is 32px high with background #F3F4F6 and the toggle label renders in green #1B8354" — NOT "Verify that the banner matches Figma".

# Step 3: Output Rules
- Every title MUST start with "Verify that..." — descriptive with clear expected outcome
- Priority: High = auth/security, data loss, payment/certificate errors, broken core flows; Medium = wrong error handling, non-blocking gaps, degraded integrations; Low = cosmetic issues bundled into broader cases
- Linked Issue: use "${linkedIssue}" for ALL test cases
- Status: leave empty string
- Arabic-only: Never generate English-language test cases. Unexpected English or mixed Arabic-English text in the UI is a defect.
- For design test cases: include exact expected values (hex, px, weight, alignment) from Step 1 extraction — never generic wording
- Ambiguous/untestable items: still output a row, stating "Verify that [behavior] — BLOCKED: [what is missing]"

# Step 4: Self-Review (Quality Gate)
Before finalizing, verify:
- Every extracted design property group (typography, colors, spacing, alignment, dimensions, icons, interactive states) is covered or flagged BLOCKED
- Every boundary value (min/max/empty/null/duplicate) has a row
- Every summary starts with "Verify that..."
- No duplicate validations
- No English-language test cases (Arabic-only platform)
- Design test cases lacking concrete expected values are rewritten with exact specs or flagged BLOCKED

Return ONLY valid JSON (no markdown wrapper, no extra text):
{
  "testCases": [
    {
      "id": "TC-001",
      "title": "Verify that...",
      "type": "ui",
      "priority": "High|Medium|Low",
      "area": "Layout|Typography|Colors|Buttons|Forms|Navigation|Spacing|RTL|Interactive|Accessibility|Security|Data",
      "preconditions": "User is on the target page: ${pageUrl || ''}",
      "steps": ["Step 1: ...", "Step 2: ..."],
      "expected": "Detailed expected result with exact values (hex, px, weight) where applicable",
      "automatable": true,
      "linkedIssue": "${linkedIssue}",
      "status": ""
    }
  ]
}`;
          const text = await callClaudeWithImages(prompt, allImagePaths);
          const jsonMatch = text.match(/\{[\s\S]*\}/);
          if (!jsonMatch) throw new Error('AI returned invalid format');
          const result = JSON.parse(jsonMatch[0]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } else {
          if (!figmaImageBase64 || !screenshotBase64) throw new Error('Both images required for comparison');
          const figmaPath = saveImg(figmaImageBase64, 'qa_uid_fg_');
          const ssPath    = saveImg(screenshotBase64,  'qa_uid_ss_');
          console.log('[UID] Comparing Figma design vs implementation…');
          const prompt = `You are a Senior QA Engineer performing a visual regression test.\n\nThe FIRST image is the Figma design (expected).\nThe SECOND image is a live screenshot of the implementation at: ${pageUrl || 'the page'}.\n\nCompare these two images thoroughly and identify ALL visual discrepancies.\n\nReturn ONLY valid JSON in this exact structure, no markdown, no extra text:\n{\n  "summary": "Brief overall assessment of visual fidelity",\n  "passRate": 75,\n  "bugs": [\n    {\n      "id": "VB-001",\n      "title": "Short descriptive bug title",\n      "severity": "Critical|High|Medium|Low",\n      "area": "Layout|Typography|Colors|Spacing|Missing Element|Extra Element|Buttons|Forms|Icons|Images",\n      "description": "Detailed description of the discrepancy",\n      "expected": "What the Figma design shows",\n      "actual": "What the live implementation shows",\n      "recommendation": "Specific fix recommendation"\n    }\n  ]\n}\n\nCheck: layout/alignment, typography (size/weight/family), colors (exact values), spacing (padding/margin), missing/extra elements, button styles, form inputs, icons, images, overall design consistency.`;
          const text = await callClaudeWithImages(prompt, [figmaPath, ssPath]);
          const jsonMatch = text.match(/\{[\s\S]*\}/);
          if (!jsonMatch) throw new Error('AI returned invalid format');
          const result = JSON.parse(jsonMatch[0]);
          console.log('[UID] Comparison done — bugs found:', result.bugs?.length || 0);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        }
      } catch (e) {
        console.error('[UID] Analyze error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      } finally {
        tmpPaths.forEach(p => { try { fs.unlinkSync(p); } catch {} });
      }
      return;
    }

    /* ── /api/ui-design/generate-scripts ───────────────────────────────── */
    if (req.method === 'POST' && req.url === '/api/ui-design/generate-scripts') {
      const _mToken = req.headers['x-member-token'];
      if (!_mToken || !memberSessions.has(_mToken)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required — please sign in' })); return; }
      try {
          const { testCases = [], pageUrl = '', figmaUrl = '', projectName = 'Doroob', demandName = 'Feature', jiraTicketKey = '' } = JSON.parse(body);
          const safeSlug = demandName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
          const tcList = testCases.map(tc =>
            `  TC-ID: ${tc.id}\n  Title: ${tc.title}\n  Priority: ${tc.priority||'Medium'}\n  Area: ${tc.area||'UI'}\n  Preconditions: ${tc.preconditions||'User is authenticated'}\n  Steps: ${(tc.steps||[]).join(' → ')}\n  Expected: ${tc.expected||''}`
          ).join('\n\n');

          const prompt = `You are a world-class Senior QA Automation Engineer working on the ${projectName} platform. Your objective is NOT to write scripts as quickly as possible. Your objective is to write production-ready, maintainable, and reliable Playwright automation scripts that compare the live implementation against the Figma design, detect visual and functional defects, and reflect execution results back onto the test cases sheet.

PROJECT SETUP:
Create a VS Code project named "doroob". Inside the project create a folder named "${demandName}". All Playwright scripts for this demand must be placed inside that folder.
Folder structure:
  doroob/
    ${demandName}/
      tests/
      pages/
      fixtures/
      reports/
  playwright.config.ts
  package.json
Use TypeScript. Use the Page Object Model pattern. Install: Playwright, Playwright Test, and visual comparison libraries if needed.

CONTEXT:
- Live Page URL: ${pageUrl || 'Not specified'}
- Figma Design Source: ${figmaUrl || 'Not specified'}
- Linked Jira Story: ${jiraTicketKey || 'Not linked'}
- Platform: Arabic-only, RTL

SCRIPT WRITING RULES:
1. Every script begins with a clear description of what it validates.
2. Every test has its own expected result.
3. NEVER mark a test passed because the page loaded, a button exists, or an API returned HTTP 200. A test ONLY passes after all expected business behavior and design elements are fully verified.
4. Each script covers:
   - Functional validation per acceptance criteria and business rules.
   - Figma design comparison: typography (family, size, weight, color hex, alignment), exact colors, layout/alignment, button labels and states, icons/images, spacing/padding, input styles and placeholders, error/success message styling, empty/loading states, RTL correctness (Arabic-only platform).
   - Responsive behavior: desktop (1920x1080), tablet (768x1024), mobile (375x812).
   - Cross-browser: Chrome, Firefox, Safari (webkit), Edge.
5. NEVER use page.waitForTimeout() or any fixed delay. For dynamic waits use: await expect(locator).toBeVisible({timeout:10000}), page.waitForLoadState('networkidle'), or page.waitForSelector().
6. STRONG assertions ONLY: toHaveText(), toHaveURL(), toContainText(), toHaveValue(), toBeChecked(), toHaveCount(), toHaveCSS() for design assertions.
7. For design comparison assertions, use toHaveCSS() with exact values extracted from the Figma specs in the test case (e.g. toHaveCSS('background-color', 'rgb(...)'), toHaveCSS('font-size', '16px')).

STRICT PASS/FAIL CRITERIA — treat any of the following as a failure:
- Broken layout or incorrect alignment vs Figma
- Incorrect colors, fonts, or spacing vs exact Figma values
- Missing/incorrect button labels
- Incorrect placeholder text or field labels
- Error messages exposing technical info, stack traces, IDs, or HTTP errors
- Any English or mixed Arabic/English text in the UI (Arabic-only platform)
- RTL issues: incorrect alignment, chevron/arrow direction, icon mirroring
- Incorrect navigation or unexpected redirects
- Missing loading indicators
- Incorrect or missing validation messages
- Any visual or functional difference between the Figma design and the live implementation

BUG HUNTING MINDSET — in every test, challenge the implementation:
- What could break? What assumptions is the developer making?
- Can validation be bypassed? Can permissions be bypassed?
- Can browser refresh break the flow? Can multiple tabs cause problems?
- Can empty values cause issues?
- Can the UI break on mobile or tablet?
- Can RTL or mixed-direction content break?
- Can session expiration cause problems?
- Does the implementation match every element in the Figma design exactly?

TEST CASES TO IMPLEMENT:
${tcList}

Generate exactly THREE files.

FILE 1 — playwright.config.ts (at project root):
Multi-browser: chromium, firefox, webkit (Safari), edge (use channel: 'msedge')
Three viewports as projects: Desktop 1920x1080, Tablet 768x1024, Mobile 375x812
baseURL: '${pageUrl || 'http://localhost:3000'}'
reporter: [['html', {open:'never'}]]
testDir: './${demandName}/tests'
retries: 1 in CI, 0 locally
use: { locale: 'ar', timezoneId: 'Asia/Riyadh', trace: 'on-first-retry', screenshot: 'only-on-failure' }

FILE 2 — ${demandName}/pages/${safeSlug}.page.ts:
Page Object class "${demandName.replace(/\s+/g,'').replace(/[^a-zA-Z0-9]/g,'')}Page"
Import Page, Locator from @playwright/test
Define every selector referenced in the test cases as a readonly Locator
Encapsulate every action (click, fill, navigate, assert) as an async method
Strict locator priority: getByRole > getByLabel > getByPlaceholder > getByTestId > getByText
Include a verifyDesignToken(locator: Locator, property: string, expectedValue: string) helper that calls expect(locator).toHaveCSS(property, expectedValue)

FILE 3 — ${demandName}/tests/${safeSlug}.spec.ts:
Import test, expect from @playwright/test
Import the Page Object
test.describe('${demandName}${jiraTicketKey?' — '+jiraTicketKey:''}', () => { ... })
One test() per test case. Title = TC-ID + test title.
beforeEach: instantiate page object, navigate to page
For EVERY test:
  - Assert the page loaded with a meaningful assertion (NOT just toBeVisible)
  - Validate functional behavior step by step following the test case steps
  - Validate at least ONE design property from the test case using toHaveCSS() or toHaveText()
  - Final assertion MUST directly validate the exact expected result from the test case

Return ONLY valid JSON (no markdown wrapper, no extra text):
{
  "config": "<full playwright.config.ts content>",
  "page": "<full ${demandName}/pages/${safeSlug}.page.ts content>",
  "spec": "<full ${demandName}/tests/${safeSlug}.spec.ts content>",
  "demandSlug": "${safeSlug}",
  "demandName": "${demandName}"
}`;

          console.log('[UID] Generating Playwright scripts for', demandName, '(', testCases.length, 'test cases)');
          const text = await callClaudeWithImages(prompt, []);
          const jsonMatch = text.match(/\{[\s\S]*\}/);
          if (!jsonMatch) throw new Error('AI returned invalid format');
          const result = JSON.parse(jsonMatch[0]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e) {
          console.error('[UID] Script gen error:', e.message);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      return;
    }

    res.writeHead(404); res.end();
  });
});


server.listen(PORT, () => {
  console.log('');
  console.log('  QA AI Platform is running');
  console.log('  App  → http://localhost:' + PORT + '/');
  console.log('  AI   → http://localhost:' + PORT + '/api/ai   (Anthropic direct)');
  console.log('  Jira → http://localhost:' + PORT + '/api/jira');
  console.log('  Perf → http://localhost:' + PORT + '/api/perf');
  console.log('');
  console.log('  Open http://localhost:' + PORT + '/ in your browser.');
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});
