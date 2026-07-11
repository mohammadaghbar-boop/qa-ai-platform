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
//   - No .env file needed — credentials are managed inside the app per member
// ─────────────────────────────────────────────────────────────────────────────

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

// In-memory session store: token -> { memberId, jiraUrl, jiraAuth, aioToken, createdAt }
const sessions = new Map();
function createSession(memberId, jiraUrl, jiraEmail, jiraToken, aioToken) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    memberId,
    jiraUrl:  jiraUrl  || '',
    jiraAuth: (jiraEmail && jiraToken) ? Buffer.from(jiraEmail + ':' + jiraToken).toString('base64') : '',
    aioToken: aioToken || '',
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
// In-memory member sessions
const memberSessions = new Map();
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

/* ── Claude AI (direct Anthropic API — used when ANTHROPIC_API_KEY is set) ── */
function callAnthropicAPI(messages, system, maxTokens=4000, model='') {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: model || 'claude-haiku-4-5-20251001',
      max_tokens: maxTokens,
      system: system || undefined,
      messages: messages.map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }))
    });
    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 300000
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode === 200 && json.content && json.content[0]) {
            resolve(json.content.map(b => b.text || '').join(''));
          } else {
            reject(new Error('Anthropic API ' + res.statusCode + ': ' + (json.error ? json.error.message : data.slice(0, 300))));
          }
        } catch (e) { reject(new Error('Anthropic API parse error: ' + e.message)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Anthropic API request timed out after 5 minutes.')); });
    req.on('error', e => reject(new Error('Anthropic API request failed: ' + e.message)));
    req.write(payload);
    req.end();
  });
}

/* ── Claude AI (via Claude CLI — no API key required) ───────────────────── */
function callClaude(messages, system, maxTokens=4000, model='') {
  return new Promise((resolve, reject) => {
    const conversation = messages.map(m =>
      (m.role === 'user' ? 'Human' : 'Assistant') + ': ' + m.content
    ).join('\n\n');
    const fullPrompt = system ? `[System: ${system}]\n\n${conversation}` : conversation;
    const isWin = process.platform === 'win32';
    const claudeCmd = isWin ? 'cmd' : 'claude';
    const modelArgs = model ? ['--model', model] : [];
    const claudeArgs = isWin
      ? ['/c', process.env.APPDATA + '\\npm\\claude.cmd', '-p', '--output-format', 'text', '--effort', 'low', ...modelArgs, '--strict-mcp-config', '--mcp-config', EMPTY_MCP]
      : ['-p', '--output-format', 'text', '--effort', 'low', ...modelArgs, '--strict-mcp-config', '--mcp-config', EMPTY_MCP];
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

/* ── Jira Proxy ─────────────────────────────────────────────────────────── */
function proxyJira(jiraUrl, jiraPath, method, auth, body) {
  return new Promise((resolve, reject) => {
    if (!jiraUrl || !isValidJiraUrl(jiraUrl)) {
      reject(new Error('Invalid Jira URL. Must be a public HTTPS address.')); return;
    }
    // Use only the origin (protocol + hostname) — strip any path the user may have pasted
    const baseUrl = new URL(jiraUrl).origin;
    const url  = new URL(baseUrl + '/rest/api/3' + jiraPath);
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

/* ── AIO Tests Importer ─────────────────────────────────────────────────── */
// Shared AIO Tests cloud endpoint (same for all cloud instances). Override with
// AIO_BASE_URL env var if a member's instance differs.
const AIO_BASE = process.env.AIO_BASE_URL || 'https://tcms.aiojiraapps.com/aio-tcms/api/v1';
const AIO_PRIORITY_MAP = {
  critical: 'Critical', highest: 'Critical', high: 'High', hi: 'High',
  medium: 'Medium', med: 'Medium', normal: 'Medium', low: 'Low', lowest: 'Lowest'
};

// Thin AIO REST call. Returns {status, json, raw}. Never throws on HTTP errors (caller inspects status).
function aioFetch(token, method, projectKey, subPath, bodyObj) {
  return new Promise((resolve, reject) => {
    const url = new URL(AIO_BASE + '/project/' + encodeURIComponent(projectKey) + subPath);
    const payload = bodyObj ? JSON.stringify(bodyObj) : null;
    const opts = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   method,
      timeout:  REQ_TIMEOUT,
      headers: {
        'Authorization': 'AioAuth ' + token,
        'Content-Type':  'application/json',
        'Accept':        'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    };
    const req = https.request(opts, r => {
      let data = ''; r.on('data', d => data += d);
      r.on('end', () => {
        let json = null; try { json = data ? JSON.parse(data) : null; } catch {}
        resolve({ status: r.statusCode, json, raw: data });
      });
    });
    req.on('timeout', () => { req.destroy(new Error('AIO request timed out')); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// Orchestrates importing platform test cases into AIO Tests. Mirrors the reference
// Python importer's payloads/endpoints. Returns a {created, skipped, failed, ...} summary.
async function aioImport(session, opts) {
  const { projectKey, parentFolder, storyKey, cases, dryRun } = opts;
  const token = session.aioToken;
  if (!token) throw new Error('AIO token not configured. Add it in Settings.');
  if (!projectKey) throw new Error('AIO project key missing (set the Jira Project Key on the project).');
  if (!Array.isArray(cases) || cases.length === 0) throw new Error('No approved cases to import.');

  // 1) Verify connection + load priorities / script type / case type from project config.
  const cfgRes = await aioFetch(token, 'GET', projectKey, '/config');
  if (cfgRes.status === 401) throw new Error('AIO authentication failed (401). Check the AIO API token.');
  if (cfgRes.status === 404) throw new Error(`AIO project '${projectKey}' not found (404). Check the project key.`);
  if (cfgRes.status >= 400 || !cfgRes.json) throw new Error('AIO /config request failed (HTTP ' + cfgRes.status + ').');
  const cfg = cfgRes.json;
  const pickDefault = arr => { arr = arr || []; return arr.find(x => x.isDefault) || arr.find(x => !x.isArchived) || arr[0] || null; };
  const priorities = {};
  for (const p of (cfg.casePriorities || cfg.priorities || [])) {
    const n = String(p.name || '').trim().toLowerCase(); const id = (p.ID != null ? p.ID : p.id);
    if (n && id != null) priorities[n] = id;
  }
  const st = pickDefault(cfg.caseScriptTypes); const scriptType = (st && st.ID != null) ? { ID: st.ID } : null;
  const ct = pickDefault(cfg.caseTypes);       const caseType   = (ct && ct.ID != null) ? { ID: ct.ID } : null;

  // 2) Resolve target folder (READ-ONLY — this AIO instance can't create folders via API).
  let folderId = null;
  if (parentFolder) {
    const fRes = await aioFetch(token, 'GET', projectKey, '/testcase/folder');
    const flat = [];
    const flatten = (nodes, parent) => {
      for (const n of nodes || []) {
        const fid = (n.ID != null ? n.ID : n.id); const name = n.name || n.title || '';
        flat.push({ fid, name, parent });
        flatten(n.children || n.subFolders || [], fid);
      }
    };
    if (fRes.json) flatten(fRes.json, null);
    const findF = (name, parent) => {
      const hit = flat.find(f => String(f.name).trim().toLowerCase() === String(name).trim().toLowerCase()
        && (parent == null || f.parent === parent));
      return hit ? hit.fid : null;
    };
    const parentId = findF(parentFolder, null);
    if (parentId != null) folderId = storyKey ? (findF(storyKey, parentId) != null ? findF(storyKey, parentId) : parentId) : parentId;
  }

  // 3) Resolve the Jira story to its numeric ID for the requirement link (best-effort).
  let requirementId = null;
  if (storyKey && session.jiraUrl && session.jiraAuth) {
    try {
      const issue = await proxyJira(session.jiraUrl, `/issue/${storyKey}?fields=id`, 'GET', session.jiraAuth);
      if (issue && issue.id) requirementId = parseInt(issue.id, 10);
    } catch { /* non-fatal — import without the link */ }
  }

  // 4) Dedup: collect existing case titles in the target folder.
  const existing = new Set();
  if (folderId != null) {
    let startAt = 0; const pageSize = 100;
    while (true) {
      const lr = await aioFetch(token, 'GET', projectKey, `/testcase?startAt=${startAt}&maxResults=${pageSize}`);
      if (!lr.json) break;
      const items = Array.isArray(lr.json) ? lr.json : (lr.json.items || lr.json.testCases || []);
      if (!Array.isArray(items) || items.length === 0) break;
      for (const c of items) {
        const f = c.folder || {}; const fid = (f && typeof f === 'object') ? f.ID : null;
        if (fid === folderId) { const t = String(c.title || '').trim().toLowerCase(); if (t) existing.add(t); }
      }
      if (items.length < pageSize) break;
      startAt += pageSize;
    }
  }

  // 5) Create each case (multi-step payload built from the platform's per-step arrays).
  const summary = { created: 0, skipped: 0, failed: 0, errors: [], folderId, requirementId, dryRun: !!dryRun, total: cases.length };
  for (const c of cases) {
    const title = String(c.title || '').trim();
    if (!title) continue;
    if (existing.has(title.toLowerCase())) { summary.skipped++; continue; }

    const steps = Array.isArray(c.steps) ? c.steps : [];
    const stepResults = Array.isArray(c.stepResults) ? c.stepResults : [];
    const stepData = Array.isArray(c.stepData) ? c.stepData : [];
    let stepObjs;
    if (steps.length) {
      stepObjs = steps.map((s, i) => ({
        stepType: 'TEXT',
        step: String(s || ''),
        data: String(stepData[i] || ''),
        expectedResult: String(stepResults[i] || (i === steps.length - 1 ? (c.expected || '') : ''))
      }));
    } else {
      stepObjs = [{ stepType: 'TEXT', step: '', data: String(c.testData || ''), expectedResult: String(c.expected || '') }];
    }

    const prioName = AIO_PRIORITY_MAP[String(c.priority || '').trim().toLowerCase()] || 'Medium';
    const payload = { title, precondition: c.preconditions || null, steps: stepObjs };
    const pid = priorities[prioName.toLowerCase()];
    payload.priority = (pid != null) ? { ID: pid } : { name: prioName };
    if (folderId != null) { payload.folder = { ID: folderId }; payload.folderID = folderId; }
    if (requirementId != null) payload.jiraRequirementIDs = [requirementId];
    if (scriptType) payload.scriptType = scriptType;
    if (caseType) payload.caseType = caseType;

    if (dryRun) { summary.created++; existing.add(title.toLowerCase()); continue; }
    try {
      const cr = await aioFetch(token, 'POST', projectKey, '/testcase', payload);
      if (cr.status === 200 || cr.status === 201) { summary.created++; existing.add(title.toLowerCase()); }
      else { summary.failed++; summary.errors.push(`${c.id || title.slice(0, 30)}: HTTP ${cr.status} ${String(cr.raw || '').slice(0, 150)}`); }
    } catch (e) {
      summary.failed++; summary.errors.push(`${c.id || title.slice(0, 30)}: ${e.message}`);
    }
  }
  return summary;
}

/* ── Playwright Test Runner ─────────────────────────────────────────────── */
function runPlaywrightTests(files) {
  return new Promise((resolve) => {
    const runId  = crypto.randomBytes(16).toString('hex');
    const tmpDir = path.join(os.tmpdir(), 'qa_pw_' + runId);
    const cleanup = () => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} };

    try {
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name:'qa-run', version:'1.0.0', private:true }));
      // Playwright config: disable browser download, set testDir, use JSON reporter
      const pwConfig = `module.exports = { testDir: '.', timeout: 60000, use: { headless: true } };`;
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
    let jsonOutput = '';
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
    const preCheck = spawnSync('npx', ['playwright', '--version'], {
      cwd: tmpDir, shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: spawnEnv, timeout: 15000
    });
    if (preCheck.status !== 0 || preCheck.error) {
      cleanup();
      resolve({ lines: [], passed: [], failed: [], error: 'not_installed' });
      return;
    }

    const proc = spawn('npx', ['playwright', 'test', '--reporter=json'], {
      cwd: tmpDir, shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: spawnEnv
    });
    proc.stdout.on('data', d => jsonOutput += d.toString());
    proc.stderr.on('data', d => d.toString().split('\n').filter(l=>l.trim()).forEach(l=>lines.push(l)));

    const killProc = () => {
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/F', '/T', '/PID', String(proc.pid)], { shell: true, stdio: 'ignore' });
        } else {
          proc.kill('SIGTERM');
        }
      } catch {}
    };

    const timer = setTimeout(() => {
      killProc(); cleanup();
      resolve({ lines:[...lines,'✗ Test run timed out after 5 minutes'], passed:[], failed:[], error:'timeout' });
    }, 300000);

    proc.on('close', (code) => {
      clearTimeout(timer); cleanup();
      let passed = [], failed = [];
      const globalErrors = [];
      try {
        const s = jsonOutput.indexOf('{'), e = jsonOutput.lastIndexOf('}');
        if (s >= 0 && e > s) {
          const results = JSON.parse(jsonOutput.slice(s, e + 1));
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
        }
      } catch {}

      // Surface global errors so the user knows WHY 0 tests ran
      if (globalErrors.length > 0) {
        lines.unshift('');
        globalErrors.forEach(e => lines.unshift('✗ ' + e));
        lines.unshift('Playwright reported global errors:');
        // Detect @playwright/test module not found — treat as not_installed
        const errText = globalErrors.join('\n').toLowerCase();
        if (errText.includes("cannot find module") && errText.includes('playwright')) {
          resolve({ lines, passed: [], failed: [], error: 'not_installed' });
          return;
        }
      }

      lines.push(''); lines.push('Results: '+passed.length+' passed, '+failed.length+' failed');
      resolve({ lines, passed, failed, error: null });
    });

    proc.on('error', e => {
      clearTimeout(timer); cleanup();
      resolve({ lines:[], passed:[], failed:[], error: e.code==='ENOENT'?'not_installed':e.message });
    });
  });
}

/* ── Performance Test (k6) ─────────────────────────────────────────────── */
function generateK6Script({ testType, method, apiUrl, vus, duration, ramp, p95Threshold, authType, token, basicUsername, basicPassword, requestBody, expectedStatus, csvUsers }) {
  const m    = ['get','post','put','patch','delete'].includes((method||'').toLowerCase()) ? (method||'GET').toLowerCase() : 'get';
  const vusN = parseInt(vus) || 100;
  const p95N = parseInt(p95Threshold) || 2000;
  const exp  = parseInt(expectedStatus) || 200;
  // Validate and sanitize URL and durations
  const safeUrl  = isValidHttpUrl(apiUrl) ? apiUrl : 'http://localhost';
  const safeDur  = sanitizeK6Duration(duration);
  const safeRamp = sanitizeK6Duration(ramp);

  const baseHeaders = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (authType === 'bearer' && token)
    baseHeaders['Authorization'] = 'Bearer ' + token;
  if (authType === 'basic' && basicUsername)
    baseHeaders['Authorization'] = 'Basic ' + Buffer.from(basicUsername + ':' + (basicPassword || '')).toString('base64');

  const bodyArg = ['post', 'put', 'patch'].includes(m) && requestBody
    ? `, ${JSON.stringify(String(requestBody))}`
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
export let options = {
  stages: ${stages},
  thresholds: { 'http_req_duration': ['p(95)<${p95N}'], 'http_req_failed': ['rate<0.05'] }
};
export default function () {
  const headers = ${JSON.stringify(baseHeaders)};
  headers['Authorization'] = 'Basic ' + __creds[(__VU - 1) % __creds.length];
  const res = http.${m}('${safeUrl}'${bodyArg}, { headers });
  check(res, { 'status ${exp}': r => r.status === ${exp} });
  sleep(1);
}`;
  }

  return `import http from 'k6/http';
import { check, sleep } from 'k6';
export let options = {
  stages: ${stages},
  thresholds: { 'http_req_duration': ['p(95)<${p95N}'], 'http_req_failed': ['rate<0.05'] }
};
export default function () {
  const res = http.${m}('${safeUrl}'${bodyArg}, { headers: ${JSON.stringify(baseHeaders)} });
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
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token, X-Admin-Token');
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
      const html = fs.readFileSync(path.join(__dirname, 'QA AI Platform.html'), 'utf8');
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
        const proc = spawn('npx', ['playwright', 'codegen', url, '--output', outputFile], { shell: true });
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

    /* ── /api/playwright/run (requires session) ── */
    if (req.method === 'POST' && req.url === '/api/playwright/run') {
      if (!getSession(req)) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const parsed = JSON.parse(body);
        const result = await runPlaywrightTests(parsed.files || {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message, lines: [], passed: [], failed: [] }));
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
        const { memberId, jiraUrl, jiraEmail, jiraToken, aioToken } = JSON.parse(body);
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
        const sessionToken = createSession(memberId, jiraUrl, jiraEmail, jiraToken, aioToken);
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
        const { messages, system, max, model } = JSON.parse(body);
        const useAPI = !!process.env.ANTHROPIC_API_KEY;
        console.log('[AI]   Request received' + (model ? ' (model: ' + model + ')' : '') + (useAPI ? ' [direct API]' : ' [CLI]'));
        const text = useAPI
          ? await callAnthropicAPI(messages, system, max||4000, model||'')
          : await callClaude(messages, system, max||4000, model||'');
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

    /* ── /api/aio/import ── */
    if (req.method === 'POST' && req.url === '/api/aio/import') {
      const session = getSession(req);
      if (!session) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Authentication required' })); return; }
      try {
        const { projectKey, parentFolder, storyKey, cases, dryRun } = JSON.parse(body);
        if (!session.aioToken) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'AIO token not configured. Open Settings and add your AIO Tests API token, then reconnect.' }));
          return;
        }
        console.log('[AIO]  Import request —', (dryRun ? 'DRY-RUN ' : ''), (Array.isArray(cases) ? cases.length : 0), 'case(s), project', projectKey, 'story', storyKey || 'none');
        const summary = await aioImport(session, { projectKey, parentFolder, storyKey, cases, dryRun });
        console.log('[AIO]  Done — created', summary.created, 'skipped', summary.skipped, 'failed', summary.failed);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(summary));
      } catch (e) {
        console.error('[AIO]  Error:', e.message);
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
