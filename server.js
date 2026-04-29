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
//   - Port 3456 (configured in docker-compose.yml)
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

// In-memory session store: token -> { memberId, claudeApiKey, jiraUrl, jiraAuth }
const sessions = new Map();
function createSession(memberId, claudeApiKey, jiraUrl, jiraEmail, jiraToken) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    memberId,
    claudeApiKey,
    jiraUrl:  jiraUrl  || '',
    jiraAuth: (jiraEmail && jiraToken) ? Buffer.from(jiraEmail + ':' + jiraToken).toString('base64') : ''
  });
  return token;
}
function getSession(req) {
  const token = req.headers['x-session-token'];
  return token ? sessions.get(token) || null : null;
}

const PORT = 3456;

// Empty MCP config — prevents claude CLI from using MCP tools (e.g. Atlassian)
const EMPTY_MCP = path.join(os.tmpdir(), 'qa-platform-no-mcp.json');
fs.writeFileSync(EMPTY_MCP, JSON.stringify({ mcpServers: {} }));

/* ── File-based data store (admin dashboard sync) ───────────────────────── */
// Mount /data as a Docker volume so data survives container restarts.
const DATA_DIR  = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'qa-platform-db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
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

function hashPassword(p) { return crypto.createHash('sha256').update(p).digest('hex'); }

// Set default admin password to 'admin' on first run
if (!serverDB.adminPasswordHash) {
  serverDB.adminPasswordHash = hashPassword('admin');
  serverDB.adminPasswordIsDefault = true;
  saveServerDB(serverDB);
  console.log('');
  console.log('  ℹ  Default admin credentials: admin / admin');
  console.log('  You will be prompted to change the password on first login.');
  console.log('');
}
// Migration: existing db without the isDefault flag — reset to admin so forced change runs
if (serverDB.adminPasswordIsDefault === undefined) {
  serverDB.adminPasswordHash = hashPassword('admin');
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

/* ── Claude AI (direct Anthropic API) ──────────────────────────────────── */
function callClaude(messages, system, claudeApiKey) {
  return new Promise((resolve, reject) => {
    if (!claudeApiKey) {
      reject(new Error('No Claude API key configured. Please add your API key in Settings.'));
      return;
    }
    const payload = JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 8192,
      ...(system ? { system } : {}),
      messages
    });
    const opts = {
      hostname: 'api.anthropic.com',
      path:     '/v1/messages',
      method:   'POST',
      headers:  {
        'Content-Type':      'application/json',
        'x-api-key':         claudeApiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length':    Buffer.byteLength(payload)
      }
    };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject(new Error('Claude API: ' + (parsed.error.message || parsed.error.type)));
          else resolve(parsed.content[0].text);
        } catch (e) { reject(new Error('Failed to parse Claude API response: ' + data.slice(0, 120))); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

/* ── Jira Proxy ─────────────────────────────────────────────────────────── */
function proxyJira(jiraUrl, path, method, auth, body) {
  return new Promise((resolve, reject) => {
    const url    = new URL(jiraUrl + '/rest/api/3' + path);
    const opts   = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   method,
      headers:  {
        'Authorization': 'Basic ' + auth,
        'Content-Type':  'application/json',
        'Accept':        'application/json'
      }
    };

    const req = https.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error('Jira ' + res.statusCode + ': ' + data.slice(0, 120)));
        } else {
          try { resolve(JSON.parse(data)); }
          catch { resolve(data); }
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

/* ── Jira Attachment Upload ─────────────────────────────────────────────── */
function attachToJira(jiraUrl, issueKey, auth, files) {
  return new Promise((resolve, reject) => {
    const boundary = '----QAPlatformBoundary' + Date.now().toString(16);
    const parts = [];
    for (const file of files) {
      const m = file.dataUrl.match(/^data:([^;]+);base64,(.+)$/);
      if (!m) continue;
      const fileData = Buffer.from(m[2], 'base64');
      parts.push(
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.name}"\r\nContent-Type: ${m[1]}\r\n\r\n`, 'utf8'),
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
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/* ── Playwright Test Runner ─────────────────────────────────────────────── */
function runPlaywrightTests(files) {
  return new Promise((resolve) => {
    const runId  = crypto.randomBytes(6).toString('hex');
    const tmpDir = path.join(os.tmpdir(), 'qa_pw_' + runId);
    const cleanup = () => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} };

    try {
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({ name:'qa-run', version:'1.0.0', private:true }));
      for (const [filePath, content] of Object.entries(files || {})) {
        if (filePath.endsWith('.md')) continue;
        const full = path.join(tmpDir, filePath);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content);
      }
    } catch (e) { cleanup(); resolve({ lines:['Error writing test files: '+e.message], passed:[], failed:[], error:e.message }); return; }

    const lines = [];
    let jsonOutput = '';
    const proc = spawn('npx', ['playwright', 'test', '--reporter=json'], { cwd: tmpDir, shell: true });
    proc.stdout.on('data', d => jsonOutput += d.toString());
    proc.stderr.on('data', d => d.toString().split('\n').filter(l=>l.trim()).forEach(l=>lines.push(l)));

    const timer = setTimeout(() => {
      try { proc.kill('SIGTERM'); } catch {}
      cleanup();
      resolve({ lines:[...lines,'✗ Test run timed out after 5 minutes'], passed:[], failed:[], error:'timeout' });
    }, 300000);

    proc.on('close', () => {
      clearTimeout(timer); cleanup();
      let passed = [], failed = [];
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
        }
      } catch {}
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
  const m    = (method || 'GET').toLowerCase();
  const vusN = parseInt(vus) || 100;
  const p95N = parseInt(p95Threshold) || 2000;
  const exp  = parseInt(expectedStatus) || 200;

  const baseHeaders = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (authType === 'bearer' && token)
    baseHeaders['Authorization'] = 'Bearer ' + token;
  if (authType === 'basic' && basicUsername)
    baseHeaders['Authorization'] = 'Basic ' + Buffer.from(basicUsername + ':' + (basicPassword || '')).toString('base64');

  const bodyArg = ['post', 'put', 'patch'].includes(m) && requestBody
    ? ', `' + (requestBody || '').replace(/`/g, '\\`') + '`'
    : '';

  let stages;
  if (testType === 'stress') {
    const s25 = Math.ceil(vusN * 0.25), s50 = Math.ceil(vusN * 0.5), s75 = Math.ceil(vusN * 0.75);
    stages = `[{duration:'${ramp}',target:${s25}},{duration:'${duration}',target:${s25}},{duration:'${ramp}',target:${s50}},{duration:'${duration}',target:${s50}},{duration:'${ramp}',target:${s75}},{duration:'${duration}',target:${s75}},{duration:'${ramp}',target:${vusN}},{duration:'${duration}',target:${vusN}},{duration:'${ramp}',target:0}]`;
  } else {
    stages = `[{duration:'${ramp}',target:${vusN}},{duration:'${duration}',target:${vusN}},{duration:'${ramp}',target:0}]`;
  }

  // CSV auth: pre-encode each username:password pair on the server side,
  // then embed the array in the k6 script so each VU picks its credential by index.
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
  const res = http.${m}('${apiUrl}'${bodyArg}, { headers });
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
  const res = http.${m}('${apiUrl}'${bodyArg}, { headers: ${JSON.stringify(baseHeaders)} });
  check(res, { 'status ${exp}': r => r.status === ${exp} });
  sleep(1);
}`;
}

function runK6(scriptPath) {
  return new Promise((resolve, reject) => {
    const summaryPath = scriptPath + '.summary.json';
    const proc = spawn('k6', ['run', '--summary-export', summaryPath, '--no-color', scriptPath], { shell: true });
    let stderr = '';
    proc.stderr.on('data', d => stderr += d.toString());
    proc.on('close', code => {
      try {
        if (!fs.existsSync(summaryPath))
          throw new Error(stderr.slice(0, 300) || 'k6 produced no output (exit ' + code + ')');
        const sum = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
        try { fs.unlinkSync(summaryPath); } catch {}
        const dur  = sum.metrics?.http_req_duration?.values || {};
        const req  = sum.metrics?.http_reqs?.values         || {};
        const fail = sum.metrics?.http_req_failed?.values   || {};
        resolve({
          passed: code === 0,
          metrics: {
            totalRequests: Math.round(req.count  || 0),
            rps:           parseFloat((req.rate  || 0).toFixed(2)),
            avgDuration:   parseFloat((dur.avg   || 0).toFixed(2)),
            minDuration:   parseFloat((dur.min   || 0).toFixed(2)),
            maxDuration:   parseFloat((dur.max   || 0).toFixed(2)),
            p50:           parseFloat((dur['p(50)'] || 0).toFixed(2)),
            p90:           parseFloat((dur['p(90)'] || 0).toFixed(2)),
            p95:           parseFloat((dur['p(95)'] || 0).toFixed(2)),
            p99:           parseFloat((dur['p(99)'] || 0).toFixed(2)),
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
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  /* ── Codegen status (GET) ── */
  if (req.method === 'GET' && req.url.startsWith('/api/codegen/status/')) {
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
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(serverDB));
    return;
  }

  /* ── Serve app ── */
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'QA AI Platform.html'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (e) {
      res.writeHead(500); res.end('Could not read app file: ' + e.message);
    }
    return;
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    /* ── /api/codegen/start ── */
    if (req.method === 'POST' && req.url === '/api/codegen/start') {
      try {
        const { url } = JSON.parse(body);
        if (!url) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'url is required' })); return; }
        const sessionId  = crypto.randomBytes(8).toString('hex');
        const outputFile = path.join(os.tmpdir(), `qa_codegen_${sessionId}.js`);
        const proc = spawn('npx', ['playwright', 'codegen', url, '--output', outputFile], { shell: true });
        const session = { proc, outputFile, status: 'running', script: null };
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
        console.log('[Codegen] Started session', sessionId, 'for', url);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/codegen/:id (DELETE — cancel) ── */
    if (req.method === 'DELETE' && req.url.startsWith('/api/codegen/')) {
      const sessionId = req.url.split('/api/codegen/')[1];
      const s = codegenSessions.get(sessionId);
      if (s) { try { s.proc.kill(); } catch {} codegenSessions.delete(sessionId); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true })); return;
    }

    /* ── /api/playwright/run ── */
    if (req.method === 'POST' && req.url === '/api/playwright/run') {
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
      try {
        const { email, password } = JSON.parse(body);
        if (!serverDB.members) serverDB.members = [];
        const member = serverDB.members.find(m => m.email === email);
        if (!member || hashPassword(password || '') !== member.passwordHash) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid email or password' })); return;
        }
        const token = crypto.randomBytes(32).toString('hex');
        memberSessions.set(token, { memberId: member.id });
        console.log('[Member] Login:', member.name);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, member: { id: member.id, name: member.name, email: member.email, role: member.role } }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
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
        if (!serverDB.members) serverDB.members = [];
        if (serverDB.members.find(m => m.email === email)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'A member with this email already exists' })); return;
        }
        const member = { id: crypto.randomBytes(6).toString('hex'), name, email, role: role || 'QA Engineer', passwordHash: hashPassword(password), createdAt: Date.now() };
        serverDB.members.push(member);
        saveServerDB(serverDB);
        console.log('[Member] Created:', name);
        const { passwordHash, ...safe } = member;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(safe));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
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
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/admin/login ── */
    if (req.method === 'POST' && req.url === '/api/admin/login') {
      try {
        const { password } = JSON.parse(body);
        if (hashPassword(password || '') !== serverDB.adminPasswordHash) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid password' }));
          return;
        }
        const token = crypto.randomBytes(32).toString('hex');
        adminSessions.set(token, { createdAt: Date.now() });
        console.log('[Admin] Login successful');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, isDefaultPassword: !!serverDB.adminPasswordIsDefault }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
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
        if (hashPassword(currentPassword || '') !== serverDB.adminPasswordHash) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Current password is incorrect' })); return;
        }
        if (!newPassword || newPassword.length < 6) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'New password must be at least 6 characters' })); return;
        }
        serverDB.adminPasswordHash = hashPassword(newPassword);
        serverDB.adminPasswordIsDefault = false;
        saveServerDB(serverDB);
        console.log('[Admin] Password changed');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/auth/session ── */
    if (req.method === 'POST' && req.url === '/api/auth/session') {
      try {
        const { memberId, claudeApiKey, jiraUrl, jiraEmail, jiraToken } = JSON.parse(body);
        if (!claudeApiKey) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'claudeApiKey is required' }));
          return;
        }
        const sessionToken = createSession(memberId, claudeApiKey, jiraUrl, jiraEmail, jiraToken);
        console.log('[Auth] Session created for member:', memberId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionToken }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/ai ── */
    if (req.method === 'POST' && req.url === '/api/ai') {
      try {
        const session = getSession(req);
        const parsed  = JSON.parse(body);
        const claudeApiKey = session?.claudeApiKey || parsed.claudeApiKey;
        const { messages, system } = parsed;
        console.log('[AI]   Request —', (messages.at(-1)?.content || '').slice(0, 80) + '…');
        const text = await callClaude(messages, system, claudeApiKey);
        console.log('[AI]   Done    —', text.slice(0, 60) + '…');
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
      try {
        const session  = getSession(req);
        const parsed   = JSON.parse(body);
        const jiraUrl  = session?.jiraUrl  || parsed.jiraUrl;
        const auth     = session?.jiraAuth || parsed.auth;
        const { path, method, body: jiraBody } = parsed;
        console.log('[Jira] Request —', method, path);
        const data = await proxyJira(jiraUrl, path, method, auth, jiraBody);
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
      try {
        const session = getSession(req);
        const parsed  = JSON.parse(body);
        const jiraUrl = session?.jiraUrl  || parsed.jiraUrl;
        const auth    = session?.jiraAuth || parsed.auth;
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

    /* ── /api/perf ── */
    if (req.method === 'POST' && req.url === '/api/perf') {
      try {
        const params    = JSON.parse(body);
        const tmpScript = path.join(os.tmpdir(), 'qa_k6_' + Date.now() + '.js');
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

    /* ── /api/sync ── */
    if (req.method === 'POST' && req.url === '/api/sync') {
      try {
        const payload = JSON.parse(body);
        const { type } = payload;
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
