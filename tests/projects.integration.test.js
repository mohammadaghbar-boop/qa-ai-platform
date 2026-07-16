// Integration tests for project field persistence (jiraProjKey / platform).
// Regression guard for the bug where PUT /api/projects/:id silently dropped
// jiraProjKey and platform — causing blank Jira keys in the admin table and
// "AIO project key missing" failures on import.
//
// Run: node --test tests/projects.integration.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

async function request(port, method, urlPath, body, headers) {
  const res = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(headers || {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let json = null; try { json = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status, json, raw: text };
}

async function startServer(reuseDataDir) {
  const dataDir = reuseDataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'qa-proj-'));
  const port = 4100 + Math.floor(Math.random() * 400);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', () => {}); child.stderr.on('data', () => {});
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    try { const r = await fetch(`http://127.0.0.1:${port}/`); if (r.status === 200) return { child, port, dataDir }; }
    catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  child.kill();
  throw new Error('Server did not become ready in time');
}

function stopServer(ctx) { if (ctx && ctx.child) { try { ctx.child.kill(); } catch {} } }

async function adminToken(port) {
  const login = await request(port, 'POST', '/api/admin/login', { password: 'admin' });
  assert.equal(login.status, 200, 'admin login should succeed');
  return login.json.token;
}

test('PUT /api/projects/:id persists jiraProjKey and platform', async () => {
  const ctx = await startServer();
  try {
    const tok = await adminToken(ctx.port);
    const created = await request(ctx.port, 'POST', '/api/projects',
      { name: 'Proj A', jiraProjKey: '', platform: 'web', language: 'ar' },
      { 'X-Admin-Token': tok });
    assert.equal(created.status, 200, 'project create should succeed');
    const id = created.json.id;

    const updated = await request(ctx.port, 'PUT', `/api/projects/${id}`,
      { name: 'Proj A', jiraProjKey: 'NFTH', platform: 'mobile', language: 'ar' },
      { 'X-Admin-Token': tok });
    assert.equal(updated.status, 200, 'project update should succeed');
    assert.equal(updated.json.jiraProjKey, 'NFTH', 'PUT response must return the new jiraProjKey');
    assert.equal(updated.json.platform, 'mobile', 'PUT response must return the new platform');

    // GET must reflect the persisted values, not just the PUT echo
    const list = await request(ctx.port, 'GET', '/api/projects', null, { 'X-Admin-Token': tok });
    const proj = list.json.find(p => p.id === id);
    assert.equal(proj.jiraProjKey, 'NFTH', 'GET must return persisted jiraProjKey');
    assert.equal(proj.platform, 'mobile', 'GET must return persisted platform');
  } finally { stopServer(ctx); }
});

test('jiraProjKey and platform survive a server restart (disk persistence)', async () => {
  let ctx = await startServer();
  const dataDir = ctx.dataDir;
  let id;
  try {
    const tok = await adminToken(ctx.port);
    const created = await request(ctx.port, 'POST', '/api/projects',
      { name: 'Proj B', platform: 'web', language: 'ar' }, { 'X-Admin-Token': tok });
    id = created.json.id;
    await request(ctx.port, 'PUT', `/api/projects/${id}`,
      { name: 'Proj B', jiraProjKey: 'ABCD', platform: 'both', language: 'ar' },
      { 'X-Admin-Token': tok });
  } finally { stopServer(ctx); }

  // Restart against the same DATA_DIR
  ctx = await startServer(dataDir);
  try {
    const tok = await adminToken(ctx.port);
    const list = await request(ctx.port, 'GET', '/api/projects', null, { 'X-Admin-Token': tok });
    const proj = list.json.find(p => p.id === id);
    assert.ok(proj, 'project must exist after restart');
    assert.equal(proj.jiraProjKey, 'ABCD', 'jiraProjKey must survive restart');
    assert.equal(proj.platform, 'both', 'platform must survive restart');
  } finally { stopServer(ctx); }
});

test('PUT leaves jiraProjKey/platform untouched when omitted from the body', async () => {
  const ctx = await startServer();
  try {
    const tok = await adminToken(ctx.port);
    const created = await request(ctx.port, 'POST', '/api/projects',
      { name: 'Proj C', jiraProjKey: 'KEEP', platform: 'mobile', language: 'ar' },
      { 'X-Admin-Token': tok });
    const id = created.json.id;

    // Update only the name — key/platform must not be wiped
    const updated = await request(ctx.port, 'PUT', `/api/projects/${id}`,
      { name: 'Proj C renamed' }, { 'X-Admin-Token': tok });
    assert.equal(updated.status, 200);
    assert.equal(updated.json.jiraProjKey, 'KEEP', 'omitted jiraProjKey must be preserved');
    assert.equal(updated.json.platform, 'mobile', 'omitted platform must be preserved');
    assert.equal(updated.json.name, 'Proj C renamed');
  } finally { stopServer(ctx); }
});

test('PUT requires admin auth', async () => {
  const ctx = await startServer();
  try {
    const tok = await adminToken(ctx.port);
    const created = await request(ctx.port, 'POST', '/api/projects',
      { name: 'Proj D', platform: 'web' }, { 'X-Admin-Token': tok });
    const id = created.json.id;
    const noAuth = await request(ctx.port, 'PUT', `/api/projects/${id}`,
      { jiraProjKey: 'HACK' }, {});
    assert.equal(noAuth.status, 401, 'unauthenticated PUT must be rejected');
  } finally { stopServer(ctx); }
});
