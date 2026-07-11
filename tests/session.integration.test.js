// End-to-end HTTP integration tests for the AIO-token persistence fix.
// Spawns real server processes against isolated DATA_DIRs and verifies the
// aioToken fix through the *existing* production endpoint /api/aio/import.
//
// Discrimination without a probe endpoint:
//   - No token in session  → /api/aio/import returns 400 "AIO token not configured…"
//   - Token in session     → aioImport proceeds and calls the real AIO API
//                             (we point AIO_BASE_URL at an unreachable host, so it
//                             fails with a *different* error — that "different" is
//                             the signal that the token DID reach the session).
//
// This lets us prove aioToken persistence through save / refresh / restart / merge
// without introducing a new production endpoint solely for tests.
//
// Run: node --test tests/session.integration.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// AIO_BASE_URL that always fails (loopback port 1 is not listening).
// aioImport will make its first outbound HTTP call, error out, and the /api/aio/import
// handler will return a 500 with an error string that is NOT the "not configured" one.
const UNREACHABLE_AIO = 'http://127.0.0.1:1/aio-tcms/api/v1';
const MISSING_TOKEN_ERR = /AIO token not configured/i;

// ── Tiny HTTP helper ─────────────────────────────────────────────────────
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

// Start a fresh server in a child process. Isolated DATA_DIR, random port,
// AIO endpoint pointed at an unreachable host.
async function startServer(reuseDataDir) {
  const dataDir = reuseDataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'qa-int-'));
  const port = 3600 + Math.floor(Math.random() * 400);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(port), AIO_BASE_URL: UNREACHABLE_AIO },
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

async function setupMember(port) {
  const adminLogin = await request(port, 'POST', '/api/admin/login', { password: 'admin' });
  assert.equal(adminLogin.status, 200, 'admin login should succeed');
  const adminToken = adminLogin.json.token;
  const created = await request(port, 'POST', '/api/members',
    { name: 'Test QA', email: 'test.qa@example.com', password: 'Test1234$', role: 'QA Engineer' },
    { 'X-Admin-Token': adminToken });
  assert.equal(created.status, 200, 'member create should succeed');
  const memberLogin = await request(port, 'POST', '/api/members/login',
    { email: 'test.qa@example.com', password: 'Test1234$' });
  assert.equal(memberLogin.status, 200, 'member login should succeed');
  return {
    memberId:     memberLogin.json.member.id,
    memberToken:  memberLogin.json.token,
    sessionToken: memberLogin.json.sessionToken
  };
}

// Attempt an AIO import against the unreachable AIO base URL.
// Returns { status, missingTokenErr } so tests can assert on the discriminator.
async function tryImport(port, sessionToken) {
  const r = await request(port, 'POST', '/api/aio/import',
    { projectKey: 'NFTH', storyKey: 'NFTH-1', cases: [{ title: 't' }], dryRun: true },
    { 'X-Session-Token': sessionToken });
  return { status: r.status, missingTokenErr: MISSING_TOKEN_ERR.test(r.json?.error || r.raw || '') };
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 1: Save an AIO token → aioImport no longer reports "not configured"
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 1: save AIO token → session carries it (aioImport proceeds past the guard)', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);

    // Baseline: with no aioToken saved, aioImport MUST return the missing-token error.
    const before = await tryImport(ctx.port, m.sessionToken);
    assert.equal(before.missingTokenErr, true, 'baseline: aioImport should report missing token before save');

    // Save credentials WITH an aioToken.
    const saved = await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-1' },
      { 'X-Member-Token': m.memberToken });
    assert.equal(saved.status, 200);

    // Now aioImport must NOT report "not configured" — it should try (and fail on) AIO reachability.
    const after = await tryImport(ctx.port, saved.json.sessionToken);
    assert.equal(after.missingTokenErr, false, 'after save: aioImport must NOT report missing token');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 2: Refresh session — token survives (THE ORIGINAL BUG)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 2: refresh session → token still in session (the original bug)', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);
    await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-2' },
      { 'X-Member-Token': m.memberToken });

    const refreshed = await request(ctx.port, 'POST', '/api/members/session/refresh',
      null, { 'X-Member-Token': m.memberToken });
    assert.equal(refreshed.status, 200);

    // The refreshed session token must carry aioToken through — else this reports "not configured".
    const r = await tryImport(ctx.port, refreshed.json.sessionToken);
    assert.equal(r.missingTokenErr, false, 'refreshed session must still carry aioToken');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 3: Restart the server — token persisted on disk
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 3: restart server → token persisted through disk (encryption round-trip)', async () => {
  const ctx1 = await startServer();
  const dataDir = ctx1.dataDir;
  try {
    const m = await setupMember(ctx1.port);
    await request(ctx1.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-3' },
      { 'X-Member-Token': m.memberToken });
  } finally { stopServer(ctx1); }

  // Second boot, SAME data dir. Fresh in-memory session store — must re-hydrate from disk on login.
  const ctx2 = await startServer(dataDir);
  try {
    const reLogin = await request(ctx2.port, 'POST', '/api/members/login',
      { email: 'test.qa@example.com', password: 'Test1234$' });
    assert.equal(reLogin.status, 200);
    const r = await tryImport(ctx2.port, reLogin.json.sessionToken);
    assert.equal(r.missingTokenErr, false, 'token must survive server restart via encrypted DB');
  } finally { stopServer(ctx2); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 4: PATCH-style save (no aioToken in body) preserves existing token
// (The merge logic added in the fix — the subtlest path in this PR.)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 4: save without aioToken preserves the existing one (merge logic)', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);
    await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-4' },
      { 'X-Member-Token': m.memberToken });

    // Second save: NO aioToken in body — simulates the UI's Jira-only save flow.
    const again = await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT-new' },
      { 'X-Member-Token': m.memberToken });
    assert.equal(again.status, 200);

    const r = await tryImport(ctx.port, again.json.sessionToken);
    assert.equal(r.missingTokenErr, false, 'existing aioToken must survive a Jira-only save');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 5: Explicit clear (aioToken='') MUST wipe the token
// (Guards against the merge over-preserving.)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 5: explicit empty aioToken clears the stored token', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);
    await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-5' },
      { 'X-Member-Token': m.memberToken });

    const cleared = await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: '' },
      { 'X-Member-Token': m.memberToken });
    assert.equal(cleared.status, 200);

    const r = await tryImport(ctx.port, cleared.json.sessionToken);
    assert.equal(r.missingTokenErr, true, 'explicit empty aioToken must clear the stored token');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 6: aioImport correctly reports the missing-token error (the guard itself)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 6: aioImport reports "not configured" when the session has no token', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);
    const r = await tryImport(ctx.port, m.sessionToken);
    assert.equal(r.status >= 400 && r.status < 600, true, 'should be a 4xx/5xx, not a crash');
    assert.equal(r.missingTokenErr, true, 'missing-token error string should be present');
  } finally { stopServer(ctx); }
});
