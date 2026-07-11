// End-to-end HTTP integration tests for the AIO-token persistence fix.
// Spawns real server processes against isolated DATA_DIRs so nothing touches
// production data. Verifies the exact bug flow the fix targets.
//
// Run: node --test tests/session.integration.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// ── Tiny HTTP helper against a specific port ──────────────────────────────
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

// Start a fresh server in a child process on a random free port, isolated DATA_DIR.
async function startServer() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qa-int-'));
  const port = 3600 + Math.floor(Math.random() * 400); // low-collision range
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DATA_DIR: dataDir, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', () => {}); child.stderr.on('data', () => {}); // drain
  // Wait until the port responds (max ~4s).
  const deadline = Date.now() + 4000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/`);
      if (r.status === 200) return { child, port, dataDir };
    } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  child.kill();
  throw new Error('Server did not become ready in time');
}

function stopServer(ctx) {
  if (ctx && ctx.child) { try { ctx.child.kill(); } catch {} }
}

// End-to-end helper: admin log-in, create a member, log the member in.
async function setupMember(port) {
  // Admin log-in with the default bootstrap password.
  const adminLogin = await request(port, 'POST', '/api/admin/login', { password: 'admin' });
  assert.equal(adminLogin.status, 200, 'admin login should succeed');
  const adminToken = adminLogin.json.token;
  // Create member.
  const created = await request(port, 'POST', '/api/members',
    { name: 'Test QA', email: 'test.qa@example.com', password: 'Test1234$', role: 'QA Engineer' },
    { 'X-Admin-Token': adminToken });
  assert.equal(created.status, 200, 'member create should succeed');
  // Member log-in.
  const memberLogin = await request(port, 'POST', '/api/members/login',
    { email: 'test.qa@example.com', password: 'Test1234$' });
  assert.equal(memberLogin.status, 200, 'member login should succeed');
  return {
    memberId:     memberLogin.json.member.id,
    memberToken:  memberLogin.json.token,     // long-lived, used by /session/refresh
    sessionToken: memberLogin.json.sessionToken // short-lived, used by /api/*
  };
}

async function probe(port, sessionToken) {
  return request(port, 'GET', '/api/session/probe', null, { 'X-Session-Token': sessionToken });
}

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 1: Save an AIO token, probe confirms it is on the session
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 1: save AIO token → session has hasAioToken=true', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);

    // Save credentials WITH an AIO token.
    const saved = await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-1' },
      { 'X-Member-Token': m.memberToken });
    assert.equal(saved.status, 200, 'credentials save should succeed');
    assert.ok(saved.json.sessionToken, 'save should return a fresh sessionToken');

    // Probe the fresh session.
    const p = await probe(ctx.port, saved.json.sessionToken);
    assert.equal(p.status, 200);
    assert.equal(p.json.hasAioToken, true, 'session must have the AIO token after save');
    assert.equal(p.json.hasJiraAuth, true, 'session must also have Jira auth');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 2: Refresh the session — AIO token must survive
// (This is the ORIGINAL BUG. Before the fix, refresh dropped aioToken.)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 2: refresh session → AIO token still present (the original bug)', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);

    // Save with aioToken.
    await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-2' },
      { 'X-Member-Token': m.memberToken });

    // Refresh the session.
    const refreshed = await request(ctx.port, 'POST', '/api/members/session/refresh',
      null, { 'X-Member-Token': m.memberToken });
    assert.equal(refreshed.status, 200, 'session refresh should succeed');
    assert.ok(refreshed.json.sessionToken, 'refresh should return a new session token');

    // Probe the refreshed session.
    const p = await probe(ctx.port, refreshed.json.sessionToken);
    assert.equal(p.status, 200);
    assert.equal(p.json.hasAioToken, true, 'refreshed session must still have the AIO token');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 3: Restart the server — AIO token must be persisted on disk
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 3: restart server → AIO token persisted through disk + refresh', async () => {
  // Boot #1: save token.
  const ctx1 = await startServer();
  let memberId, memberToken;
  try {
    const m = await setupMember(ctx1.port);
    memberId = m.memberId; memberToken = m.memberToken;
    const saved = await request(ctx1.port, 'POST', `/api/members/${memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-3' },
      { 'X-Member-Token': memberToken });
    assert.equal(saved.status, 200);
  } finally { stopServer(ctx1); }

  // Boot #2: SAME DATA_DIR, fresh in-memory session store.
  // Encryption key persists in data/server.key on disk, so decryption still works.
  const port2 = 3600 + Math.floor(Math.random() * 400);
  const child2 = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DATA_DIR: ctx1.dataDir, PORT: String(port2) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child2.stdout.on('data', () => {}); child2.stderr.on('data', () => {});
  try {
    // Wait for boot.
    const deadline = Date.now() + 4000;
    let ready = false;
    while (Date.now() < deadline) {
      try { const r = await fetch(`http://127.0.0.1:${port2}/`); if (r.status === 200) { ready = true; break; } } catch {}
      await new Promise(r => setTimeout(r, 100));
    }
    assert.ok(ready, 'second server instance should boot');

    // Member session store is in-memory — it's empty after restart, so we can't refresh yet.
    // Log the member in again; the login re-hydrates the session from the encrypted DB.
    const reLogin = await request(port2, 'POST', '/api/members/login',
      { email: 'test.qa@example.com', password: 'Test1234$' });
    assert.equal(reLogin.status, 200, 'member should be able to log in after restart');
    const p = await probe(port2, reLogin.json.sessionToken);
    assert.equal(p.status, 200);
    assert.equal(p.json.hasAioToken, true, 'AIO token must survive server restart');
  } finally {
    try { child2.kill(); } catch {}
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 4: Update creds WITHOUT aioToken — existing token must NOT be lost
// (This is the merge logic I added — the subtle path most at risk.)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 4: PATCH-style save (no aioToken in body) preserves existing token', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);

    // Save WITH aioToken.
    await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT', aioToken: 'aio-secret-4' },
      { 'X-Member-Token': m.memberToken });

    // Save AGAIN, this time with NO aioToken in the body (simulates the UI's Jira-only save flow).
    const saveAgain = await request(ctx.port, 'POST', `/api/members/${m.memberId}/credentials`,
      { jiraUrl: 'https://x.atlassian.net', jiraEmail: 'a@b.c', jiraToken: 'jT-new' },
      { 'X-Member-Token': m.memberToken });
    assert.equal(saveAgain.status, 200);

    // The returned session must still carry the previous aioToken.
    const p = await probe(ctx.port, saveAgain.json.sessionToken);
    assert.equal(p.json.hasAioToken, true, 'existing AIO token must survive a Jira-only save');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 5: Explicit clear (aioToken='') MUST wipe the token
// (The merge preserves only when the field is OMITTED; an empty string is a wipe.)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 5: explicit empty aioToken clears the token', async () => {
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
    const p = await probe(ctx.port, cleared.json.sessionToken);
    assert.equal(p.json.hasAioToken, false, 'explicit empty aioToken must clear the stored token');
  } finally { stopServer(ctx); }
});

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO 6: AIO import returns a structured error when token missing
// (Full AIO import can't be tested here — no real AIO endpoint. We at least
// verify the "token not configured" pre-flight, which is what the pre-fix bug
// caused to appear misleadingly.)
// ═══════════════════════════════════════════════════════════════════════════
test('Scenario 6: /api/aio/import correctly reports missing-token error', async () => {
  const ctx = await startServer();
  try {
    const m = await setupMember(ctx.port);
    // Do NOT save an AIO token.
    const imp = await request(ctx.port, 'POST', '/api/aio/import',
      { projectKey: 'NFTH', storyKey: 'NFTH-1', cases: [{ title: 't' }], dryRun: true },
      { 'X-Session-Token': m.sessionToken });
    // Expect 4xx/5xx with a specific error, not a crash.
    assert.ok(imp.status >= 400 && imp.status < 600, 'should be a client/server error');
    assert.ok(/aio.*token.*not.*configured/i.test(imp.json?.error || imp.raw), `expected token-missing error, got: ${imp.json?.error || imp.raw}`);
  } finally { stopServer(ctx); }
});
