/**
 * server.test.js
 *
 * Unit tests for security-critical helper functions in server.js.
 * Uses only Node.js built-ins (assert + fs + path + os) — no external framework needed.
 *
 * Run with:  node server.test.js
 *
 * The functions under test are inlined here because server.js is not structured
 * as a CommonJS module (it starts the HTTP server on require).  All function
 * bodies below are copied verbatim from server.js so the tests reflect the exact
 * live implementation.
 *
 * FINDINGS COVERED
 * ────────────────
 * F1  checkRateLimit  — rate-limit guard is dead code (return true on L80)
 * F2  loadServerDB    — parse errors are silently swallowed; next save clobbers data
 * F3  isValidHttpUrl  — screenshot endpoint SSRF: only checks protocol, not private IPs
 *     isValidJiraUrl  — Jira proxy SSRF: correctly blocks private IPs
 * F4  issueKey        — /api/jira/attach accepts any string as issueKey (no format check)
 */

'use strict';

const assert = require('assert');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

// ─── Inlined functions (verbatim from server.js) ──────────────────────────────

// server.js L79–86  (fixed — return true removed)
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  let e = loginAttempts.get(ip);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + 15 * 60 * 1000 };
  e.count++;
  loginAttempts.set(ip, e);
  return e.count <= 10; // 10 attempts per 15 min
}

// server.js L100–101
function isValidHttpUrl(s) {
  try { const u = new URL(s); return u.protocol === 'http:' || u.protocol === 'https:'; } catch { return false; }
}

// server.js L104–112
function isValidJiraUrl(s) {
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|169\.254\.)/.test(h)) return false;
    return true;
  } catch { return false; }
}

// server.js L170–178  (DATA_FILE substituted with a temp path per test)
function loadServerDB(dataFile) {
  if (!fs.existsSync(dataFile)) return { sessions: [], bugs: [], perfResults: [], coverage: [], members: [], adminPasswordHash: null, adminPasswordIsDefault: true };
  try { return JSON.parse(fs.readFileSync(dataFile, 'utf8')); }
  catch (e) {
    const backup = dataFile + '.corrupt.' + Date.now();
    try { fs.copyFileSync(dataFile, backup); } catch {}
    console.error('[DB] Corrupt database file — backed up to', backup, '— starting fresh:', e.message);
    return { sessions: [], bugs: [], perfResults: [], coverage: [], members: [], adminPasswordHash: null, adminPasswordIsDefault: true };
  }
}

// server.js L174–178  (DATA_FILE substituted with a temp path per test)
function saveServerDB(db, dataFile) {
  const tmp = dataFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, dataFile);
}

// server.js L94–95
function sanitizeFilename(name) {
  return String(name || 'file').replace(/[^\w.\-]/g, '_').slice(0, 100);
}

// ─── Tiny test harness ────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log('  PASS  ' + name);
    passed++;
  } catch (err) {
    console.error('  FAIL  ' + name);
    console.error('        ' + err.message);
    failed++;
    failures.push({ name, message: err.message });
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log('  PASS  ' + name);
    passed++;
  } catch (err) {
    console.error('  FAIL  ' + name);
    console.error('        ' + err.message);
    failed++;
    failures.push({ name, message: err.message });
  }
}

// ─── Suite 1: checkRateLimit ──────────────────────────────────────────────────
// FINDING F1: The function has `return true` as its first statement, making all
// brute-force protection dead code.  Every call returns true regardless of the
// number of attempts from the same IP.  An attacker can call /api/login
// unlimited times with no throttling.

console.log('\n[Suite 1] checkRateLimit — rate limit guard (F1)');

test('returns true on first attempt', () => {
  assert.strictEqual(checkRateLimit('1.2.3.4'), true);
});

test('returns true on attempts 1–10 from same IP (within window)', () => {
  for (let i = 0; i < 9; i++) checkRateLimit('5.5.5.5');
  assert.strictEqual(checkRateLimit('5.5.5.5'), true); // 10th attempt — still allowed
});

test('returns false on 11th attempt from same IP within the window (brute-force blocked)', () => {
  // Fresh IP — loginAttempts map uses a shared instance per process; use unique IP
  const ip = '44.44.44.44';
  for (let i = 0; i < 10; i++) checkRateLimit(ip);
  assert.strictEqual(checkRateLimit(ip), false, '11th attempt should be blocked');
});

test('different IPs are rate-limited independently', () => {
  // Exhaust limit for one IP, other IPs should still be allowed
  const blocked = '55.55.55.55';
  const clean   = '66.66.66.66';
  for (let i = 0; i < 11; i++) checkRateLimit(blocked);
  assert.strictEqual(checkRateLimit(blocked), false, 'blocked IP is throttled');
  assert.strictEqual(checkRateLimit(clean),   true,  'clean IP still allowed');
});

test('returns true after rate-limit window resets', () => {
  // Simulate an expired window by injecting a past resetAt
  const ip = '77.77.77.77';
  loginAttempts.set(ip, { count: 11, resetAt: Date.now() - 1 }); // already expired
  assert.strictEqual(checkRateLimit(ip), true, 'first call after reset should be allowed');
});

// ─── Suite 2: isValidHttpUrl vs isValidJiraUrl — SSRF gap ────────────────────
// FINDING F3: The screenshot endpoint (/api/ui-design/screenshot) only calls
// isValidHttpUrl(), which accepts any http/https URL including private IPs.
// isValidJiraUrl() (used for the Jira proxy) additionally blocks RFC-1918 and
// loopback addresses.  An authenticated member can screenshot internal services
// such as http://192.168.1.1/admin or http://169.254.169.254/latest/meta-data/
// (AWS IMDS endpoint).

console.log('\n[Suite 2] isValidHttpUrl vs isValidJiraUrl SSRF gap (F3)');

// 2a  isValidHttpUrl — protocol checks only
test('isValidHttpUrl accepts http scheme', () => {
  assert.strictEqual(isValidHttpUrl('http://example.com'), true);
});

test('isValidHttpUrl accepts https scheme', () => {
  assert.strictEqual(isValidHttpUrl('https://example.com'), true);
});

test('isValidHttpUrl rejects non-http scheme (ftp)', () => {
  assert.strictEqual(isValidHttpUrl('ftp://example.com'), false);
});

test('isValidHttpUrl rejects non-http scheme (file)', () => {
  assert.strictEqual(isValidHttpUrl('file:///etc/passwd'), false);
});

// 2b  isValidHttpUrl SSRF vectors — these all PASS (return true), which is the bug
test('isValidHttpUrl ALLOWS localhost (SSRF vector — BUG)', () => {
  // isValidHttpUrl does NOT block internal addresses.
  // An authenticated user can trigger a screenshot of http://localhost:3456
  // exposing the internal API over the network.
  assert.strictEqual(isValidHttpUrl('http://localhost/admin'), true,
    'isValidHttpUrl incorrectly allows localhost — SSRF possible on screenshot endpoint');
});

test('isValidHttpUrl ALLOWS 127.0.0.1 (SSRF vector — BUG)', () => {
  assert.strictEqual(isValidHttpUrl('http://127.0.0.1/'), true,
    'isValidHttpUrl incorrectly allows loopback — SSRF possible on screenshot endpoint');
});

test('isValidHttpUrl ALLOWS 192.168.1.1 RFC-1918 (SSRF vector — BUG)', () => {
  assert.strictEqual(isValidHttpUrl('http://192.168.1.1/'), true,
    'isValidHttpUrl incorrectly allows RFC-1918 address');
});

test('isValidHttpUrl ALLOWS 10.0.0.1 RFC-1918 (SSRF vector — BUG)', () => {
  assert.strictEqual(isValidHttpUrl('http://10.0.0.1/'), true,
    'isValidHttpUrl incorrectly allows RFC-1918 address');
});

test('isValidHttpUrl ALLOWS 172.16.0.1 RFC-1918 (SSRF vector — BUG)', () => {
  assert.strictEqual(isValidHttpUrl('http://172.16.0.1/'), true,
    'isValidHttpUrl incorrectly allows RFC-1918 address');
});

test('isValidHttpUrl ALLOWS 169.254.169.254 AWS IMDS (SSRF vector — BUG)', () => {
  // AWS metadata service — leaks IAM credentials if reached from a cloud host
  assert.strictEqual(isValidHttpUrl('http://169.254.169.254/latest/meta-data/iam/security-credentials/'), true,
    'isValidHttpUrl incorrectly allows link-local address — cloud credential theft possible');
});

// 2c  isValidJiraUrl — correctly blocks all the same addresses
test('isValidJiraUrl rejects localhost', () => {
  assert.strictEqual(isValidJiraUrl('https://localhost/'), false);
});

test('isValidJiraUrl rejects 127.0.0.1', () => {
  assert.strictEqual(isValidJiraUrl('https://127.0.0.1/'), false);
});

test('isValidJiraUrl rejects 192.168.1.1', () => {
  assert.strictEqual(isValidJiraUrl('https://192.168.1.1/'), false);
});

test('isValidJiraUrl rejects 10.0.0.1', () => {
  assert.strictEqual(isValidJiraUrl('https://10.0.0.1/'), false);
});

test('isValidJiraUrl rejects 172.16.0.1', () => {
  assert.strictEqual(isValidJiraUrl('https://172.16.0.1/'), false);
});

test('isValidJiraUrl rejects 172.31.255.255 (upper RFC-1918)', () => {
  assert.strictEqual(isValidJiraUrl('https://172.31.255.255/'), false);
});

test('isValidJiraUrl accepts valid public Jira URL', () => {
  assert.strictEqual(isValidJiraUrl('https://myteam.atlassian.net'), true);
});

test('isValidJiraUrl rejects http (non-HTTPS)', () => {
  assert.strictEqual(isValidJiraUrl('http://myteam.atlassian.net'), false);
});

test('isValidJiraUrl rejects 0.0.0.0', () => {
  assert.strictEqual(isValidJiraUrl('https://0.0.0.0/'), false);
});

test('isValidJiraUrl rejects 169.254.169.254 link-local', () => {
  assert.strictEqual(isValidJiraUrl('https://169.254.169.254/'), false);
});

// 2d  Gap confirmation: same URL accepted by isValidHttpUrl but rejected by isValidJiraUrl
test('SSRF gap confirmed: 192.168.1.1 accepted by isValidHttpUrl but blocked by isValidJiraUrl', () => {
  const url = 'http://192.168.1.1/';
  assert.strictEqual(isValidHttpUrl(url), true,  'isValidHttpUrl lets it through (the bug)');
  assert.strictEqual(isValidJiraUrl(url),  false, 'isValidJiraUrl correctly blocks it');
});

test('SSRF gap confirmed: 10.10.10.10 accepted by isValidHttpUrl but blocked by isValidJiraUrl', () => {
  const url = 'http://10.10.10.10/internal-api';
  assert.strictEqual(isValidHttpUrl(url), true);
  assert.strictEqual(isValidJiraUrl(url), false);
});

// ─── Suite 3: loadServerDB — silent parse-error / data-loss bug ──────────────
// FINDING F2: When the DB file contains invalid JSON (e.g. due to power loss
// during write), JSON.parse throws inside the try block, the catch swallows it
// silently, and loadServerDB returns a fresh empty DB.  The next call to
// saveServerDB() will then overwrite the corrupt-but-potentially-recoverable
// file with an empty one — all data is permanently lost with no log or alert.

console.log('\n[Suite 3] loadServerDB — parse error handling (F2)');

const TMP_DIR = os.tmpdir();

test('loadServerDB returns default structure when file does not exist', () => {
  const f = path.join(TMP_DIR, 'qa_test_nofile_' + Date.now() + '.json');
  const db = loadServerDB(f);
  assert.deepStrictEqual(db.sessions, []);
  assert.deepStrictEqual(db.bugs, []);
  assert.deepStrictEqual(db.members, []);
  assert.strictEqual(db.adminPasswordHash, null);
});

test('loadServerDB returns correct data from valid JSON file', () => {
  const f = path.join(TMP_DIR, 'qa_test_valid_' + Date.now() + '.json');
  const payload = { sessions: [{ id: 'abc' }], bugs: [], members: [{ id: 'u1', name: 'Alice' }], adminPasswordHash: 'xyz', adminPasswordIsDefault: false };
  fs.writeFileSync(f, JSON.stringify(payload));
  const db = loadServerDB(f);
  assert.strictEqual(db.sessions.length, 1);
  assert.strictEqual(db.members[0].name, 'Alice');
  assert.strictEqual(db.adminPasswordHash, 'xyz');
  fs.unlinkSync(f);
});

test('[FIXED] loadServerDB logs error and backs up corrupt file instead of swallowing silently', () => {
  const f = path.join(TMP_DIR, 'qa_test_corrupt_' + Date.now() + '.json');
  fs.writeFileSync(f, '{"sessions":[{"id":"s1","name":"Alice"}],"bugs":[{"bid":"B-1"}],"members":[{"id":"m1"}], CORRUPTED');
  const db = loadServerDB(f);
  // Returns empty defaults — original data unreadable but NOT silently lost
  assert.deepStrictEqual(db.sessions, []);
  assert.deepStrictEqual(db.bugs, []);
  // Backup file should exist alongside the corrupt original
  const backupExists = fs.readdirSync(TMP_DIR).some(n => n.startsWith(path.basename(f) + '.corrupt.'));
  assert.ok(backupExists, 'corrupt file should be backed up');
  // Cleanup
  fs.readdirSync(TMP_DIR).filter(n => n.startsWith(path.basename(f))).forEach(n => { try { fs.unlinkSync(path.join(TMP_DIR, n)); } catch {} });
});

test('[FIXED] saveServerDB after corrupt-load does not destroy the backup', () => {
  const f = path.join(TMP_DIR, 'qa_test_overwrite_' + Date.now() + '.json');
  fs.writeFileSync(f, '{"sessions":[],"bugs":[{"bid":"IMPORTANT"}],"members":[],"adminPasswordHash":null,"adminPasswordIsDefault":true CORRUPT_TAIL');
  const db = loadServerDB(f);   // backs up, returns empty
  saveServerDB(db, f);           // writes new clean DB
  const afterSave = JSON.parse(fs.readFileSync(f, 'utf8'));
  assert.deepStrictEqual(afterSave.bugs, [], 'new DB is clean');
  // The backup preserving the corrupt (but potentially recoverable) bytes exists
  const backupExists = fs.readdirSync(TMP_DIR).some(n => n.startsWith(path.basename(f) + '.corrupt.'));
  assert.ok(backupExists, 'backup of corrupt file exists for manual recovery');
  // Cleanup
  fs.readdirSync(TMP_DIR).filter(n => n.startsWith(path.basename(f))).forEach(n => { try { fs.unlinkSync(path.join(TMP_DIR, n)); } catch {} });
});

test('saveServerDB uses atomic rename (writes to .tmp then renames)', () => {
  // Verify the safe-write pattern is present: if the rename fails mid-flight the
  // original file is untouched.  This test checks the tmp file is gone afterward.
  const f = path.join(TMP_DIR, 'qa_test_atomic_' + Date.now() + '.json');
  const db = { sessions: [], bugs: [], members: [], adminPasswordHash: null, adminPasswordIsDefault: true };
  saveServerDB(db, f);
  assert.ok(fs.existsSync(f), 'final file should exist after save');
  assert.ok(!fs.existsSync(f + '.tmp'), '.tmp file should be cleaned up after rename');
  fs.unlinkSync(f);
});

test('loadServerDB round-trips data correctly through saveServerDB', () => {
  const f = path.join(TMP_DIR, 'qa_test_roundtrip_' + Date.now() + '.json');
  const original = { sessions: [{ id: 'x' }], bugs: [{ bid: 'B-1' }], members: [], adminPasswordHash: 'h', adminPasswordIsDefault: false };
  saveServerDB(original, f);
  const loaded = loadServerDB(f);
  assert.strictEqual(loaded.sessions[0].id, 'x');
  assert.strictEqual(loaded.bugs[0].bid, 'B-1');
  assert.strictEqual(loaded.adminPasswordHash, 'h');
  fs.unlinkSync(f);
});

// ─── Suite 4: issueKey input validation ──────────────────────────────────────
// FINDING F4 (/api/jira/attach): The only check for issueKey is a truthiness
// test (`if (!issueKey ...)`).  There is no regex or format validation.
// A crafted issueKey such as "../../etc/passwd" or "PROJ-1/../../sensitive" is
// accepted and spliced directly into the Jira REST URL:
//   new URL(jiraUrl + '/rest/api/3/issue/' + issueKey + '/attachments')
// If the Jira base URL is ever changed to a different backend, or if Playwright
// evaluates a rendered URL, path-traversal-style keys could reach unintended paths.
// Additionally, no check prevents excessively long or special-character keys that
// could confuse logging or downstream systems.

console.log('\n[Suite 4] issueKey format validation (F4 — missing check)');

// Helper: simulates the validation currently in /api/jira/attach (server.js L1577-1581)
function currentIssueKeyValidation(issueKey, files) {
  // EXACTLY what the server currently does — truthiness + array check only
  if (!issueKey || !Array.isArray(files) || files.length === 0) {
    return { valid: false, error: 'issueKey and files are required' };
  }
  return { valid: true };
}

// Helper: proposed stricter validation that should be added
function strictIssueKeyValidation(issueKey) {
  // Jira issue keys are PROJECT-NUMBER, e.g. "QA-123", "MYPROJECT-4567"
  return /^[A-Z][A-Z0-9]{1,9}-\d{1,6}$/.test(String(issueKey || ''));
}

test('current validation: valid Jira key passes (QA-123)', () => {
  const r = currentIssueKeyValidation('QA-123', [{ name: 'f', dataUrl: 'data:text/plain;base64,dA==' }]);
  assert.strictEqual(r.valid, true);
});

test('current validation: empty issueKey is rejected', () => {
  const r = currentIssueKeyValidation('', [{ name: 'f' }]);
  assert.strictEqual(r.valid, false);
});

test('current validation: null issueKey is rejected', () => {
  const r = currentIssueKeyValidation(null, [{ name: 'f' }]);
  assert.strictEqual(r.valid, false);
});

test('current validation: path-traversal issueKey PASSES (BUG — no format check)', () => {
  // The server would accept this and build the URL:
  // jiraUrl + '/rest/api/3/issue/../../etc/passwd/attachments'
  const r = currentIssueKeyValidation('../../etc/passwd', [{ name: 'f', dataUrl: 'data:text/plain;base64,dA==' }]);
  assert.strictEqual(r.valid, true,
    'Path-traversal issueKey incorrectly accepted — format validation is missing');
});

test('current validation: URL-encoded traversal issueKey PASSES (BUG)', () => {
  const r = currentIssueKeyValidation('%2F..%2F..%2Fetc%2Fpasswd', [{ name: 'f', dataUrl: 'data:text/plain;base64,dA==' }]);
  assert.strictEqual(r.valid, true,
    'Encoded path-traversal issueKey incorrectly accepted');
});

test('current validation: overly long issueKey (1000 chars) PASSES (BUG)', () => {
  const longKey = 'A'.repeat(1000);
  const r = currentIssueKeyValidation(longKey, [{ name: 'f', dataUrl: 'data:text/plain;base64,dA==' }]);
  assert.strictEqual(r.valid, true,
    'Excessively long issueKey incorrectly accepted');
});

test('proposed strict validation: QA-123 is valid', () => {
  assert.strictEqual(strictIssueKeyValidation('QA-123'), true);
});

test('proposed strict validation: MYPROJECT-9999 is valid', () => {
  assert.strictEqual(strictIssueKeyValidation('MYPROJECT-9999'), true);
});

test('proposed strict validation: path traversal is rejected', () => {
  assert.strictEqual(strictIssueKeyValidation('../../etc/passwd'), false);
});

test('proposed strict validation: lowercase key is rejected', () => {
  assert.strictEqual(strictIssueKeyValidation('qa-123'), false);
});

test('proposed strict validation: empty string is rejected', () => {
  assert.strictEqual(strictIssueKeyValidation(''), false);
});

test('proposed strict validation: null is rejected', () => {
  assert.strictEqual(strictIssueKeyValidation(null), false);
});

// ─── Suite 5: sanitizeFilename ────────────────────────────────────────────────
// Not a reported finding, but exercises the helper used in attachment upload.

console.log('\n[Suite 5] sanitizeFilename — upload filename sanitization');

test('sanitizeFilename allows word chars, dots, hyphens', () => {
  assert.strictEqual(sanitizeFilename('my-file.png'), 'my-file.png');
});

test('sanitizeFilename strips path separators', () => {
  // The regex [^\w.\-] removes slashes but keeps dots (dots are whitelisted).
  // '../../etc/passwd' → '......etc.passwd' — slashes gone, traversal impossible.
  const result = sanitizeFilename('../../etc/passwd');
  assert.ok(!result.includes('/'), 'forward slash should be removed');
  // Dots are kept by design; verify the output is harmless (no slash remains)
  assert.ok(result.startsWith('..'), 'dots are kept — expected behaviour for this regex');
});

test('sanitizeFilename strips backslashes', () => {
  const result = sanitizeFilename('..\\..\\windows\\system32\\cmd.exe');
  assert.ok(!result.includes('\\'), 'backslash should be removed');
});

test('sanitizeFilename caps at 100 characters', () => {
  const long = 'a'.repeat(200);
  assert.strictEqual(sanitizeFilename(long).length, 100);
});

test('sanitizeFilename returns "file" for empty input', () => {
  assert.strictEqual(sanitizeFilename(''), 'file');
});

test('sanitizeFilename returns "file" for null input', () => {
  assert.strictEqual(sanitizeFilename(null), 'file');
});

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log('\n' + '─'.repeat(60));
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailed tests:');
  failures.forEach(f => console.log('  • ' + f.name + '\n    ' + f.message));
  process.exitCode = 1;
} else {
  console.log('\nAll tests passed.');
}
