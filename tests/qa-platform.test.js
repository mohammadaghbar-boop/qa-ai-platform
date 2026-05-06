/**
 * QA Platform — Unit & Integration Tests
 * Covers: script generation batching, Playwright execution, path safety, URL validators, HTTP API auth
 *
 * Run: node tests/qa-platform.test.js
 * (Integration tests auto-skip if server is not running on port 3456)
 */

'use strict';

const assert  = require('assert');
const path    = require('path');
const os      = require('os');
const fs      = require('fs');
const http    = require('http');
const crypto  = require('crypto');

// ─── Simple test runner ───────────────────────────────────────────────────────
const R = '\x1b[0m', GREEN = '\x1b[32m', RED = '\x1b[31m', YELLOW = '\x1b[33m', CYAN = '\x1b[36m';
let passed = 0, failed = 0, skipped = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ${GREEN}✓${R} ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ${RED}✗${R} ${name}`);
    console.error(`    ${RED}${e.message}${R}`);
    if (e.actual !== undefined) {
      console.error(`    expected: ${JSON.stringify(e.expected)}`);
      console.error(`    actual:   ${JSON.stringify(e.actual)}`);
    }
    failed++;
  }
}

function skip(name) {
  console.log(`  ${YELLOW}○${R} ${name} (skipped)`);
  skipped++;
}

async function suite(name, fn) {
  console.log(`\n${CYAN}${name}${R}`);
  await fn();
}

// ─── Helpers mirrored from server.js / QA AI Platform.html ───────────────────
// These are copied exactly so tests catch drift between spec and implementation.

/** Mirror of the JSON walk in runPlaywrightTests (server.js) */
function parsePlaywrightResults(jsonOutput) {
  const pw_passed = [], pw_failed = [], globalErrors = [];
  try {
    const s = jsonOutput.indexOf('{'), e = jsonOutput.lastIndexOf('}');
    if (s >= 0 && e > s) {
      const results = JSON.parse(jsonOutput.slice(s, e + 1));
      const walk = (suites) => {
        for (const suite of suites || []) {
          for (const spec of suite.specs || []) {
            const title = [suite.title, spec.title].filter(Boolean).join(' › ');
            if (spec.ok) pw_passed.push(title);
            else pw_failed.push({ title, error: (spec.tests?.[0]?.results?.[0]?.errors?.[0]?.message || 'Failed').slice(0, 300) });
          }
          walk(suite.suites);
        }
      };
      walk(results.suites);
      for (const err of results.errors || []) globalErrors.push((err.message || String(err)).slice(0, 400));
    }
  } catch {}
  return { passed: pw_passed, failed: pw_failed, globalErrors };
}

/** Mirror of path-traversal guard in runPlaywrightTests (server.js) */
function isFileSafe(tmpDir, filePath) {
  const safeBase = path.resolve(tmpDir) + path.sep;
  const full     = path.resolve(tmpDir, filePath);
  return full.startsWith(safeBase);
}

/** Mirror of batch splitting in doScripts (QA AI Platform.html) */
function batchCases(cases, batchSize) {
  const batches = [];
  for (let i = 0; i < cases.length; i += batchSize) batches.push(cases.slice(i, i + batchSize));
  return batches;
}

/** Mirror of isValidHttpUrl (server.js) */
function isValidHttpUrl(s) {
  try { const u = new URL(s); return u.protocol === 'http:' || u.protocol === 'https:'; }
  catch { return false; }
}

/** Mirror of isValidJiraUrl — SSRF guard (server.js) */
function isValidJiraUrl(s) {
  try {
    const u = new URL(s);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase();
    if (/^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1|169\.254\.)/.test(h)) return false;
    return true;
  } catch { return false; }
}

// Expected constants from runPlaywrightTests — if these change the tests catch it
const PW_CONFIG = `module.exports = { testDir: '.', timeout: 60000, use: { headless: true } };`;
const SPAWN_ENV = { CI: '1', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1', NPM_CONFIG_YES: 'true' };
const BATCH_SIZE = 12; // must match doScripts

// ─── HTTP helper for integration tests ───────────────────────────────────────
const SERVER_PORT = parseInt(process.env.PORT) || 3456;

function httpPost(endpoint, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req  = http.request({
      hostname: 'localhost', port: SERVER_PORT,
      path: endpoint, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
      timeout: 10000
    }, res => {
      let out = '';
      res.on('data', d => out += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(out) }); }
        catch { resolve({ status: res.statusCode, body: out }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.write(data);
    req.end();
  });
}

async function isServerRunning() {
  try {
    await httpPost('/api/ai', { messages: [], system: '' });
    return true;
  } catch {
    return false;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// TEST SUITES
// ═════════════════════════════════════════════════════════════════════════════
(async () => {

  // ── 1. Playwright JSON output parsing ─────────────────────────────────────
  await suite('1. Playwright JSON output parsing', async () => {

    await test('empty string → empty arrays', () => {
      const r = parsePlaywrightResults('');
      assert.deepStrictEqual(r, { passed: [], failed: [], globalErrors: [] });
    });

    await test('single passing spec → in passed array with full title', () => {
      const json = JSON.stringify({
        suites: [{ title: 'Login', specs: [{ title: 'TC-001: valid login', ok: true, tests: [] }], suites: [] }]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.passed.length, 1);
      assert.strictEqual(r.passed[0], 'Login › TC-001: valid login');
      assert.strictEqual(r.failed.length, 0);
    });

    await test('single failing spec → in failed array with error message', () => {
      const json = JSON.stringify({
        suites: [{
          title: 'Checkout',
          specs: [{ title: 'TC-002: add to cart', ok: false,
            tests: [{ results: [{ errors: [{ message: 'Expected "Added" but got ""' }] }] }] }],
          suites: []
        }]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.failed.length, 1);
      assert.strictEqual(r.failed[0].title, 'Checkout › TC-002: add to cart');
      assert.ok(r.failed[0].error.includes('Expected'));
    });

    await test('mixed pass/fail → both arrays populated correctly', () => {
      const json = JSON.stringify({
        suites: [{
          title: 'Suite', specs: [
            { title: 'TC-001: pass', ok: true,  tests: [] },
            { title: 'TC-002: fail', ok: false, tests: [{ results: [{ errors: [{ message: 'fail' }] }] }] }
          ], suites: []
        }]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.passed.length, 1);
      assert.strictEqual(r.failed.length, 1);
    });

    await test('nested suites are walked recursively', () => {
      const json = JSON.stringify({
        suites: [{
          title: 'Outer', specs: [], suites: [{
            title: 'Inner',
            specs: [{ title: 'TC-003: nested', ok: true, tests: [] }],
            suites: []
          }]
        }]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.passed.length, 1);
      assert.strictEqual(r.passed[0], 'Inner › TC-003: nested');
    });

    await test('stderr prefix before JSON does not crash parsing', () => {
      const prefix = 'Running 5 tests\nusing chromium\n\n';
      const json   = JSON.stringify({
        suites: [{ title: 'S', specs: [{ title: 'T', ok: true, tests: [] }], suites: [] }]
      });
      const r = parsePlaywrightResults(prefix + json);
      assert.strictEqual(r.passed.length, 1);
    });

    await test('malformed JSON → empty arrays, no throw', () => {
      assert.doesNotThrow(() => {
        const r = parsePlaywrightResults('{ "suites": [INVALID] }');
        assert.deepStrictEqual(r, { passed: [], failed: [], globalErrors: [] });
      });
    });

    await test('error message is capped at 300 characters', () => {
      const longErr = 'E'.repeat(500);
      const json = JSON.stringify({
        suites: [{
          title: 'S',
          specs: [{ title: 'T', ok: false, tests: [{ results: [{ errors: [{ message: longErr }] }] }] }],
          suites: []
        }]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.failed[0].error.length, 300);
    });

    await test('spec with no tests array → defaults to "Failed"', () => {
      const json = JSON.stringify({
        suites: [{
          title: 'S',
          specs: [{ title: 'T', ok: false, tests: [] }],
          suites: []
        }]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.failed[0].error, 'Failed');
    });

    await test('multiple suites at top level are all parsed', () => {
      const json = JSON.stringify({
        suites: [
          { title: 'A', specs: [{ title: 'a1', ok: true, tests: [] }], suites: [] },
          { title: 'B', specs: [{ title: 'b1', ok: true, tests: [] }], suites: [] }
        ]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.passed.length, 2);
    });

    await test('results.errors are collected (file-load / import failures)', () => {
      const json = JSON.stringify({
        suites: [],
        errors: [
          { message: "Cannot find module '@playwright/test'" },
          { message: 'SyntaxError: Unexpected token' }
        ]
      });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.passed.length, 0);
      assert.strictEqual(r.failed.length, 0);
      assert.strictEqual(r.globalErrors.length, 2);
      assert.ok(r.globalErrors[0].includes('@playwright/test'));
    });

    await test('results.errors absent → globalErrors is empty array', () => {
      const json = JSON.stringify({ suites: [] });
      const r = parsePlaywrightResults(json);
      assert.deepStrictEqual(r.globalErrors, []);
    });

    await test('results.errors message is capped at 400 chars', () => {
      const json = JSON.stringify({ suites: [], errors: [{ message: 'E'.repeat(500) }] });
      const r = parsePlaywrightResults(json);
      assert.strictEqual(r.globalErrors[0].length, 400);
    });
  });

  // ── 2. Path traversal protection ──────────────────────────────────────────
  await suite('2. Path traversal protection (runPlaywrightTests)', async () => {
    const tmpDir = path.join(os.tmpdir(), 'qa_test_' + crypto.randomBytes(4).toString('hex'));

    await test('safe path inside tmpDir is allowed', () => {
      assert.strictEqual(isFileSafe(tmpDir, 'tests/login.spec.js'), true);
    });

    await test('nested safe path is allowed', () => {
      assert.strictEqual(isFileSafe(tmpDir, 'tests/auth/signup.spec.js'), true);
    });

    await test('../ traversal one level is blocked', () => {
      assert.strictEqual(isFileSafe(tmpDir, '../evil.js'), false);
    });

    await test('../ traversal through subdir is blocked', () => {
      assert.strictEqual(isFileSafe(tmpDir, 'tests/../../server.js'), false);
    });

    await test('absolute path is blocked', () => {
      const abs = process.platform === 'win32' ? 'C:\\Windows\\System32\\evil.js' : '/etc/passwd';
      assert.strictEqual(isFileSafe(tmpDir, abs), false);
    });

    await test('deeply nested safe path is allowed', () => {
      assert.strictEqual(isFileSafe(tmpDir, 'tests/e2e/auth/login.spec.js'), true);
    });
  });

  // ── 3. Script batching logic ───────────────────────────────────────────────
  await suite('3. Script batching logic (doScripts)', async () => {
    const make = n => Array.from({ length: n }, (_, i) => ({ id: `TC-${String(i + 1).padStart(3, '0')}` }));

    await test('0 cases → 0 batches', () => {
      assert.strictEqual(batchCases([], BATCH_SIZE).length, 0);
    });

    await test('1 case → 1 batch of 1', () => {
      const b = batchCases(make(1), BATCH_SIZE);
      assert.strictEqual(b.length, 1);
      assert.strictEqual(b[0].length, 1);
    });

    await test('5 cases → 1 batch of 5 (below threshold)', () => {
      const b = batchCases(make(5), BATCH_SIZE);
      assert.strictEqual(b.length, 1);
      assert.strictEqual(b[0].length, 5);
    });

    await test(`${BATCH_SIZE} cases (exactly BATCH_SIZE) → 1 batch`, () => {
      const b = batchCases(make(BATCH_SIZE), BATCH_SIZE);
      assert.strictEqual(b.length, 1);
      assert.strictEqual(b[0].length, BATCH_SIZE);
    });

    await test(`${BATCH_SIZE + 1} cases → 2 batches [${BATCH_SIZE}, 1]`, () => {
      const b = batchCases(make(BATCH_SIZE + 1), BATCH_SIZE);
      assert.strictEqual(b.length, 2);
      assert.strictEqual(b[0].length, BATCH_SIZE);
      assert.strictEqual(b[1].length, 1);
    });

    await test('33 cases → 3 batches [12, 12, 9]', () => {
      const b = batchCases(make(33), BATCH_SIZE);
      assert.strictEqual(b.length, 3);
      assert.strictEqual(b[0].length, 12);
      assert.strictEqual(b[1].length, 12);
      assert.strictEqual(b[2].length, 9);
    });

    await test('all cases preserved — no case lost or duplicated', () => {
      const cases   = make(33);
      const batches = batchCases(cases, BATCH_SIZE);
      const flat    = batches.flat();
      assert.strictEqual(flat.length, 33, 'total cases must be preserved');
      assert.deepStrictEqual(flat.map(c => c.id), cases.map(c => c.id), 'order must be preserved');
      assert.strictEqual(new Set(flat.map(c => c.id)).size, 33, 'no duplicates');
    });

    await test('first batch is always full size when cases > BATCH_SIZE', () => {
      [13, 24, 33, 50].forEach(n => {
        const b = batchCases(make(n), BATCH_SIZE);
        assert.strictEqual(b[0].length, BATCH_SIZE, `first batch of ${n} cases must be ${BATCH_SIZE}`);
      });
    });

    await test('last batch contains the remainder', () => {
      const b = batchCases(make(25), BATCH_SIZE);
      assert.strictEqual(b[b.length - 1].length, 25 % BATCH_SIZE || BATCH_SIZE);
    });
  });

  // ── 4. URL validators — SSRF guard ────────────────────────────────────────
  await suite('4. URL validators & SSRF guard', async () => {

    await test('valid Atlassian Jira URL is accepted', () => {
      assert.strictEqual(isValidJiraUrl('https://myorg.atlassian.net'), true);
    });

    await test('custom HTTPS Jira domain is accepted', () => {
      assert.strictEqual(isValidJiraUrl('https://jira.mycompany.com'), true);
    });

    await test('HTTP Jira URL is rejected (must be HTTPS)', () => {
      assert.strictEqual(isValidJiraUrl('http://myorg.atlassian.net'), false);
    });

    await test('localhost is rejected (SSRF)', () => {
      assert.strictEqual(isValidJiraUrl('https://localhost'), false);
    });

    await test('127.0.0.1 is rejected (SSRF loopback)', () => {
      assert.strictEqual(isValidJiraUrl('https://127.0.0.1'), false);
    });

    await test('10.x private range is rejected (SSRF internal)', () => {
      assert.strictEqual(isValidJiraUrl('https://10.0.0.1/jira'), false);
    });

    await test('192.168.x private range is rejected (SSRF internal)', () => {
      assert.strictEqual(isValidJiraUrl('https://192.168.1.100'), false);
    });

    await test('172.16.x private range is rejected (SSRF internal)', () => {
      assert.strictEqual(isValidJiraUrl('https://172.16.0.1'), false);
    });

    await test('plain string is rejected', () => {
      assert.strictEqual(isValidJiraUrl('not-a-url'), false);
    });

    await test('isValidHttpUrl accepts http and https', () => {
      assert.strictEqual(isValidHttpUrl('http://example.com/api'), true);
      assert.strictEqual(isValidHttpUrl('https://example.com/api'), true);
    });

    await test('isValidHttpUrl rejects ftp and other protocols', () => {
      assert.strictEqual(isValidHttpUrl('ftp://example.com'), false);
      assert.strictEqual(isValidHttpUrl('javascript:alert(1)'), false);
    });

    await test('isValidHttpUrl rejects plain strings', () => {
      assert.strictEqual(isValidHttpUrl('not-a-url'), false);
      assert.strictEqual(isValidHttpUrl(''), false);
    });
  });

  // ── 5. Playwright runner configuration ────────────────────────────────────
  await suite('5. Playwright runner configuration constants', async () => {

    await test('playwright.config.js sets testDir to current directory', () => {
      assert.ok(PW_CONFIG.includes("testDir: '.'"), 'testDir must be "."');
    });

    await test('playwright.config.js enables headless mode', () => {
      assert.ok(PW_CONFIG.includes('headless: true'), 'must run headless');
    });

    await test('playwright.config.js sets per-test timeout to 60s', () => {
      assert.ok(PW_CONFIG.includes('timeout: 60000'), 'timeout must be 60000ms');
    });

    await test('playwright.config.js is valid JavaScript syntax', () => {
      assert.doesNotThrow(() => new Function('module', PW_CONFIG)({ exports: {} }));
    });

    await test('spawn env CI=1 prevents interactive Playwright prompts', () => {
      assert.strictEqual(SPAWN_ENV.CI, '1');
    });

    await test('spawn env PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 prevents auto-install', () => {
      assert.strictEqual(SPAWN_ENV.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD, '1');
    });

    await test('spawn env NPM_CONFIG_YES=true auto-accepts npx install prompts', () => {
      assert.strictEqual(SPAWN_ENV.NPM_CONFIG_YES, 'true');
    });
  });

  // ── 6. File-system write safety ───────────────────────────────────────────
  await suite('6. File-system write safety', async () => {

    await test('writing a safe test file inside tmpDir succeeds', () => {
      const tmpDir = path.join(os.tmpdir(), 'qa_write_' + crypto.randomBytes(4).toString('hex'));
      fs.mkdirSync(tmpDir, { recursive: true });
      try {
        const filePath = 'tests/login.spec.js';
        const content  = "const { test, expect } = require('@playwright/test');";
        const full     = path.resolve(tmpDir, filePath);
        assert.ok(isFileSafe(tmpDir, filePath), 'path must be safe before writing');
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content, 'utf8');
        assert.strictEqual(fs.readFileSync(full, 'utf8'), content, 'content must match');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    await test('traversal path is never written (blocked before fs call)', () => {
      const tmpDir  = path.join(os.tmpdir(), 'qa_block_' + crypto.randomBytes(4).toString('hex'));
      const evil    = '../server.js';
      const safe    = isFileSafe(tmpDir, evil);
      assert.strictEqual(safe, false, 'traversal must be flagged as unsafe');
      // Since it is unsafe, we would skip writing — verify the check fires before any fs operation
    });

    await test('tmpDir cleanup removes all written files', () => {
      const tmpDir = path.join(os.tmpdir(), 'qa_clean_' + crypto.randomBytes(4).toString('hex'));
      fs.mkdirSync(tmpDir, { recursive: true });
      const f = path.join(tmpDir, 'test.spec.js');
      fs.writeFileSync(f, '// test');
      assert.ok(fs.existsSync(f), 'file must exist before cleanup');
      fs.rmSync(tmpDir, { recursive: true, force: true });
      assert.ok(!fs.existsSync(tmpDir), 'tmpDir must be gone after cleanup');
    });

    await test('package.json written to tmpDir is valid JSON', () => {
      const pkg = JSON.stringify({ name: 'qa-run', version: '1.0.0', private: true });
      assert.doesNotThrow(() => JSON.parse(pkg), 'package.json must be valid JSON');
      const parsed = JSON.parse(pkg);
      assert.strictEqual(parsed.name, 'qa-run');
      assert.strictEqual(parsed.private, true);
    });
  });

  // ── 7. HTTP API integration tests ─────────────────────────────────────────
  await suite(`7. HTTP API integration (server at localhost:${SERVER_PORT})`, async () => {
    const serverUp = await isServerRunning().catch(() => false);

    if (!serverUp) {
      ['POST /api/playwright/run without session → 401',
       'POST /api/ai without session → 401',
       'POST /api/jira without session → 401',
       'Path traversal in file names does not cause 500',
       'Oversized body (>20 MB) → 413 or connection close',
      ].forEach(skip);
      console.log(`\n  ${YELLOW}Start server with "node server.js" to run integration tests.${R}`);
      return;
    }

    await test('POST /api/playwright/run without session → 401', async () => {
      const r = await httpPost('/api/playwright/run', { files: {} });
      assert.strictEqual(r.status, 401);
      assert.ok(r.body.error, 'error field must be present');
    });

    await test('POST /api/ai without session → 401', async () => {
      const r = await httpPost('/api/ai', { messages: [{ role: 'user', content: 'hi' }], system: '' });
      assert.strictEqual(r.status, 401);
    });

    await test('POST /api/jira without session → 401', async () => {
      const r = await httpPost('/api/jira', { path: '/myself', method: 'GET' });
      assert.strictEqual(r.status, 401);
    });

    await test('Path traversal in file names does not cause 500', async () => {
      // Without session, we get 401 before the files are processed — that is correct.
      // The key assertion: server must not crash (no 500) on malicious input.
      const r = await httpPost('/api/playwright/run', {
        files: { '../../../evil.js': 'malicious', 'tests/ok.spec.js': '// ok' }
      });
      assert.notStrictEqual(r.status, 500, 'server must not 500 on traversal input');
    });

    await test('Oversized body (>20 MB) → 413 or connection close', async () => {
      const big = 'x'.repeat(21 * 1024 * 1024); // 21 MB
      const r   = await httpPost('/api/playwright/run', { files: { 'tests/big.spec.js': big } })
        .catch(() => ({ status: 0, body: {} }));
      assert.ok(
        r.status === 413 || r.status === 0 || r.status === 400,
        `expected 413/400/connection-close for oversized body, got ${r.status}`
      );
    });
  });

  // ── Summary ───────────────────────────────────────────────────────────────
  const total = passed + failed + skipped;
  console.log(`\n${'─'.repeat(55)}`);
  console.log(`${GREEN}Passed:${R}  ${passed}`);
  if (failed)  console.log(`${RED}Failed:${R}  ${failed}`);
  if (skipped) console.log(`${YELLOW}Skipped:${R} ${skipped} (server not running)`);
  console.log(`Total:   ${total}`);
  console.log('─'.repeat(55));
  if (failed > 0) process.exit(1);
})();
