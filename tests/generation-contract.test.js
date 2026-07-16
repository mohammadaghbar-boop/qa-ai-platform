// Static contract tests for the test-case generation pipeline in index.html.
// These lock in the fixes validated end-to-end against NFTH-2041:
//   - single-pass generation (no per-type parallel calls → no 4x duplication)
//   - story-scope / type-ownership / atomic-assertion prompt rules
//   - model selection actually forwarded to the server
//   - complete typeGuide (empty guides caused invented scenarios)
//   - valid model IDs and full platform options in the UI
//
// They parse index.html as text — no server, no browser, no API calls.
//
// Run: node --test tests/generation-contract.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

// ── Prompt template ──────────────────────────────────────────────────────
const tmplMatch = html.match(/content:(`You are a senior QA engineer\. Generate ONE deduplicated set[\s\S]*?testable"\}\]\}`)/);

test('generation prompt template exists (single-pass wording)', () => {
  assert.ok(tmplMatch, 'single-pass generation template must exist in index.html');
});

test('prompt contains the STORY-SCOPE RULE', () => {
  assert.match(tmplMatch[1], /STORY-SCOPE RULE \(non-negotiable\)/);
  assert.match(tmplMatch[1], /no failure-injection, no idempotency, no security logging, no provider-unavailability/);
});

test('prompt contains the TYPE OWNERSHIP RULE (anti-duplication)', () => {
  assert.match(tmplMatch[1], /TYPE OWNERSHIP RULE \(non-negotiable\)/);
  assert.match(tmplMatch[1], /appears EXACTLY ONCE/);
  assert.match(tmplMatch[1], /return ZERO cases for that type/);
});

test('prompt contains ATOMIC ASSERTIONS, NO INVENTED IMPLEMENTATION DETAILS, DD VALUE ASSERTIONS', () => {
  assert.match(tmplMatch[1], /ATOMIC ASSERTIONS/);
  assert.match(tmplMatch[1], /NO INVENTED IMPLEMENTATION DETAILS/);
  assert.match(tmplMatch[1], /DD VALUE ASSERTIONS/);
});

test('risk patterns are gated with ONLY IF conditions', () => {
  assert.match(tmplMatch[1], /EXTERNAL DEPENDENCY: ONLY IF/);
  assert.match(tmplMatch[1], /CONCURRENT OPERATIONS: ONLY IF/);
  assert.match(tmplMatch[1], /STATE-CHANGING OPERATIONS: ONLY IF/);
  assert.match(tmplMatch[1], /ONE case under ONE type/);
});

// ── typeGuide completeness ───────────────────────────────────────────────
test('typeGuide defines a non-empty guide for all five types', () => {
  const guideMatch = html.match(/const typeGuide=(\{[\s\S]*?\});/);
  assert.ok(guideMatch, 'typeGuide must exist');
  const typeGuide = eval('(' + guideMatch[1] + ')');
  for (const t of ['happy', 'edge', 'boundary', 'negative', 'regression']) {
    assert.ok(typeGuide[t] && typeGuide[t].length > 40, `typeGuide.${t} must be defined and substantive`);
  }
  assert.match(typeGuide.boundary, /generate 0 boundary cases/i, 'boundary guide must allow empty output');
});

// ── Single-pass architecture (no per-type fan-out) ───────────────────────
test('doGen makes ONE call — no per-type Promise.all over callAI', () => {
  // The old bug: Promise.all(typesNeedingAPI.map(type => callAI(...)))
  assert.ok(!/Promise\.all\(typesNeedingAPI\.map\([^)]*callAI/.test(html.replace(/\n/g, ' ')),
    'generation must not fan out one callAI per type (causes cross-type duplication)');
  assert.match(html, /Generating \$\{typesNeedingAPI\.join\(" \+ "\)\} test cases in one pass/,
    'single-pass loading message must be present');
});

test('generated cases get a default priority when the model omits it', () => {
  assert.match(html, /priority:c\.priority\|\|"Medium"/, 'priority coercion must exist in doGen parsing');
});

// ── Model selection wiring ───────────────────────────────────────────────
test('callAI accepts a model parameter and sends it in the request body', () => {
  assert.match(html, /async function callAI\(messages, sys="", max=4000, _legacy="", model=""\)/,
    'callAI must accept the model parameter');
  assert.match(html, /body: JSON\.stringify\(\{ messages, system: sys, max, model: model \|\| undefined \}\)/,
    'callAI must include model in the request body');
});

test('generation call site passes genModel through', () => {
  assert.match(html, /,SYS,12000,proj\.anthropicKey\|\|"",genModel\)/,
    'doGen must pass genModel as the model argument');
});

test('model dropdown offers only valid current model IDs', () => {
  const options = [...html.matchAll(/<option value="(claude-[^"]+)">/g)].map(m => m[1]);
  assert.ok(options.length >= 3, 'model dropdown must exist with at least 3 options');
  const valid = new Set(['claude-sonnet-5', 'claude-opus-4-8', 'claude-haiku-4-5-20251001']);
  for (const o of options) assert.ok(valid.has(o), `model id "${o}" must be a valid current API model id`);
});

test('default genModel state is a valid model id', () => {
  assert.match(html, /useState\("claude-sonnet-5"\)/, 'genModel default must be claude-sonnet-5');
});

// ── UI options ───────────────────────────────────────────────────────────
test('all six test-case type options are present', () => {
  for (const label of ['Happy flow', 'Edge cases', 'Boundary cases', 'Negative cases', 'Regression cases', 'All of the above']) {
    assert.ok(html.includes(`l:"${label}"`), `type option "${label}" must exist`);
  }
  assert.ok(html.includes('["happy","edge","boundary","negative","regression"]'),
    '"all" must expand to the five concrete types');
});

test('admin platform dropdown offers web, mobile, and both', () => {
  assert.match(html, /<option value="web">Web<\/option><option value="mobile">Mobile<\/option><option value="both">Web \+ Mobile<\/option>/,
    'platform select must include Web, Mobile, and Web + Mobile');
});

// ── Remember-Me token durability (fixes "Could not create test session") ────
test('auth tokens are mirrored to localStorage and rehydrated on load', () => {
  // Login must persist the member token via the helper (mirrors to localStorage in remember mode)
  assert.match(html, /persistMemberToken\(d\.token,remember\)/,
    'member login must persist token through persistMemberToken');
  // A rehydrate step must copy the localStorage mirror back into sessionStorage on load
  assert.match(html, /_hydrateAuthTokens/,
    'a token rehydration step must exist so reopened sessions can mint API sessions');
  assert.match(html, /function persistSessionToken/,
    'persistSessionToken helper must exist');
  // Session refresh must persist through the helper (not raw sessionStorage.setItem)
  assert.ok(!/if \(d\.sessionToken\) \{ sessionStorage\.setItem\(SESSION_TOKEN_KEY, d\.sessionToken\); return d\.sessionToken; \}/.test(html),
    '_refreshSession must persist via persistSessionToken, not raw sessionStorage.setItem');
});

test('logout clears auth tokens from both storages', () => {
  assert.match(html, /function clearAuthTokens/, 'clearAuthTokens helper must exist');
  assert.match(html, /clearAuthTokens\(\)/, 'logout must call clearAuthTokens');
  // clearAuthTokens must remove from BOTH localStorage and sessionStorage
  const fn = html.match(/function clearAuthTokens\(\)\s*\{[\s\S]*?\n\}/);
  assert.ok(fn, 'clearAuthTokens body must be found');
  assert.match(fn[0], /localStorage\.removeItem\(MEMBER_TOKEN_KEY\)/);
  assert.match(fn[0], /localStorage\.removeItem\(SESSION_TOKEN_KEY\)/);
});

// ── "New story" / start-over must always be available (fixes "can't undo") ──
test('New story button is not gated behind hasSaved', () => {
  const btn = html.match(/<button onClick=\{startNewStory\}[^>]*>↩ New story<\/button>/);
  assert.ok(btn, 'New story button must use the startNewStory handler');
  // The old gating ("Save first to enable" / disabled unless hasSaved) must be gone
  assert.ok(!/↩ New story/.test(html) || !/Save first to enable/.test(html),
    'New story must no longer show "Save first to enable" gating');
  assert.match(html, /const startNewStory=\(\)=>\{/, 'startNewStory handler must exist');
  // It must confirm before discarding unsaved work
  const fn = html.match(/const startNewStory=\(\)=>\{[\s\S]*?\n  \};/);
  assert.ok(fn, 'startNewStory body must be found');
  assert.match(fn[0], /window\.confirm/, 'startNewStory must confirm before discarding unsaved work');
});

// ── Saved-story search must match by name AND key (sid) ──────────────────────
test('saved-story search matches both name and sid (not name-only)', () => {
  // The old bug: filter used (s.name||s.sid) which short-circuits on name, so
  // searching by Jira key never matched stories that have a name.
  assert.ok(!/\(s\.name\|\|s\.sid\|\|""\)\.toLowerCase\(\)\.includes/.test(html),
    'search must not use the name-only-fallback filter');
  const line = html.match(/const visibleStories=_sq\?projFiltered\.filter\([^\n]*\)/);
  assert.ok(line, 'search filter must build a haystack from multiple fields');
  assert.match(line[0], /s\.name/, 'search must include name');
  assert.match(line[0], /s\.sid/, 'search must include sid (Jira key)');
});
