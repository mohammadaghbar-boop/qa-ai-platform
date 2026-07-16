// Unit tests for the AIO importer's pure helpers.
// Run: node --test tests/aio.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { aioResolvePriority, aioTitleKey, aioBuildSteps, aioBuildCasePayload } = require('../server.js');

test('aioResolvePriority: known aliases', () => {
  assert.equal(aioResolvePriority('High'), 'High');
  assert.equal(aioResolvePriority(' high '), 'High');
  assert.equal(aioResolvePriority('HIGHEST'), 'Critical');
  assert.equal(aioResolvePriority('critical'), 'Critical');
  assert.equal(aioResolvePriority('med'), 'Medium');
  assert.equal(aioResolvePriority('normal'), 'Medium');
  assert.equal(aioResolvePriority('low'), 'Low');
  assert.equal(aioResolvePriority('lowest'), 'Lowest');
});

test('aioResolvePriority: unknown / empty → Medium default', () => {
  assert.equal(aioResolvePriority(''), 'Medium');
  assert.equal(aioResolvePriority(null), 'Medium');
  assert.equal(aioResolvePriority(undefined), 'Medium');
  assert.equal(aioResolvePriority('Blocker'), 'Medium');
});

test('aioTitleKey: case + whitespace collapsed', () => {
  assert.equal(aioTitleKey('Verify Login'), 'verify login');
  assert.equal(aioTitleKey('  Verify   Login  '), 'verify login');
  assert.equal(aioTitleKey('Verify\tLogin\nFlow'), 'verify login flow');
  assert.equal(aioTitleKey(''), '');
  assert.equal(aioTitleKey(null), '');
});

test('aioBuildSteps: empty steps → single placeholder', () => {
  const out = aioBuildSteps({ steps: [], testData: 'x=1', expected: 'ok' });
  assert.equal(out.length, 1);
  assert.equal(out[0].stepType, 'TEXT');
  assert.equal(out[0].step, '');
  assert.equal(out[0].data, 'x=1');
  assert.equal(out[0].expectedResult, 'ok');
});

test('aioBuildSteps: per-step arrays aligned by index', () => {
  const out = aioBuildSteps({
    steps: ['login', 'submit'],
    stepData: ['user/pass', ''],
    stepResults: ['welcome page', 'confirmation'],
  });
  assert.deepEqual(out, [
    { stepType: 'TEXT', step: 'login',  data: 'user/pass', expectedResult: 'welcome page' },
    { stepType: 'TEXT', step: 'submit', data: '',          expectedResult: 'confirmation' }
  ]);
});

test('aioBuildSteps: missing stepResults → tail case.expected on last step only', () => {
  const out = aioBuildSteps({ steps: ['a', 'b', 'c'], expected: 'FINAL' });
  assert.equal(out[0].expectedResult, '');
  assert.equal(out[1].expectedResult, '');
  assert.equal(out[2].expectedResult, 'FINAL');
});

test('aioBuildSteps: gracefully handles non-array fields', () => {
  const out = aioBuildSteps({ steps: 'not-an-array', expected: 'x' });
  assert.equal(out.length, 1);
  assert.equal(out[0].expectedResult, 'x');
});

test('aioBuildCasePayload: known priority → { ID }', () => {
  const p = aioBuildCasePayload({ title: 't', priority: 'High' }, { high: 42 }, null, null);
  assert.deepEqual(p.priority, { ID: 42 });
  assert.equal(p.title, 't');
  assert.equal(p.precondition, null);
});

test('aioBuildCasePayload: unknown priority → { name } fallback', () => {
  const p = aioBuildCasePayload({ title: 't', priority: 'Weird' }, { high: 42 }, null, null);
  assert.deepEqual(p.priority, { name: 'Medium' });
});

test('aioBuildCasePayload: folder + requirement injected only when provided', () => {
  const noExtras = aioBuildCasePayload({ title: 't' }, {}, null, null);
  assert.equal(noExtras.folder, undefined);
  assert.equal(noExtras.folderID, undefined);
  assert.equal(noExtras.jiraRequirementIDs, undefined);

  const withExtras = aioBuildCasePayload({ title: 't' }, {}, 7, 12345);
  assert.deepEqual(withExtras.folder, { ID: 7 });
  assert.equal(withExtras.folderID, 7);
  assert.deepEqual(withExtras.jiraRequirementIDs, [12345]);
});

test('aioBuildCasePayload: preserves preconditions and trims title', () => {
  const p = aioBuildCasePayload({ title: '  Verify login  ', preconditions: 'user exists' }, {}, null, null);
  assert.equal(p.title, 'Verify login');
  assert.equal(p.precondition, 'user exists');
});

test('aioBuildCasePayload: null/undefined-safe on completely empty case', () => {
  const p = aioBuildCasePayload({}, null, null, null);
  assert.equal(p.title, '');
  assert.equal(p.precondition, null);
  assert.deepEqual(p.priority, { name: 'Medium' });
  assert.equal(p.steps.length, 1);
});
