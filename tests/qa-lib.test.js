// Unit tests for the shared browser/Node helper library used in generation
// normalization, layer classification, and AIO export mapping.
// Run: node --test tests/qa-lib.test.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const QaLib = require('../public/qa-lib.js');

// ── normType ───────────────────────────────────────────────────────────
test('normType: canonical values pass through', () => {
  ['happy', 'edge', 'negative', 'boundary', 'regression'].forEach(v => {
    assert.equal(QaLib.normType(v), v);
  });
});

test('normType: case-insensitive', () => {
  assert.equal(QaLib.normType('HAPPY'),   'happy');
  assert.equal(QaLib.normType('Edge'),    'edge');
  assert.equal(QaLib.normType('Boundary'),'boundary');
});

test('normType: "positive" is a synonym for "happy"', () => {
  assert.equal(QaLib.normType('positive'), 'happy');
  assert.equal(QaLib.normType('POSITIVE'), 'happy');
});

test('normType: unknown value falls back (default "happy")', () => {
  assert.equal(QaLib.normType('nonsense'), 'happy');
  assert.equal(QaLib.normType(''), 'happy');
  assert.equal(QaLib.normType(null), 'happy');
  assert.equal(QaLib.normType(undefined), 'happy');
});

test('normType: explicit fallback wins for unknown values', () => {
  assert.equal(QaLib.normType('nonsense', 'edge'), 'edge');
  assert.equal(QaLib.normType('', 'negative'), 'negative');
});

test('normType: explicit fallback is IGNORED for canonical values', () => {
  // Real AI output wins over the caller's default.
  assert.equal(QaLib.normType('boundary', 'edge'), 'boundary');
});

// ── normLayer ──────────────────────────────────────────────────────────
test('normLayer: canonical values pass through with correct casing', () => {
  ['Functional', 'UI', 'API', 'Database', 'Security'].forEach(v => {
    assert.equal(QaLib.normLayer(v), v);
  });
});

test('normLayer: case-insensitive, returns canonical case', () => {
  assert.equal(QaLib.normLayer('functional'), 'Functional');
  assert.equal(QaLib.normLayer('ui'),         'UI');
  assert.equal(QaLib.normLayer('database'),   'Database');
  assert.equal(QaLib.normLayer('SECURITY'),   'Security');
});

test('normLayer: unknown value falls back to Functional', () => {
  assert.equal(QaLib.normLayer('Performance'), 'Functional');
  assert.equal(QaLib.normLayer(''), 'Functional');
  assert.equal(QaLib.normLayer(null), 'Functional');
  assert.equal(QaLib.normLayer(undefined), 'Functional');
});

test('normLayer: trims surrounding whitespace', () => {
  assert.equal(QaLib.normLayer('  UI  '), 'UI');
});

// ── normalizeSteps ─────────────────────────────────────────────────────
test('normalizeSteps: already-flat case is returned untouched', () => {
  const c = { title: 'x', steps: ['s1', 's2'], stepResults: ['r1', 'r2'] };
  const out = QaLib.normalizeSteps(c);
  assert.equal(out, c); // same reference — no rebuild
});

test('normalizeSteps: converts step-object schema to flat arrays', () => {
  const c = {
    title: 'x',
    steps: [
      { stepNumber: 1, action: 'open',   testData: 'url=a', expectedResult: 'page loads' },
      { stepNumber: 2, action: 'submit', testData: '',      expectedResult: 'saved' }
    ]
  };
  const out = QaLib.normalizeSteps(c);
  assert.deepEqual(out.steps,       ['open', 'submit']);
  assert.deepEqual(out.stepResults, ['page loads', 'saved']);
  assert.deepEqual(out.stepData,    ['url=a', '']);
});

test('normalizeSteps: combines per-step data into single testData field', () => {
  const c = { steps: [{ action: 'a', testData: 'x=1' }, { action: 'b', testData: 'y=2' }] };
  const out = QaLib.normalizeSteps(c);
  assert.equal(out.testData, 'x=1 | y=2'); // pipe-separated combined field
});

test('normalizeSteps: prefers case.testData when caller already set it', () => {
  const c = { testData: 'preset', steps: [{ action: 'a', testData: 'x' }] };
  const out = QaLib.normalizeSteps(c);
  assert.equal(out.testData, 'preset');
});

test('normalizeSteps: empty-step-array case returned unchanged', () => {
  const c = { title: 'x', steps: [] };
  const out = QaLib.normalizeSteps(c);
  assert.equal(out, c);
});

test('normalizeSteps: null-safe when steps is missing or not an array', () => {
  const c1 = {};
  assert.equal(QaLib.normalizeSteps(c1), c1); // no steps → returned as-is
  const c2 = { steps: 'not-an-array' };
  assert.equal(QaLib.normalizeSteps(c2), c2);
});

test('normalizeSteps: does not lose other case fields', () => {
  const c = {
    id: 'TC-001', title: 't', suite: 'Auth', type: 'happy', layer: 'UI',
    steps: [{ action: 'a', testData: '', expectedResult: 'r' }]
  };
  const out = QaLib.normalizeSteps(c);
  assert.equal(out.id, 'TC-001');
  assert.equal(out.suite, 'Auth');
  assert.equal(out.type, 'happy');
  assert.equal(out.layer, 'UI');
});

// ── AIO export mapping ─────────────────────────────────────────────────
test('aioType: nature takes priority over layer', () => {
  assert.equal(QaLib.aioType('Functional', 'regression'), 'Regression');
  assert.equal(QaLib.aioType('API',        'negative'),   'Negative');
  assert.equal(QaLib.aioType('Database',   'boundary'),   'Negative');
  assert.equal(QaLib.aioType('Functional', 'happy'),      'Functional');
  assert.equal(QaLib.aioType('Functional', 'edge'),       'Functional');
});

test('aioType: layer refines when nature is neutral', () => {
  assert.equal(QaLib.aioType('Security', 'happy'),     'Security');
  assert.equal(QaLib.aioType('UI',       'edge'),      'UI');
  assert.equal(QaLib.aioType('API',      'happy'),     'Functional');
  assert.equal(QaLib.aioType('Database', 'happy'),     'Functional');
  assert.equal(QaLib.aioType('Functional','happy'),    'Functional');
});

test('aioType: unknown / missing → Functional', () => {
  assert.equal(QaLib.aioType('',        ''),     'Functional');
  assert.equal(QaLib.aioType(null,      null),   'Functional');
  assert.equal(QaLib.aioType('Unknown', 'edge'), 'Functional');
});

test('aioStatus: approved → Ready for Testing; anything else → Draft', () => {
  assert.equal(QaLib.aioStatus('approved'), 'Ready for Testing');
  assert.equal(QaLib.aioStatus('pending'),  'Draft');
  assert.equal(QaLib.aioStatus(''),         'Draft');
  assert.equal(QaLib.aioStatus(null),       'Draft');
});
