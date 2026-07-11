// Shared pure helpers used by BOTH the browser (loaded before the React block)
// and the Node unit tests. Keep this file dependency-free and side-effect-free.
//
// Browser: exposes `window.QaLib`.
// Node:    module.exports = QaLib.
(function (root, factory) {
  var lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else root.QaLib = lib;
}(typeof self !== 'undefined' ? self : this, function () {
  // ── Test-case NATURE (the "type" field) ───────────────────────────────
  var NATURES = ['happy', 'edge', 'negative', 'boundary', 'regression'];

  // Normalize the AI's nature tag to a supported value.
  //   - "positive" is a common synonym → "happy".
  //   - Case-insensitive.
  //   - Unknown values fall back to `fallback` (default "happy").
  function normType(t, fallback) {
    var v = String(t == null ? '' : t).toLowerCase();
    if (v === 'positive') return 'happy';
    if (NATURES.indexOf(v) !== -1) return v;
    return fallback || 'happy';
  }

  // ── Test-case LAYER (the "layer" field) ───────────────────────────────
  var LAYERS = ['Functional', 'UI', 'API', 'Database', 'Security'];

  // Normalize the AI's layer/category tag to a supported value.
  //   - Case-insensitive match, canonical capitalization returned.
  //   - Unknown values fall back to "Functional".
  function normLayer(x) {
    var v = String(x == null ? '' : x).trim().toLowerCase();
    for (var i = 0; i < LAYERS.length; i++) {
      if (LAYERS[i].toLowerCase() === v) return LAYERS[i];
    }
    return 'Functional';
  }

  // ── Step schema normalization ─────────────────────────────────────────
  // The AI schema now returns steps as [{stepNumber, action, testData, expectedResult}].
  // Downstream code (renderer, Playwright/Appium script gen, AIO Excel export,
  // AIO REST import) expects the older flat shape:
  //   steps:        string[]  ("Step 1", "Step 2", …)
  //   stepResults:  string[]  (per-step expected)
  //   stepData:     string[]  (per-step data)
  //   testData:     string    (combined, backwards-compat single-field)
  //
  // This function converts step-objects to the flat shape while leaving
  // already-flat cases untouched. Never throws — returns the case as-is
  // when steps is missing or malformed.
  function normalizeSteps(c) {
    if (!c || !Array.isArray(c.steps)) return c;
    if (c.steps.length === 0) return c;
    if (typeof c.steps[0] === 'string') return c; // already flat
    var stepStrings = c.steps.map(function (s) { return (s && s.action) || ''; });
    var stepResults = c.steps.map(function (s) { return (s && s.expectedResult) || ''; });
    var stepDataArr = c.steps.map(function (s) { return (s && s.testData) || ''; });
    var combinedData = c.testData || stepDataArr.filter(Boolean).join(' | ') || '';
    var out = {};
    for (var k in c) if (Object.prototype.hasOwnProperty.call(c, k)) out[k] = c[k];
    out.steps = stepStrings;
    out.stepResults = stepResults;
    out.stepData = stepDataArr;
    out.testData = combinedData;
    return out;
  }

  // ── AIO Tests export mapping ──────────────────────────────────────────
  // Map platform layer → AIO Tests "Type" field value. AIO's built-in type
  // vocabulary has API and Security as first-class values; every other
  // functional layer is imported as "Integration".
  function aioType(layer) {
    if (layer === 'API') return 'API';
    if (layer === 'Security') return 'Security';
    return 'Integration';
  }

  // Map platform approval status → AIO status label.
  function aioStatus(status) {
    return status === 'approved' ? 'Ready for Testing' : 'Draft';
  }

  return {
    NATURES: NATURES,
    LAYERS: LAYERS,
    normType: normType,
    normLayer: normLayer,
    normalizeSteps: normalizeSteps,
    aioType: aioType,
    aioStatus: aioStatus
  };
}));
