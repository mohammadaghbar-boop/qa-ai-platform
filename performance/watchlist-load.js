/**
 * Performance Test — Watchlist API
 * Endpoint: GET /auctions/api/v1/watchlist
 * Run: k6 run --env BEARER_TOKEN=<token> performance/watchlist-load.js
 * Modes:
 *   Smoke  → k6 run --env MODE=smoke   --env BEARER_TOKEN=<token> performance/watchlist-load.js
 *   Load   → k6 run --env MODE=load    --env BEARER_TOKEN=<token> performance/watchlist-load.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { htmlReport } from 'https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const errorRate      = new Rate('watchlist_error_rate');
const latencyTrend   = new Trend('watchlist_p95_ms', true);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const BASE_URL      = 'https://qa-infath-api.azm-dev.com';
const CATEGORY_ID   = '11111111-1111-1111-1111-111111111111';
const BEARER_TOKEN  = __ENV.BEARER_TOKEN || '';
const MODE          = __ENV.MODE || 'smoke';

if (!BEARER_TOKEN) {
  throw new Error('BEARER_TOKEN is required. Run with: --env BEARER_TOKEN=eyJ...');
}

const HEADERS = {
  'accept':           'application/json',
  'Authorization':    `Bearer ${BEARER_TOKEN}`,
  'TenantIdentifier': 'azm-tenant-12345',
  'Accept-Language':  'ar-SA',
};

// ---------------------------------------------------------------------------
// Load profiles
// ---------------------------------------------------------------------------
const SCENARIOS = {
  smoke: {
    executor: 'constant-vus',
    vus: 1,
    duration: '30s',
  },
  load: {
    executor: 'constant-vus',
    vus: 1,           // 1 VU — we only have 1 token
    duration: '1m',
  },
};

export const options = {
  scenarios: {
    watchlist: SCENARIOS[MODE] || SCENARIOS.smoke,
  },
  thresholds: {
    'http_req_failed':      ['rate<0.01'],   // <1% HTTP errors
    'http_req_duration':    ['p(95)<400'],   // p95 < 400ms (list endpoint standard)
    'watchlist_error_rate': ['rate<0.01'],
    'watchlist_p95_ms':     ['p(95)<400'],
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
export default function () {
  const t0  = Date.now();
  const res = http.get(
    `${BASE_URL}/auctions/api/v1/watchlist?categoryId=${CATEGORY_ID}`,
    { headers: HEADERS, tags: { endpoint: 'watchlist' } },
  );
  latencyTrend.add(Date.now() - t0);

  const ok = check(res, {
    'status is 200':          (r) => r.status === 200,
    'response time < 400ms':  (r) => r.timings.duration < 400,
    'has body':               (r) => r.body && r.body.length > 0,
  });

  errorRate.add(!ok);
  sleep(1);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
export function handleSummary(data) {
  const reportName = `performance/reports/watchlist-${MODE}-report.html`;
  return {
    [reportName]: htmlReport(data),
    'stdout':     textSummary(data, { indent: ' ', enableColors: true }),
  };
}
