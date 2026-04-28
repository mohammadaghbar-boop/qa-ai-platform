// QA AI Platform — Local Proxy (Claude AI + Jira)
// Run with: node server.js
// Keep this terminal open while using the app.

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const os    = require('os');
const path  = require('path');
const { spawn } = require('child_process');

const PORT = 3456;

// Empty MCP config — prevents claude CLI from using MCP tools (e.g. Atlassian)
const EMPTY_MCP = path.join(os.tmpdir(), 'qa-platform-no-mcp.json');
fs.writeFileSync(EMPTY_MCP, JSON.stringify({ mcpServers: {} }));

/* ── Claude AI ──────────────────────────────────────────────────────────── */
function callClaude(messages, system) {
  return new Promise((resolve, reject) => {
    const conversation = messages.map(m =>
      (m.role === 'user' ? 'Human' : 'Assistant') + ': ' + m.content
    ).join('\n\n');

    const fullPrompt = system
      ? `[System: ${system}]\n\n${conversation}`
      : conversation;

    const proc = spawn('claude', [
      '-p', '--output-format', 'text',
      '--tools', '',
      '--strict-mcp-config', '--mcp-config', EMPTY_MCP
    ], {
      shell: true,
      env: process.env
    });

    let output = '', error = '';
    proc.stdin.write(fullPrompt);
    proc.stdin.end();
    proc.stdout.on('data', d => output += d.toString());
    proc.stderr.on('data', d => error  += d.toString());
    proc.on('close', code => {
      if (code === 0 && output.trim()) resolve(output.trim());
      else reject(new Error(error.trim() || 'claude CLI returned no output (exit ' + code + ')'));
    });
    proc.on('error', err => reject(new Error('Could not start claude CLI: ' + err.message)));
  });
}

/* ── Jira Proxy ─────────────────────────────────────────────────────────── */
function proxyJira(jiraUrl, path, method, auth, body) {
  return new Promise((resolve, reject) => {
    const url    = new URL(jiraUrl + '/rest/api/3' + path);
    const opts   = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   method,
      headers:  {
        'Authorization': 'Basic ' + auth,
        'Content-Type':  'application/json',
        'Accept':        'application/json'
      }
    };

    const req = https.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error('Jira ' + res.statusCode + ': ' + data.slice(0, 120)));
        } else {
          try { resolve(JSON.parse(data)); }
          catch { resolve(data); }
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

/* ── Performance Test (k6) ─────────────────────────────────────────────── */
function generateK6Script({ testType, method, apiUrl, vus, duration, ramp, p95Threshold, authType, token, basicUsername, basicPassword, requestBody, expectedStatus }) {
  const m    = (method || 'GET').toLowerCase();
  const vusN = parseInt(vus) || 100;
  const p95N = parseInt(p95Threshold) || 2000;
  const exp  = parseInt(expectedStatus) || 200;

  const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (authType === 'bearer' && token)
    headers['Authorization'] = 'Bearer ' + token;
  if (authType === 'basic' && basicUsername)
    headers['Authorization'] = 'Basic ' + Buffer.from(basicUsername + ':' + (basicPassword || '')).toString('base64');

  const bodyArg = ['post', 'put', 'patch'].includes(m) && requestBody
    ? ', `' + (requestBody || '').replace(/`/g, '\\`') + '`'
    : '';

  let stages;
  if (testType === 'stress') {
    const s25 = Math.ceil(vusN * 0.25), s50 = Math.ceil(vusN * 0.5), s75 = Math.ceil(vusN * 0.75);
    stages = `[{duration:'${ramp}',target:${s25}},{duration:'${duration}',target:${s25}},{duration:'${ramp}',target:${s50}},{duration:'${duration}',target:${s50}},{duration:'${ramp}',target:${s75}},{duration:'${duration}',target:${s75}},{duration:'${ramp}',target:${vusN}},{duration:'${duration}',target:${vusN}},{duration:'${ramp}',target:0}]`;
  } else {
    stages = `[{duration:'${ramp}',target:${vusN}},{duration:'${duration}',target:${vusN}},{duration:'${ramp}',target:0}]`;
  }

  return `import http from 'k6/http';
import { check, sleep } from 'k6';
export let options = {
  stages: ${stages},
  thresholds: { 'http_req_duration': ['p(95)<${p95N}'], 'http_req_failed': ['rate<0.05'] }
};
export default function () {
  const res = http.${m}('${apiUrl}'${bodyArg}, { headers: ${JSON.stringify(headers)} });
  check(res, { 'status ${exp}': r => r.status === ${exp} });
  sleep(1);
}`;
}

function runK6(scriptPath) {
  return new Promise((resolve, reject) => {
    const summaryPath = scriptPath + '.summary.json';
    const proc = spawn('k6', ['run', '--summary-export', summaryPath, '--no-color', scriptPath], { shell: true });
    let stderr = '';
    proc.stderr.on('data', d => stderr += d.toString());
    proc.on('close', code => {
      try {
        if (!fs.existsSync(summaryPath))
          throw new Error(stderr.slice(0, 300) || 'k6 produced no output (exit ' + code + ')');
        const sum = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
        try { fs.unlinkSync(summaryPath); } catch {}
        const dur  = sum.metrics?.http_req_duration?.values || {};
        const req  = sum.metrics?.http_reqs?.values         || {};
        const fail = sum.metrics?.http_req_failed?.values   || {};
        resolve({
          passed: code === 0,
          metrics: {
            totalRequests: Math.round(req.count  || 0),
            rps:           parseFloat((req.rate  || 0).toFixed(2)),
            avgDuration:   parseFloat((dur.avg   || 0).toFixed(2)),
            minDuration:   parseFloat((dur.min   || 0).toFixed(2)),
            maxDuration:   parseFloat((dur.max   || 0).toFixed(2)),
            p50:           parseFloat((dur['p(50)'] || 0).toFixed(2)),
            p90:           parseFloat((dur['p(90)'] || 0).toFixed(2)),
            p95:           parseFloat((dur['p(95)'] || 0).toFixed(2)),
            p99:           parseFloat((dur['p(99)'] || 0).toFixed(2)),
            errorRate:     parseFloat(((fail.rate || 0) * 100).toFixed(2))
          }
        });
      } catch (e) { reject(new Error(e.message)); }
    });
    proc.on('error', e => reject(new Error(
      e.code === 'ENOENT'
        ? 'k6 is not installed. Install it from https://k6.io/docs/get-started/installation/'
        : 'Failed to start k6: ' + e.message
    )));
  });
}

/* ── HTTP Server ────────────────────────────────────────────────────────── */
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    /* ── /api/ai ── */
    if (req.method === 'POST' && req.url === '/api/ai') {
      try {
        const { messages, system } = JSON.parse(body);
        console.log('[AI]   Request —', (messages.at(-1)?.content || '').slice(0, 80) + '…');
        const text = await callClaude(messages, system);
        console.log('[AI]   Done    —', text.slice(0, 60) + '…');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ text }));
      } catch (e) {
        console.error('[AI]   Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/jira ── */
    if (req.method === 'POST' && req.url === '/api/jira') {
      try {
        const { jiraUrl, path, method, auth, body: jiraBody } = JSON.parse(body);
        console.log('[Jira] Request —', method, path);
        const data = await proxyJira(jiraUrl, path, method, auth, jiraBody);
        console.log('[Jira] Done');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      } catch (e) {
        console.error('[Jira] Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    /* ── /api/perf ── */
    if (req.method === 'POST' && req.url === '/api/perf') {
      try {
        const params    = JSON.parse(body);
        const tmpScript = path.join(os.tmpdir(), 'qa_k6_' + Date.now() + '.js');
        fs.writeFileSync(tmpScript, generateK6Script(params));
        console.log('[Perf] Running k6 —', params.testName);
        const result = await runK6(tmpScript);
        try { fs.unlinkSync(tmpScript); } catch {}
        console.log('[Perf] Done — passed:', result.passed);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        console.error('[Perf] Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    res.writeHead(404); res.end();
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  QA AI Platform proxy is running');
  console.log('  AI   → http://localhost:' + PORT + '/api/ai');
  console.log('  Jira → http://localhost:' + PORT + '/api/jira');
  console.log('  Perf → http://localhost:' + PORT + '/api/perf');
  console.log('');
  console.log('  Keep this terminal open while using the app.');
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});
