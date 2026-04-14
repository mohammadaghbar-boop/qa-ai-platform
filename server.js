// QA AI Platform — Local Proxy (Claude AI + Jira)
// Run with: node server.js
// Keep this terminal open while using the app.

const http  = require('http');
const https = require('https');
const { spawn } = require('child_process');

const PORT = 3456;

/* ── Claude AI ──────────────────────────────────────────────────────────── */
function callClaude(messages, system) {
  return new Promise((resolve, reject) => {
    const conversation = messages.map(m =>
      (m.role === 'user' ? 'Human' : 'Assistant') + ': ' + m.content
    ).join('\n\n');

    const fullPrompt = system
      ? `[System: ${system}]\n\n${conversation}`
      : conversation;

    const proc = spawn('claude', ['-p', '--output-format', 'text'], {
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

    res.writeHead(404); res.end();
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  QA AI Platform proxy is running');
  console.log('  AI   → http://localhost:' + PORT + '/api/ai');
  console.log('  Jira → http://localhost:' + PORT + '/api/jira');
  console.log('');
  console.log('  Keep this terminal open while using the app.');
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});
