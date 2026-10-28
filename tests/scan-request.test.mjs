import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer } from 'vite';
let requests = [], failHealth = false, failScan = false, holdHealth = false;
const api = http.createServer((req, res) => {
  requests.push(req.url);
  if (req.url === '/') {
    if (holdHealth) return;
    res.writeHead(failHealth ? 503 : 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  } else { res.writeHead(failScan ? 503 : 200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ scan: { verdict: 'INCONCLUSIVE' } })); }
});
await new Promise(r => api.listen(0, '127.0.0.1', r));
const vite = await createServer({ server: { middlewareMode: true }, appType: 'custom' });
try {
  const { requestScan } = await vite.ssrLoadModule('/src/lib/scanRequest.ts');
  const base = `http://127.0.0.1:${api.address().port}/api`;
  const phases = [];
  const result = await requestScan(base, 'https://example.com', new AbortController().signal, p => phases.push(p));
  assert.equal(result.data.scan.verdict, 'INCONCLUSIVE');
  assert.deepEqual(requests, ['/', '/api/scan/url']); assert.equal(phases.length, 2);
  requests = []; failHealth = true;
  await assert.rejects(() => requestScan(base, 'https://example.com', new AbortController().signal, () => {}));
  assert.deepEqual(requests, ['/']); // URL was never submitted if readiness failed.
  failHealth = false; failScan = true; requests = [];
  await assert.rejects(() => requestScan(base, 'https://example.com', new AbortController().signal, () => {}));
  assert.deepEqual(requests, ['/', '/api/scan/url']); // Never replay a failed scan.
  requests = []; holdHealth = true;
  const controller = new AbortController();
  const pending = requestScan(base, 'https://example.com', controller.signal, () => {});
  setTimeout(() => controller.abort(), 30);
  await assert.rejects(() => pending, e => e.code === 'ERR_CANCELED');
  assert.ok(!requests.includes('/api/scan/url'));
  console.log('API readiness, error handling, no replay and cancellation passed.');
} finally { await vite.close(); api.closeAllConnections(); await new Promise(r => api.close(r)); }
