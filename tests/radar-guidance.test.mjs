import assert from 'node:assert/strict';
import { createServer } from 'vite';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const vite = await createServer({ server: { middlewareMode: true }, appType: 'custom' });
try {
  const { radarGuidance, RADAR_URL } = await vite.ssrLoadModule('/src/lib/radarGuidance.ts');
  const cases = [
    [{ verdict: 'SAFE', risk_score: 0, coverage: 'complete' }, 'educational'],
    [{ verdict: 'SAFE', risk_score: 49, coverage: 'complete' }, 'educational'],
    [{ verdict: 'SAFE', risk_score: 50, coverage: 'complete' }, 'attention'],
    [{ verdict: 'DANGEROUS', coverage: 'complete' }, 'attention'],
    [{ verdict: 'SUSPICIOUS', risk_score: 10, coverage: 'complete' }, 'attention'],
    [{ verdict: 'INCONCLUSIVE', risk_score: 0, coverage: 'partial' }, 'limited'],
    [{ verdict: 'SAFE', risk_score: 0, coverage: 'partial' }, 'limited'],
    [{ verdict: 'SAFE', coverage: 'complete', confidence_score: 100 }, 'educational'],
  ];
  for (const [input, expected] of cases) {
    const guidance = radarGuidance(input);
    assert.equal(guidance.variant, expected);
    assert.ok(guidance.title && guidance.description);
  }
  const address = new URL(RADAR_URL);
  assert.equal(address.origin, 'https://radar-de-golpes-hub.xadoondias.workers.dev');
  assert.equal(address.search, '');
  assert.equal(address.hash, '#categorias');
  const { default: App, RadarAfterScan } = await vite.ssrLoadModule('/src/App.tsx');
  for (const [input] of cases) {
    const html = renderToStaticMarkup(React.createElement(RadarAfterScan, { result: { ...input, target: 'https://privado.example/?token=segredo' } }));
    assert.ok(html.includes('data-testid="radar-after-scan"'));
    assert.ok(html.includes(RADAR_URL));
    assert.ok(html.includes('referrerPolicy="no-referrer"'));
    assert.ok(!html.includes('privado.example') && !html.includes('segredo'));
  }
  const markup = renderToStaticMarkup(React.createElement(App));
  assert.ok(!markup.includes('data-testid="radar-after-scan"'), 'No result guidance before an analysis');
  console.log('Radar guidance: all results, threshold, incomplete coverage and static private destination passed.');
} finally { await vite.close(); }
