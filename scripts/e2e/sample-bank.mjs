#!/usr/bin/env node
// Whole-page check on the sample bank (samples/server.mjs): Hook ON -> every feature -> Send to Burp, then every
// request and response the browser actually exchanged (CDP Network = what Burp sees) goes through the crypto
// server like the Decrypted tab. Catches what single-feature coverage cases can't: several endpoints sharing a
// location with different keys, decrypts recorded after their response (worker), stale-profile shadowing.
//   node scripts/e2e/sample-bank.mjs        (CHROME=<path> to pick the browser)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, findChrome, panelModules, sleep } from './harness.mjs';
import { createSampleServer } from '../../samples/server.mjs';
import { createEngine } from '../../server/src/engine.mjs';

// path -> what Burp's Decrypted view must show (request / response); null = stays ciphertext by design
const EXPECT = {
  '/api/login': { req: /"pw":\s*"Demo!2026pw"/, res: /welcome minjun\.kim/ },
  '/api/transfer': { req: /ct-keep:/, res: null, why: 'fresh AES key per request (needs the L4 oracle)' },
  '/api/profile': { req: /"email":\s*"minjun\.kim@/, res: /profile saved for/ },
  '/api/pin': { req: /encPin=ct-keep/, res: null, why: 'RSA public key only: re-encrypt, no plaintext' },
  '/api/inquiry': { req: /"title":\s*"이체 한도 변경 문의"/, res: /inquiry received/ },
  '/api/card/pin': { req: null, res: null, why: 'SEED: needs the trace step' },
};

const chrome = findChrome();
if (!chrome) { console.error('Chrome not found (set CHROME=<path>)'); process.exit(2); }
const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-bank-keys-'));
const server = createSampleServer({ keyDir });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const b = await launchChrome(chrome);
let failures = 0;
try {
  const tab = await b.open(`http://127.0.0.1:${port}/`, { settle: 1500 });
  const reqs = [];
  await b.cdp('Network.enable', {}, tab.s);
  tab.listeners.push((m) => {
    if (m.method === 'Network.requestWillBeSent' && /\/api\//.test(m.params.request.url) && m.params.request.method === 'POST') {
      const r = m.params.request;
      reqs.push({ id: m.params.requestId, url: r.url, headers: Object.entries(r.headers), body: r.postData || '' });
    }
  });
  for (const id of ['a-go', 'b-go', 'c-go', 'd-go', 'e-go', 'f-go']) {
    await tab.evaluate(`document.getElementById('${id}').click()`);
    await sleep(900);
  }
  await sleep(800);

  const mods = panelModules();
  const seen = [];
  for (const r of tab.records) {
    if (r.lib === 'origin') continue;
    if (r.lib === 'transport') mods.correlate(r, seen);
    else if (r.op === 'decrypt') mods.correlateLate(r, seen);
    seen.push(r);
  }
  const { cfg } = mods.loadableConfig(mods.buildConfig(seen));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-bank-'));
  fs.writeFileSync(path.join(dir, 'c.json'), JSON.stringify(cfg));
  const eng = createEngine();
  const load = eng.handle({ op: 'load', files: [path.join(dir, 'c.json')] }).results[0];
  fs.rmSync(dir, { recursive: true, force: true });
  if (load.error) { console.log('LOAD ERROR', load.error); failures++; }
  for (const t of load.selftest || []) if (!t.ok) { console.log(`FAIL selftest ${t.cipher}: ${t.error}`); failures++; }

  for (const r of reqs) {
    const u = new URL(r.url);
    const want = EXPECT[u.pathname];
    if (!want) continue;
    const dec = eng.handle({ op: 'decryptRequest', host: u.hostname, port: Number(u.port), request: { method: 'POST', path: u.pathname, headers: r.headers, body: r.body } });
    const reqView = dec.request ? dec.request.body : '';
    let resView = '';
    try {
      const rb = await b.cdp('Network.getResponseBody', { requestId: r.id }, tab.s);
      const dr = eng.handle({ op: 'decryptResponse', host: u.hostname, port: Number(u.port), path: u.pathname, response: { status: 200, headers: [], body: rb.body } });
      resView = dr.response ? String(dr.response.body) : '';
    } catch (_) { /* no body */ }
    const check = (label, re, view) => {
      if (!re) return `${label}: (by design)`;
      if (re.test(view)) return `${label}: ok`;
      failures++;
      return `${label}: FAIL -> ${view.replace(/\s+/g, ' ').slice(0, 80)}`;
    };
    console.log(`${u.pathname.padEnd(16)} ${check('request', want.req, reqView)} | ${check('response', want.res, resView)}${want.why ? '  [' + want.why + ']' : ''}`);
  }
  await tab.close();
} finally {
  await b.close();
  server.close();
  fs.rmSync(keyDir, { recursive: true, force: true });
}
console.log(failures ? `sample-bank: ${failures} FAILED` : 'sample-bank: PASS');
process.exit(failures ? 1 : 0);
