#!/usr/bin/env node
// Coverage run: every case in samples/coverage/cases.mjs through the panel's full pipeline in headless Chrome
// -- hooks, constant scan, unknown-ciphertext back-trace, tracing when needed, config build, crypto-server
// load -- then the request the target actually received is decrypted, edited, re-encrypted and sent back.
// Prints an expected-vs-measured table and writes it to output/coverage-report.md (and docs/COVERAGE.md
// with --docs). Offline: 127.0.0.1 only.
//   node scripts/coverage.mjs [--only id,id] [--docs]       (CHROME=<path> to pick the browser)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchChrome, findChrome, panelModules, sleep } from './e2e/harness.mjs';
import { createCoverageServer } from '../samples/coverage/server.mjs';
import { CASES, RANK } from '../samples/coverage/cases.mjs';
import { createEngine } from '../server/src/engine.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const only = argv.includes('--only') ? String(argv[argv.indexOf('--only') + 1] || '').split(',').filter(Boolean) : [];
const writeDocs = argv.includes('--docs');
const verbose = argv.includes('--verbose');

const chromePath = findChrome();
if (!chromePath) { console.error('Chrome not found (set CHROME=<path>)'); process.exit(2); }
const server = createCoverageServer();
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const base = `http://127.0.0.1:${port}`;
const getJSON = async (p) => (await fetch(base + p)).json();

function replay(mods, records) {
  const seen = [];
  const unknown = [];
  for (const r of records) {
    if (r.lib === 'origin') { if (!mods.isExplained(r, seen)) unknown.push(r); continue; }
    if (r.lib === 'transport') mods.correlate(r, seen);
    else if (r.op === 'decrypt') mods.correlateLate(r, seen);
    seen.push(r);
  }
  return { seen, unknown };
}

async function runCase(browser, c) {
  const id = c.id;
  const api = `/cov/${id}/api`;
  const P = (n) => `{"t":"cov-${id}-${n}"}`;
  const mods = panelModules();
  const tab = await browser.open(`${base}/cov/${id}`);
  const tracer = mods.CryptoTraceTracer.createTracer({ cdp: (m, p, t) => browser.cdp(m, p, t), emit: (r, t) => { r.__session = t; tab.records.push(r); }, keyOf: (t) => t,
    scriptsOf: (t) => tab.parsed.filter((p) => (p.__session || tab.s) === t) });
  tab.listeners.push((m) => { if (m.method === 'Debugger.paused') tracer.onPaused(m.sessionId, m.params); }); // page or worker session
  const tracedSessions = new Set();
  const out = { id, group: c.group, title: c.title, expect: c.expect, notes: [] };
  try {
    for (let i = 0; i < 30 && !(await tab.evaluate('window.__ready === true')); i++) await sleep(100);
    await tab.evaluate(`window.__run(${JSON.stringify(P(1))})`);
    await sleep(500);
    const first = await getJSON(`/cov/${id}/last`);
    if (!first || !first.accepted) { out.status = 'page-broken'; out.notes.push('target rejected the page\'s own request: ' + (first && first.error)); return out; }

    // what the panel would show after the first run
    const r1 = replay(mods, tab.records);
    out.scan = [];
    for (const p of tab.parsed) {
      if (p.url && !p.url.startsWith(base)) continue; // ours + eval scripts (no URL); not extensions
      try {
        const { scriptSource } = await browser.cdp('Debugger.getScriptSource', { scriptId: p.scriptId }, p.__session || tab.s);
        for (const f of mods.CryptoTraceScan.scanSource(scriptSource, mods.signatures)) if (f.strength === 'strong' && !out.scan.includes(f.algo)) out.scan.push(f.algo);
      } catch (_) {}
    }
    const unk = r1.unknown.filter((u) => u.url && u.url.includes(api));
    if (unk.length) {
      const target = unk[0].__session || tab.s; // trace in the realm (page or worker) that built the value
      tracedSessions.add(target);
      const armed = await tracer.traceFrames(target, tracer.pickFrames(unk[0].frames));
      out.notes.push('traced: ' + armed.join(' / '));
    }
    await tab.evaluate(`window.__run(${JSON.stringify(P(2))})`);
    await sleep(800);
    for (const t of tracedSessions) await tracer.stop(t).catch(() => {});

    // config as Send to Burp builds it, loaded by the crypto server
    const { seen, unknown } = replay(mods, tab.records);
    const draft = mods.buildConfig(seen);
    const { cfg, skipped } = mods.loadableConfig(draft);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-cov-'));
    fs.writeFileSync(path.join(dir, 'c.json'), JSON.stringify(cfg));
    const eng = createEngine();
    const load = eng.handle({ op: 'load', files: [path.join(dir, 'c.json')] }).results[0];
    fs.rmSync(dir, { recursive: true, force: true });
    if (load.error) out.notes.push('load error: ' + load.error);
    for (const t of load.selftest || []) if (!t.ok) out.notes.push(`selftest ${t.cipher}: ${t.error}`);
    if (load.identified && load.identified.length) out.notes.push('identified: ' + load.identified.map((x) => `${x.alg}/${x.padding}`).join(', '));
    for (const s of skipped) out.notes.push('skipped: ' + s);
    const rules = [...cfg.apply.request].map((r) => `${r.in}:${r.path || r.name || ''}`);
    if (verbose) {
      console.log(`--- ${id} records:`, seen.filter((r) => r.lib !== 'transport').map((r) => `${r.lib}.${r.op}${r.fn ? '(' + r.fn + ')' : ''}${r.apply ? ' ->' + r.apply.in + ':' + (r.apply.path || r.apply.name || '') : ''}`).join(', '));
      console.log(`--- ${id} transport:`, JSON.stringify(seen.filter((r) => r.lib === 'transport').map((r) => [r.op, r.url, r.headers && r.headers.length, r.body && r.body.kind])));
      console.log(`--- ${id} config:`, JSON.stringify({ ciphers: cfg.ciphers, apply: cfg.apply, integrity: cfg.integrity }).slice(0, 1500));
    }
    out.rules = rules;

    // the request the target received -> Burp's Decrypted view -> edit -> re-encrypt -> target
    const raw = await getJSON(`/cov/${id}/last`);
    const req = { method: raw.method, path: raw.path, headers: raw.headers.map(([k, v]) => [k, String(v)]), body: raw.body };
    const dec = load.error ? null : eng.handle({ op: 'decryptRequest', host: '127.0.0.1', port, request: req });
    const view = dec && dec.request
      ? `${dec.request.path || ''}\n${dec.request.headers.map(([k, v]) => k + ': ' + v).join('\n')}\n${dec.request.body}` : '';
    const times = (hay, needle) => String(hay).split(needle).length - 1;
    const need = c.markers || 1;
    const decryptOk = c.kind !== 'response' && times(view, `cov-${id}-2`) >= need;
    let edited = null;
    if (decryptOk) {
      const sw = (s) => (s == null ? s : s.split(`cov-${id}-2`).join(`cov-${id}-3`));
      edited = { ...dec.request, body: sw(dec.request.body), path: sw(dec.request.path), headers: dec.request.headers.map(([k, v]) => [k, sw(v)]) };
    } else if (dec && /ct-keep(:|%3A)/i.test(view)) {
      // encrypt-only field: replace it with plaintext, as the analyst would
      const isForm = /x-www-form-urlencoded/i.test((req.headers.find(([k]) => /^content-type$/i.test(k)) || [])[1] || '');
      const val = isForm ? encodeURIComponent(P(3)) : P(3).replace(/"/g, '\\"');
      edited = { ...dec.request, body: dec.request.body.replace(/ct-keep(:|%3A)[A-Za-z0-9+/=_%-]+/i, val) };
    }
    let reencOk = false;
    let usedOracle = false;
    if (edited) {
      // Burp + bridge + panel stand-in for the L4 oracle: run the registered page function in its tab/worker
      const oracleCall = async (job) => {
        const owner = tab.records.find((r) => r.lib === 'traced' && r.oracleKey === job.fn);
        const res = await browser.cdp('Runtime.evaluate', { expression: mods.CryptoTraceTracer.oracleExpression(job.fn, job.value),
          awaitPromise: true, returnByValue: true }, (owner && owner.__session) || tab.s);
        if (res.exceptionDetails) throw new Error((res.exceptionDetails.exception && res.exceptionDetails.exception.description) || 'page function threw');
        usedOracle = true;
        return res.result.value;
      };
      const enc = await eng.handleAsync({ op: 'encryptRequest', host: '127.0.0.1', port, request: edited }, oracleCall);
      const failed = (enc.applied || []).filter((a) => !a.ok);
      if (failed.length) out.notes.push('re-encrypt: ' + failed.map((a) => a.where + ' ' + a.error).join('; '));
      const headers = Object.fromEntries(enc.request.headers.filter(([k]) => /^(content-type|cookie|x-)/i.test(k)));
      const res = await fetch(base + (enc.request.path || req.path), { method: req.method, headers, body: req.method === 'GET' ? undefined : enc.request.body });
      const reply = await res.json().catch(() => ({}));
      reencOk = !!reply.ok && times(reply.plain, `cov-${id}-3`) >= need;
      if (!reply.ok) out.notes.push('target rejected the re-encrypted request: ' + reply.error);
    }

    const at = (r) => (r.apply && r.apply.at === api) || (r.applyResponse && r.applyResponse.at === api);
    const hooked = seen.some((r) => r.lib !== 'traced' && r.lib !== 'transport' && at(r));
    const traced = seen.some((r) => r.lib === 'traced' && at(r));
    const unknownLeft = unknown.filter((u) => u.url && u.url.includes(api));
    // response cases: Burp's view of the response the target sent back (decryptResponse)
    let respOk = false;
    if (c.kind === 'response' && !load.error && raw.response) {
      const dr = eng.handle({ op: 'decryptResponse', host: '127.0.0.1', port, path: raw.path, response: raw.response });
      respOk = !!(dr.response && String(dr.response.body).includes(`cov-${id}-2`));
      if (!respOk) out.notes.push('response not decrypted: ' + JSON.stringify(dr.applied || dr.matched || null));
    }
    if (respOk) out.status = 'auto';
    else if (decryptOk && reencOk) out.status = traced && !hooked ? 'trace' : 'auto';
    else if (reencOk) out.status = 'encrypt-only';
    else if (skipped.length) out.status = 'skip';
    else if (unknownLeft.length || traced || hooked || unk.length) out.status = 'locate';
    else if (out.scan.length) out.status = 'scan-only';
    else out.status = 'none';
    if (usedOracle) out.notes.push('re-encrypted by the page function (oracle)');
    out.detail = { hooked, traced, decryptOk, reencOk, unknown: unknownLeft.length, oracle: usedOracle };
  } catch (e) {
    out.status = 'error';
    out.notes.push(e.message);
  } finally {
    await tab.close();
  }
  return out;
}

const verdict = (r) => {
  if (r.status === 'page-broken' || r.status === 'error') return 'ERROR';
  const a = RANK.indexOf(r.status), e = RANK.indexOf(r.expect);
  return a === e ? 'ok' : a < e ? 'GAP' : 'better';
};

const browser = await launchChrome(chromePath);
const results = [];
try {
  for (const c of CASES) {
    if (only.length && !only.includes(c.id)) continue;
    const r = await runCase(browser, c);
    r.verdict = verdict(r);
    results.push(r);
    console.log(`${r.verdict.padEnd(6)} ${r.id.padEnd(26)} expect=${r.expect.padEnd(12)} got=${String(r.status).padEnd(12)} ${r.notes.join(' | ')}`);
  }
} finally {
  await browser.close();
  server.close();
}

const count = (v) => results.filter((r) => r.verdict === v).length;
const md = [
  '# CryptoTrace coverage',
  '',
  `Measured by \`node scripts/coverage.mjs\` against the self-made coverage lab (\`samples/coverage/\`, fake keys, 127.0.0.1).`,
  'Each case runs the panel pipeline in headless Chrome; "got" is what actually happened to the request the target received',
  '(decrypted in Burp\'s view, edited, re-encrypted, accepted by the target).',
  '',
  `ok ${count('ok')} · better ${count('better')} · GAP ${count('GAP')} · ERROR ${count('ERROR')} (of ${results.length})`,
  '',
  'Levels: auto > trace > encrypt-only > skip > locate > scan-only > none.',
  '',
  '| case | group | what | expect | got | verdict | notes |',
  '|---|---|---|---|---|---|---|',
  ...results.map((r) => `| ${r.id} | ${r.group} | ${r.title} | ${r.expect} | ${r.status} | ${r.verdict} | ${[...(r.notes || []), r.scan && r.scan.length ? 'scan: ' + r.scan.join('/') : ''].filter(Boolean).join('<br>').replace(/\|/g, '\\|')} |`),
  '',
  '## Not measured by this lab',
  '',
  '- Rewriting WebSocket frames in Burp (placements are only shown in the panel).',
  '- Non-standard ciphers (custom XOR, nested encodings, per-request keys): located only -- they need a custom module or the planned L4 browser oracle.',
  '- Identification covers AES/ARIA/SEED block modes (CBC/ECB/CTR/CFB/OFB, PKCS#7/zero/none); LEA, WASM crypto and stream ciphers outside OpenSSL are not identified.',
  '- Code with no stable function boundaries (control-flow-flattened obfuscation) and cross-origin iframes are not exercised.',
  '- Burp UI itself (Decrypted tab, Scanner insertion points) is covered by the Java tests and manual checks, not by this run.',
  '',
].join('\n');
fs.mkdirSync(path.join(ROOT, 'output'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'output/coverage-report.md'), md);
if (writeDocs) fs.writeFileSync(path.join(ROOT, 'docs/COVERAGE.md'), md);
console.log(`\nok ${count('ok')} · better ${count('better')} · GAP ${count('GAP')} · ERROR ${count('ERROR')} -> output/coverage-report.md`);
process.exit(count('ERROR') ? 1 : 0);
