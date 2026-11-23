// L4 browser oracle: a cipher the server can't re-implement is run by the page's own function. The engine
// asks for what it needs (handleAsync re-runs the request once the answers are in); over stdio main.mjs sends
// {oracle: {...}} lines to Burp and reads {oracleResult} lines back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createEngine } from '../src/engine.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
// the page's "custom cipher" (what the browser would run): XOR + base64
const scramble = (t) => Buffer.from(Buffer.from(t).map((x, i) => x ^ ((0x5a + i) & 0xff))).toString('base64');

function writeCfg(cipher) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-oracle-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify({
    schemaVersion: 1, profile: 'orc', scope: [{ host: 'api.test', pathRegex: '.*' }], keys: {},
    ciphers: { c1: cipher }, apply: { request: [{ in: 'json', path: '$.z', cipher: 'c1' }], response: [] }, integrity: [], selftest: [{ cipher: 'c1', plain: 'x', ciphertext: 'y' }],
  }));
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const ORACLE = { oracle: { fn: 'scramble@http://app.test/a.js:3:1', frame: 'http://app.test/' } };

test('oracle cipher: decrypt shows ct-keep, re-encrypt asks the page function (handleAsync) and uses its answer', async () => {
  const { file, cleanup } = writeCfg(ORACLE);
  const eng = createEngine();
  const load = eng.handle({ op: 'load', files: [file] }).results[0];
  assert.equal(load.error, undefined, load.error);
  assert.deepEqual(load.selftest.map((t) => t.ok), [true], 'oracle ciphers are not checked at load');
  const req = { method: 'POST', path: '/p', headers: [], body: JSON.stringify({ z: scramble('{"a":1}'), n: 1 }) };
  const dec = await eng.handleAsync({ op: 'decryptRequest', host: 'api.test', port: 443, request: req }, async () => { throw new Error('not called'); });
  assert.match(JSON.parse(dec.request.body).z, /^ct-keep:/);
  const jobs = [];
  const edited = { ...req, body: JSON.stringify({ z: '{"a":2}', n: 1 }) };
  const enc = await eng.handleAsync({ op: 'encryptRequest', host: 'api.test', port: 443, request: edited },
    async (job) => { jobs.push(job); return scramble(job.value); });
  assert.deepEqual(jobs.map((j) => ({ dir: j.dir, value: j.value, fn: j.fn })), [{ dir: 'encrypt', value: '{"a":2}', fn: ORACLE.oracle.fn }]);
  assert.equal(JSON.parse(enc.request.body).z, scramble('{"a":2}'));
  assert.ok(enc.applied.every((a) => a.ok), JSON.stringify(enc.applied));
  // no browser: the field is reported, the request is not sent in plaintext (HttpHandler blocks on !ok)
  const off = await eng.handleAsync({ op: 'encryptRequest', host: 'api.test', port: 443, request: edited }, async () => { throw new Error('oracle is off in Burp'); });
  assert.equal(off.applied[0].ok, false);
  assert.match(off.applied[0].error, /oracle is off/);
  // the synchronous path (unit tests, raw ops) says what it needs
  const sync = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: edited });
  assert.match(sync.applied[0].error, /oracle/);
  cleanup();
});

test('identify that fails falls back to the oracle when the spec carries one', () => {
  const { file, cleanup } = writeCfg({ identify: { algs: ['aes-128-cbc'], keys: [], ivs: [], paddings: ['pkcs7'] }, ...ORACLE });
  const res = createEngine().handle({ op: 'load', files: [file] }).results[0];
  assert.equal(res.error, undefined, res.error);
  assert.deepEqual(res.oracles, [{ cipher: 'c1', fn: ORACLE.oracle.fn }]);
  cleanup();
});

test('stdio: the server asks Burp with an {oracle} line and finishes the request with the {oracleResult} answer', async () => {
  const { file, cleanup } = writeCfg(ORACLE);
  const proc = spawn(process.execPath, [path.join(ROOT, 'server/src/main.mjs'), '--config', file]);
  const rl = readline.createInterface({ input: proc.stdout });
  const lines = [];
  const waiters = [];
  rl.on('line', (l) => { const m = JSON.parse(l); const w = waiters.findIndex((f) => f(m)); if (w >= 0) waiters.splice(w, 1); else lines.push(m); });
  const next = (pred) => new Promise((resolve) => {
    const i = lines.findIndex(pred);
    if (i >= 0) return resolve(lines.splice(i, 1)[0]);
    waiters.push((m) => (pred(m) ? (resolve(m), true) : false));
  });
  const send = (o) => proc.stdin.write(JSON.stringify(o) + '\n');
  try {
    send({ id: 1, op: 'encryptRequest', host: 'api.test', port: 443, request: { method: 'POST', path: '/p', headers: [], body: '{"z":"hello oracle"}' } });
    const ask = await next((m) => m.oracle);
    assert.equal(ask.oracle.dir, 'encrypt');
    assert.equal(ask.oracle.value, 'hello oracle');
    send({ oracleResult: ask.oracle.oid, ok: true, value: scramble('hello oracle') });
    const res = await next((m) => m.id === 1);
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(JSON.parse(res.request.body).z, scramble('hello oracle'));
  } finally {
    proc.kill();
    cleanup();
  }
});
