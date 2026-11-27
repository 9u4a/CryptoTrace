// Send to Burp client: token handling, error texts, selftest summary. Runs bridge-client.js under a window shim.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ctx = { window: {} };
vm.runInNewContext(fs.readFileSync(path.join(HERE, '../bridge-client.js'), 'utf8'), ctx);
const B = ctx.window.CryptoTraceBridge;

const reply = (status, body) => async () => ({ status, json: async () => body });

test('sends to 127.0.0.1 with the bearer token and summarizes selftest', async () => {
  let seen;
  const fetchFn = async (url, init) => {
    seen = { url, init };
    return { status: 200, json: async () => ({ ok: true, status: 'running — 1 config(s)', log: ['loaded p — selftest: c1=OK c2=OK'] }) };
  };
  const r = await B.send(fetchFn, { port: 17777, token: 'abc' }, { ciphers: { c1: {} } });
  assert.equal(seen.url, 'http://127.0.0.1:17777/config');
  assert.equal(seen.init.headers.Authorization, 'Bearer abc');
  assert.equal(seen.init.headers['Content-Type'], 'application/json');
  assert.equal(r.ok, true);
  assert.match(r.text, /selftest 2\/2/);
});

test('explains the usual failures', async () => {
  assert.match((await B.send(reply(200, {}), { port: 1, token: '' }, {})).text, /token not set/);
  assert.match((await B.send(async () => { throw new Error('refused'); }, { port: 17777, token: 'x' }, {})).text, /not reachable/);
  assert.match((await B.send(reply(401, { ok: false, error: 'token missing or wrong' }), { token: 'x' }, {})).text, /rejected the token/);
  assert.match((await B.send(reply(403, { ok: false, error: 'declined in Burp (config uses custom JS)' }), { token: 'x' }, {})).text, /declined/);
  const failed = await B.send(reply(200, { ok: false, status: 'running with 1 problem(s)', log: ['loaded p — selftest: c1=FAIL(bad key)', 'ERROR p.json: bad key'] }), { token: 'x' }, {});
  assert.equal(failed.ok, false);
  assert.match(failed.text, /bad key · selftest 0\/1/);
});

test('ping reports the port', async () => {
  const r = await B.ping(reply(200, { ok: true, name: 'CryptoTrace' }), { port: 18000, token: 'x' });
  assert.equal(r.text, 'Burp: connected (127.0.0.1:18000)');
});

test('summary names the cipher the server identified from a traced function', async () => {
  const fetchFn = async () => ({ status: 200, json: async () => ({ ok: true, status: 'running - 1 config(s)',
    log: ['loaded p - selftest: c1=OK', '  IDENTIFIED c1 = seed-cbc key=k1 iv=base64:Y3Q= padding=pkcs7'] }) });
  const r = await B.send(fetchFn, { port: 17777, token: 'abc' }, { ciphers: { c1: {} } });
  assert.equal(r.ok, true);
  assert.match(r.text, /identified c1=seed-cbc/);
});

test('oracle: next() long-polls with the token and returns the job; result() posts the answer', async () => {
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url, init });
    if (url.includes('/oracle/next')) return { status: 200, json: async () => ({ enabled: true, job: { oid: 4, fn: 'f@u:1:1', value: 'hi' } }) };
    return { status: 200, json: async () => ({ ok: true }) };
  };
  const n = await B.oracleNext(fetchFn, { port: 17777, token: 'abc' }, 15000);
  assert.equal(calls[0].url, 'http://127.0.0.1:17777/oracle/next?wait=15000');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer abc');
  assert.deepEqual({ enabled: n.enabled, oid: n.job.oid }, { enabled: true, oid: 4 });
  await B.oracleResult(fetchFn, { port: 17777, token: 'abc' }, { oid: 4, ok: true, value: 'enc' });
  assert.equal(calls[1].url, 'http://127.0.0.1:17777/oracle/result');
  assert.deepEqual(JSON.parse(calls[1].init.body), { oid: 4, ok: true, value: 'enc' });
  // Burp has the oracle off -> the panel learns it and backs off
  const off = await B.oracleNext(async () => ({ status: 200, json: async () => ({ enabled: false }) }), { port: 1, token: 'x' }, 10);
  assert.equal(off.enabled, false);
  const down = await B.oracleNext(async () => { throw new Error('refused'); }, { port: 1, token: 'x' }, 10);
  assert.match(down.error, /not reachable/);
});

test('oracleNext gives up on a poll Burp never answers (extension reloaded mid-poll)', async () => {
  const src = (await import('node:fs')).readFileSync(new URL('../bridge-client.js', import.meta.url), 'utf8');
  const sandbox = { window: {}, setTimeout, clearTimeout, AbortController };
  (await import('node:vm')).runInNewContext(src, sandbox);
  let signal = null;
  const never = (u, init) => { signal = init.signal; return new Promise(() => {}); };
  const t0 = Date.now();
  const r = await sandbox.window.CryptoTraceBridge.oracleNext(never, { port: 17777, token: 't' }, 10, '', 20);
  assert.match(r.error, /not reachable/);
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(signal.aborted, true); // the hung connection is dropped too
});

test('oracleNext sends the inspected origin so Burp routes jobs to the right tab', async () => {
  const src = (await import('node:fs')).readFileSync(new URL('../bridge-client.js', import.meta.url), 'utf8');
  const sandbox = { window: {} };
  (await import('node:vm')).runInNewContext(src, sandbox);
  let url = '';
  const fetchFn = async (u) => { url = u; return { status: 200, json: async () => ({ enabled: true }) }; };
  await sandbox.window.CryptoTraceBridge.oracleNext(fetchFn, { port: 17777, token: 't' }, 100, 'https://app.test:8443');
  assert.match(url, /wait=100&origin=https%3A%2F%2Fapp\.test%3A8443$/);
});

test('oracleResult gives up on a post Burp never answers (the oracle loop must keep going)', async () => {
  const src = (await import('node:fs')).readFileSync(new URL('../bridge-client.js', import.meta.url), 'utf8');
  const sandbox = { window: {}, setTimeout, clearTimeout, AbortController };
  (await import('node:vm')).runInNewContext(src, sandbox);
  let signal = null;
  const never = (u, init) => { signal = init.signal; return new Promise(() => {}); };
  const t0 = Date.now();
  const ok = await sandbox.window.CryptoTraceBridge.oracleResult(never, { port: 17777, token: 't' }, { oid: 1, ok: true, value: 'v' }, 20);
  assert.equal(ok, false);
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(signal.aborted, true);
});
