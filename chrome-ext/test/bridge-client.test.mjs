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
