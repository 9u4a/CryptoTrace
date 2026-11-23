// hook-transport.js against a stub fetch: checks how each body shape is described for correlation.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const records = [];
const lastSent = () => [...records].reverse().find((r) => r.lib === 'transport' && r.op === 'fetch');

before(() => {
  globalThis.__cryptotrace_emit = (line) => { try { records.push(JSON.parse(line)); } catch (_) {} };
  globalThis.fetch = async () => new Response('ok'); // the page's network, stubbed
  globalThis.__beacons = [];
  globalThis.navigator.sendBeacon = (url, data) => { globalThis.__beacons.push([url, data]); return true; };
  globalThis.WebSocket = class FakeWebSocket { constructor(url) { this.url = url; this.sent = []; } send(d) { this.sent.push(d); } };
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'chrome-ext/hook-transport.js'), 'utf8'), { filename: 'hook-transport.js' });
});

test('a urlencoded string body is described as form fields (decoded values)', async () => {
  await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'userId=minjun&encPw=0a1b%2B2c&mode=1' });
  assert.deepEqual(lastSent().body, { kind: 'form', fields: [
    { name: 'userId', value: 'minjun' }, { name: 'encPw', value: '0a1b+2c' }, { name: 'mode', value: '1' }] });
});

test('a URLSearchParams body is described as form fields', async () => {
  await fetch('/login', { method: 'POST', body: new URLSearchParams({ encPw: 'abcdef0123', id: 'x' }) });
  assert.deepEqual(lastSent().body, { kind: 'form', fields: [{ name: 'encPw', value: 'abcdef0123' }, { name: 'id', value: 'x' }] });
});

test('a FormData body is described as multipart text fields (files skipped)', async () => {
  const fd = new FormData();
  fd.append('enc', 'Q2lwaGVydGV4dA==');
  fd.append('file', new Blob(['bin']), 'a.bin');
  await fetch('/upload', { method: 'POST', body: fd });
  assert.deepEqual(lastSent().body, { kind: 'multipart', fields: [{ name: 'enc', value: 'Q2lwaGVydGV4dA==' }] });
});

test('JSON and plain text bodies keep their existing description', async () => {
  await fetch('/a', { method: 'POST', body: JSON.stringify({ data: 'xyz' }) });
  assert.deepEqual(lastSent().body, { kind: 'json', fields: [{ path: '$.data', value: 'xyz' }] });
  await fetch('/b', { method: 'POST', body: 'U2FsdGVkX1+abc==' }); // base64 with '=' padding is not a form
  assert.deepEqual(lastSent().body, { kind: 'text', sample: 'U2FsdGVkX1+abc==' });
});

const lastOp = (op) => [...records].reverse().find((r) => r.lib === 'transport' && r.op === op);
const tick = () => new Promise((r) => setTimeout(r, 20));

test('fetch(new Request(...)) reports the Request body (read from a clone)', async () => {
  await fetch(new Request('http://api.test/r', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enc: 'cipher-in-request' }) }));
  await tick();
  const r = lastOp('fetch');
  assert.equal(r.url, 'http://api.test/r');
  assert.deepEqual(r.body, { kind: 'json', fields: [{ path: '$.enc', value: 'cipher-in-request' }] });
});

test('navigator.sendBeacon bodies are reported and still sent', async () => {
  assert.equal(navigator.sendBeacon('/log', 'a=1&enc=QUJDREVGR0hJSktM'), true);
  assert.deepEqual(lastOp('beacon').body, { kind: 'form', fields: [{ name: 'a', value: '1' }, { name: 'enc', value: 'QUJDREVGR0hJSktM' }] });
  assert.equal(globalThis.__beacons.length, 1);
});

test('WebSocket.send messages are reported with the socket URL', async () => {
  const ws = new WebSocket('wss://api.test/stream');
  ws.send(JSON.stringify({ t: 'msg', payload: 'U2VjcmV0UGF5bG9hZA==' }));
  const r = lastOp('websocket');
  assert.equal(r.url, 'wss://api.test/stream');
  assert.deepEqual(r.body, { kind: 'json', fields: [{ path: '$.t', value: 'msg' }, { path: '$.payload', value: 'U2VjcmV0UGF5bG9hZA==' }] });
  assert.deepEqual(ws.sent.length, 1, 'message still sent');
});
