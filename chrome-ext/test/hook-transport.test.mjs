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
