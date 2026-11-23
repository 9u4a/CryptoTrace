// correlate.js: learning where a captured ciphertext travels (apply location) from transport records.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const load = () => {
  const sandbox = { window: {}, URL };
  vm.runInNewContext(fs.readFileSync(path.join(HERE, '../correlate.js'), 'utf8'), sandbox);
  return sandbox.window.correlate;
};
const enc = (output) => ({ lib: 'x', op: 'encrypt', output: { encoding: 'hex', value: output } });

test('a ciphertext in a urlencoded form field -> apply {in:form, name}', () => {
  const correlate = load();
  const rec = enc('9f3a0c11d2e4b5a6c7d8e9f0');
  const records = [rec];
  correlate({ lib: 'transport', op: 'fetch', url: '/api/pin', body: { kind: 'form', fields: [
    { name: 'userId', value: 'minjun' }, { name: 'encPin', value: '9f3a0c11d2e4b5a6c7d8e9f0' }] } }, records);
  assert.deepEqual({ ...rec.apply }, { in: 'form', name: 'encPin', at: '/api/pin' });
});

test('a ciphertext in a multipart text field -> apply {in:multipart, name}', () => {
  const correlate = load();
  const rec = enc('Q2lwaGVydGV4dEhlcmU=');
  correlate({ lib: 'transport', op: 'fetch', url: '/up', body: { kind: 'multipart', fields: [{ name: 'enc', value: 'Q2lwaGVydGV4dEhlcmU=' }] } }, [rec]);
  assert.deepEqual({ ...rec.apply }, { in: 'multipart', name: 'enc', at: '/up' });
});

test('JSON field, header and whole-body placements still correlate', () => {
  const correlate = load();
  const a = enc('AAAABBBBCCCCDDDD'), b = enc('EEEEFFFFGGGGHHHH'), c = enc('IIIIJJJJKKKKLLLL');
  correlate({ lib: 'transport', op: 'fetch', url: '/j', headers: [['X-Enc', 'EEEEFFFFGGGGHHHH']],
    body: { kind: 'json', fields: [{ path: '$.data', value: 'AAAABBBBCCCCDDDD' }] } }, [a, b]);
  correlate({ lib: 'transport', op: 'fetch', url: '/t', body: { kind: 'text', sample: 'IIIIJJJJKKKKLLLL' } }, [c]);
  assert.deepEqual({ ...a.apply }, { in: 'json', path: '$.data', at: '/j' });
  assert.deepEqual({ ...b.apply }, { in: 'header', name: 'X-Enc', at: '/j' });
  assert.deepEqual({ ...c.apply }, { in: 'body', at: '/t' });
});
