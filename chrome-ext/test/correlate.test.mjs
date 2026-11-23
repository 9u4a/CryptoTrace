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

const B = (buf) => Buffer.from(buf).toString('base64');
const wc = (iv, ct) => ({ lib: 'webcrypto', op: 'encrypt', alg: { name: 'AES-GCM' },
  iv: { encoding: 'base64', value: B(iv) }, output: { encoding: 'base64', value: B(ct) } });
const IV12 = Buffer.from('0102030405060708090a0b0c', 'hex');
const IV16 = Buffer.from('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf', 'hex'); // test bytes  leakcheck:allow
const CT = Buffer.from('f1e2d3c4b5a6978877665544332211000f1e2d3c', 'hex'); // 20 bytes (not a multiple of 3)  leakcheck:allow

test('IV sent in its own JSON field next to the ciphertext -> ivApply', () => {
  const correlate = load();
  const rec = wc(IV12, CT);
  correlate({ lib: 'transport', op: 'fetch', url: '/api/transfer', body: { kind: 'json', fields: [
    { path: '$.ek', value: 'zzzzzzzzzzzz' }, { path: '$.iv', value: B(IV12) }, { path: '$.ct', value: B(CT) }] } }, [rec]);
  assert.deepEqual({ ...rec.apply }, { in: 'json', path: '$.ct', at: '/api/transfer' });
  assert.deepEqual({ ...rec.ivApply }, { in: 'json', path: '$.iv', encoding: 'base64' });
});

test('IV in a header as hex -> ivApply {in:header, encoding:hex}', () => {
  const correlate = load();
  const rec = wc(IV16, CT);
  correlate({ lib: 'transport', op: 'fetch', url: '/x', headers: [['X-IV', IV16.toString('hex')], ['X-Data', B(CT)]], body: { kind: 'none' } }, [rec]);
  assert.deepEqual({ ...rec.apply }, { in: 'header', name: 'X-Data', at: '/x' });
  assert.deepEqual({ ...rec.ivApply }, { in: 'header', name: 'X-IV', encoding: 'hex' });
});

test('ciphertext bytes re-encoded as hex in a form field -> apply + wire encoding hex', () => {
  const correlate = load();
  const rec = wc(IV12, CT);
  correlate({ lib: 'transport', op: 'fetch', url: '/f', body: { kind: 'form', fields: [{ name: 'encData', value: CT.toString('hex') }] } }, [rec]);
  assert.deepEqual({ ...rec.apply }, { in: 'form', name: 'encData', at: '/f', encoding: 'hex' });
});

test('IV prepended to the ciphertext bytes (16-byte IV breaks base64 substring alignment) -> ivPrefix', () => {
  const correlate = load();
  const rec = wc(IV16, CT);
  const wire = B(Buffer.concat([IV16, CT]));
  assert.ok(!wire.includes(B(CT).replace(/=+$/, '')), 'precondition: plain substring matching cannot see it');
  correlate({ lib: 'transport', op: 'fetch', url: '/p', body: { kind: 'text', sample: wire } }, [rec]);
  assert.deepEqual({ ...rec.apply }, { in: 'body', at: '/p', ivPrefix: 16 });
});

test('a ciphertext sent over a WebSocket -> applyWebSocket (never an HTTP apply rule)', () => {
  const correlate = load();
  const rec = enc('U2VjcmV0UGF5bG9hZA==');
  correlate({ lib: 'transport', op: 'websocket', url: 'wss://api.test/stream', headers: [],
    body: { kind: 'json', fields: [{ path: '$.payload', value: 'U2VjcmV0UGF5bG9hZA==' }] } }, [rec]);
  assert.equal(rec.apply, undefined);
  assert.deepEqual({ ...rec.applyWebSocket }, { in: 'json', path: '$.payload', at: '/stream', url: 'wss://api.test/stream' });
});

test('isExplained: a traced value is explained only by a captured call placed at the same location and endpoint', () => {
  const sandbox = { window: {}, URL };
  vm.runInNewContext(fs.readFileSync(path.join(HERE, '../correlate.js'), 'utf8'), sandbox);
  const { correlate, isExplained } = sandbox.window;
  const rec = enc('QUJDREVGR0hJSktMTU5PUA==');
  const records = [rec];
  correlate({ lib: 'transport', op: 'fetch', url: '/api/a', body: { kind: 'json', fields: [{ path: '$.enc', value: 'QUJDREVGR0hJSktMTU5PUA==' }] } }, records);
  assert.equal(isExplained({ url: '/api/a', loc: { in: 'json', path: '$.enc' } }, records), true);
  assert.equal(isExplained({ url: '/api/a', loc: { in: 'json', path: '$.other' } }, records), false, 'another field');
  assert.equal(isExplained({ url: '/api/b', loc: { in: 'json', path: '$.enc' } }, records), false, 'another endpoint');
});

test('isExplained: the IV field of a captured call (ivApply) is explained too', () => {
  const sandbox = { window: {}, URL };
  vm.runInNewContext(fs.readFileSync(path.join(HERE, '../correlate.js'), 'utf8'), sandbox);
  const { correlate, isExplained } = sandbox.window;
  const rec = wc(IV16, CT);
  const records = [rec];
  correlate({ lib: 'transport', op: 'fetch', url: '/api/inquiry', headers: [['X-Enc-IV', IV16.toString('hex')]],
    body: { kind: 'json', fields: [{ path: '$.payload', value: B(CT) }] } }, records);
  assert.equal(isExplained({ url: '/api/inquiry', loc: { in: 'header', name: 'X-Enc-IV' } }, records), true);
  assert.equal(isExplained({ url: '/api/other', loc: { in: 'header', name: 'X-Enc-IV' } }, records), false);
});
