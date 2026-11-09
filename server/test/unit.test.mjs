import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { symmetricCipher, rsaCipher } from '../src/cipher.mjs';
import { loadCustomCipher } from '../src/custom.mjs';
import { parsePath, getAt } from '../src/jsonpath.mjs';
import { createEngine } from '../src/engine.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SAMPLES = path.resolve(HERE, '../../samples/configs');
const k32 = Buffer.alloc(32, 1);
const k16 = Buffer.alloc(16, 2);

test('AES-CBC static IV matches node reference', () => {
  const c = symmetricCipher({ alg: 'aes-256-cbc', iv: { value: '00'.repeat(16), encoding: 'hex' } }, k32);
  const ref = crypto.createCipheriv('aes-256-cbc', k32, Buffer.alloc(16));
  assert.equal(c.encrypt('hello'), Buffer.concat([ref.update('hello'), ref.final()]).toString('base64'));
  assert.equal(c.decrypt(c.encrypt('hello')), 'hello');
});

test('round-trips: ECB, CTR, GCM prefix IV, zero padding, hex output, ARIA', () => {
  const specs = [
    [{ alg: 'aes-128-ecb' }, k16],
    [{ alg: 'aes-256-ctr', iv: { value: '11'.repeat(16), encoding: 'hex' } }, k32],
    [{ alg: 'aes-256-gcm', iv: { from: 'prefix', length: 12 } }, k32],
    [{ alg: 'aes-256-cbc', padding: 'zero', iv: { value: 'a'.repeat(16) }, outEncoding: 'hex' }, k32],
    [{ alg: 'aria-256-cbc', iv: { value: 'b'.repeat(16) } }, k32],
  ];
  for (const [spec, key] of specs) {
    const c = symmetricCipher(spec, key);
    assert.equal(c.decrypt(c.encrypt('평문 plain {"a":1}')), '평문 plain {"a":1}', spec.alg);
  }
});

test('GCM detects tampering; missing IV and unknown alg are config errors', () => {
  const c = symmetricCipher({ alg: 'aes-256-gcm', iv: { from: 'prefix' } }, k32);
  const ct = Buffer.from(c.encrypt('x'), 'base64');
  ct[ct.length - 1] ^= 1;
  assert.throws(() => c.decrypt(ct.toString('base64')));
  assert.throws(() => symmetricCipher({ alg: 'aes-256-cbc' }, k32), /needs "iv"/);
  assert.throws(() => symmetricCipher({ alg: 'nope-cbc', iv: { value: 'x' } }, k32), /not available/);
});

test('RSA-OAEP encrypts with public key; decrypt needs private key', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const pem = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const enc = rsaCipher({ padding: 'oaep', oaepHash: 'sha256' }, spki, null);
  const full = rsaCipher({ padding: 'oaep', oaepHash: 'sha256' }, spki, pem);
  assert.equal(full.decrypt(enc.encrypt('secret')), 'secret');
  assert.throws(() => enc.decrypt('AAAA'), /private key/);
});

test('custom cipher runs in vm without require/process/fetch, with timeout', () => {
  const rev = loadCustomCipher(path.join(HERE, '../fixtures/reverse-cipher.js'), {}, {});
  assert.equal(rev.decrypt(rev.encrypt('abc')), 'abc');
  const bad = loadCustomCipher(path.join(HERE, '../fixtures/escape-attempt.js'), { timeoutMs: 100 }, {});
  assert.equal(bad.encrypt('x'), 'undefinedundefinedundefined');
  assert.throws(() => bad.decrypt('x'), /timed out/);
});

test('JSON path subset', () => {
  const doc = { a: { 'b-c': [{ d: 1 }] } };
  assert.equal(getAt(doc, parsePath("$.a['b-c'][0].d")), 1);
  assert.throws(() => parsePath('a.b'));
});

test('sample configs load and pass selftest', () => {
  const eng = createEngine();
  const { results } = eng.handle({
    op: 'load',
    files: [path.join(SAMPLES, 'scenario-a.json'), path.join(SAMPLES, 'scenario-c.json')],
  });
  for (const r of results) {
    assert.equal(r.error, undefined, r.error);
    assert.ok(r.selftest.length > 0 && r.selftest.every((t) => t.ok), JSON.stringify(r.selftest));
  }
  assert.deepEqual(eng.handle({ op: 'health' }).profiles, ['sample-a-login', 'sample-c-profile']);
});

test('bad config is reported without dropping good ones', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-cfg-'));
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, JSON.stringify({ schemaVersion: 99, profile: 'x' }));
  const eng = createEngine();
  const { results } = eng.handle({ op: 'load', files: [bad, path.join(SAMPLES, 'scenario-a.json')] });
  assert.match(results[0].error, /schemaVersion 99/);
  assert.deepEqual(eng.handle({ op: 'health' }).profiles, ['sample-a-login']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('request JSON field: decrypt embeds object, encrypt restores compact ciphertext; marker removed', () => {
  const eng = createEngine();
  eng.handle({ op: 'load', files: [path.join(SAMPLES, 'scenario-a.json')] });
  const enc = 'HXehilhpKDerwpYGLBYST6sSfDhtBfmrF9qs2RFHQ1k=';  // leakcheck:allow — fake sample vector (samples/configs/scenario-a.json)
  const request = { path: '/api/login', headers: [['Content-Type', 'application/json']], body: JSON.stringify({ data: enc }) };
  const dec = eng.handle({ op: 'decryptRequest', host: '127.0.0.1', port: 8088, request });
  assert.equal(dec.matched, 'sample-a-login');
  assert.deepEqual(JSON.parse(dec.request.body).data, { id: 'alice', pw: 'pw1234' });

  dec.request.headers.push(['X-CT-Plain', '1']);
  const back = eng.handle({ op: 'encryptRequest', host: '127.0.0.1', port: 8088, request: dec.request });
  assert.equal(JSON.parse(back.request.body).data, enc);
  assert.ok(!back.request.headers.some(([n]) => n.toLowerCase() === 'x-ct-plain'));
});

test('out-of-scope request is untouched; header/query rules', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-cfg-'));
  const file = path.join(dir, 'hq.json');
  fs.writeFileSync(file, JSON.stringify({
    schemaVersion: 1, profile: 'hq',
    scope: [{ host: 'api.shop.test', pathRegex: '^/v1/' }],
    keys: { k: { value: 'k'.repeat(32) } },
    ciphers: { c: { alg: 'aes-256-cbc', key: 'k', iv: { value: 'i'.repeat(16) } } },
    apply: { request: [{ in: 'header', name: 'X-Enc', cipher: 'c' }, { in: 'query', name: 'q', cipher: 'c' }] },
  }));
  const eng = createEngine();
  eng.handle({ op: 'load', files: [file] });
  const plain = { path: '/v1/s?q=hello%20world&x=1', headers: [['X-Enc', 'top secret']], body: '' };
  const enc = eng.handle({ op: 'encryptRequest', host: 'api.shop.test', port: 443, request: plain });
  assert.ok(enc.applied.every((a) => a.ok));
  const dec = eng.handle({ op: 'decryptRequest', host: 'api.shop.test', port: 443, request: enc.request });
  assert.equal(dec.request.headers[0][1], 'top secret');
  assert.equal(dec.request.path, '/v1/s?q=hello%20world&x=1');
  const other = eng.handle({ op: 'decryptRequest', host: 'other.test', port: 443, request: plain });
  assert.equal(other.matched, null);
  fs.rmSync(dir, { recursive: true, force: true });
});
