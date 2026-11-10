import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { symmetricCipher, rsaCipher } from '../src/cipher.mjs';
import { deriveKey } from '../src/kdf.mjs';
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

test('session key: pending until captured, then decrypts; op "key" sets it', () => {
  const sessKeyHex = '11'.repeat(32); // captured at runtime, not in the config
  const ivHex = '22'.repeat(16);
  const plain = '{"user":"alice"}';
  const ref = crypto.createCipheriv('aes-256-cbc', Buffer.from(sessKeyHex, 'hex'), Buffer.from(ivHex, 'hex'));
  const ct = Buffer.concat([ref.update(plain, 'utf8'), ref.final()]).toString('base64');

  const cfg = {
    schemaVersion: 1, profile: 'sess',
    scope: [{ host: 'api.test', pathRegex: '.*' }],
    keys: { sk: { source: 'session', encoding: 'hex', capture: { urlRegex: '/auth/handshake', jsonPath: '$.key' } } },
    ciphers: { c1: { alg: 'aes-256-cbc', key: 'sk', iv: { value: ivHex, encoding: 'hex' }, padding: 'pkcs7' } },
    apply: { request: [{ in: 'json', path: '$.data', cipher: 'c1' }], response: [] },
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-sess-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  const loaded = eng.handle({ op: 'load', files: [file] }).results[0];

  // Capture rule is surfaced to Burp, and the cipher is pending before capture.
  assert.equal(loaded.error, undefined, loaded.error);
  assert.deepEqual(loaded.captures, [{ keyName: 'sk', urlRegex: '/auth/handshake', jsonPath: '$.key', regex: null, header: null, encoding: 'hex' }]);

  const body = JSON.stringify({ data: ct });
  const before = eng.handle({ op: 'decryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/x' } });
  assert.equal(before.applied[0].ok, false);
  assert.match(before.applied[0].error, /not captured yet/);

  // Burp captured the key from the handshake response and pushes it in.
  eng.handle({ op: 'key', profile: 'sess', keyName: 'sk', value: sessKeyHex });
  const after = eng.handle({ op: 'decryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/x' } });
  assert.equal(after.applied[0].ok, true, JSON.stringify(after.applied));
  assert.equal(JSON.parse(after.request.body).data.user, 'alice');

  // A non-session key cannot be set this way.
  assert.throws(() => eng.handle({ op: 'key', profile: 'sess', keyName: 'nope', value: 'x' }), /not a session key/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('integrity: timestamp + hmac over ciphertext recomputed on encrypt', () => {
  const keyHex = 'aa'.repeat(32); // hmac key  (test-only)
  const ivHex = '22'.repeat(16);
  const cfg = {
    schemaVersion: 1, profile: 'intg',
    scope: [{ host: 'api.test', pathRegex: '.*' }],
    keys: {
      ek: { source: 'static', value: '33'.repeat(32), encoding: 'hex' },
      hk: { source: 'static', value: keyHex, encoding: 'hex' },
    },
    ciphers: { c1: { alg: 'aes-256-cbc', key: 'ek', iv: { value: ivHex, encoding: 'hex' }, padding: 'pkcs7' } },
    apply: { request: [{ in: 'json', path: '$.data', cipher: 'c1' }], response: [] },
    integrity: [
      { type: 'timestamp', format: 'ms', target: { in: 'header', name: 'X-Ts' } },
      { type: 'hmac', alg: 'sha256', key: 'hk', input: '{json:$.data}{header:X-Ts}', outEncoding: 'hex', target: { in: 'header', name: 'X-Sign' } },
    ],
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-intg-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);

  const body = JSON.stringify({ data: 'topsecret', other: 1 });
  const res = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/x' } });
  assert.ok(res.applied.every((a) => a.ok), JSON.stringify(res.applied));

  const ct = JSON.parse(res.request.body).data;
  const ts = res.request.headers.find(([n]) => n === 'X-Ts')[1];
  const sign = res.request.headers.find(([n]) => n === 'X-Sign')[1];
  assert.match(ts, /^\d+$/);
  const expected = crypto.createHmac('sha256', Buffer.from(keyHex, 'hex')).update(ct + ts, 'utf8').digest('hex');
  assert.equal(sign, expected);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('integrity: custom sign module runs on encrypt', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-intgc-'));
  fs.writeFileSync(path.join(dir, 'sign.js'),
    'module.exports = { sign: (ctx) => "L" + ctx.input.length + ":" + Object.keys(ctx.key).join(",") };');
  const cfg = {
    schemaVersion: 1, profile: 'intgc',
    scope: [{ host: 'api.test', pathRegex: '.*' }],
    keys: { hk: { source: 'static', value: 'ab'.repeat(16), encoding: 'hex' } },
    ciphers: {},
    apply: { request: [], response: [] },
    integrity: [{ type: 'custom', custom: 'sign.js', input: '{body}', target: { in: 'header', name: 'X-C' } }],
  };
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);

  const body = '{"a":1}';
  const res = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/x' } });
  const xc = res.request.headers.find(([n]) => n === 'X-C')[1];
  assert.equal(xc, 'L' + body.length + ':hk');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('integrity: failing rule makes the op not-ok (blocks in Burp)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-intgf-'));
  fs.writeFileSync(path.join(dir, 'bad.js'), 'module.exports = { sign: () => { throw new Error("boom"); } };');
  const cfg = {
    schemaVersion: 1, profile: 'intgf',
    scope: [{ host: 'api.test', pathRegex: '.*' }], keys: {}, ciphers: {},
    apply: { request: [], response: [] },
    integrity: [{ type: 'custom', custom: 'bad.js', target: { in: 'header', name: 'X-C' } }],
  };
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);
  const res = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body: '{}', path: '/x' } });
  assert.ok(res.applied.some((a) => !a.ok), JSON.stringify(res.applied));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ChaCha20-Poly1305 AEAD round-trips and detects tampering', () => {
  const c = symmetricCipher({ alg: 'chacha20-poly1305', iv: { from: 'prefix', length: 12 } }, k32);
  const ct = c.encrypt('평문 secret {"a":1}');
  assert.equal(c.decrypt(ct), '평문 secret {"a":1}');
  const bad = Buffer.from(ct, 'base64'); bad[bad.length - 1] ^= 1;
  assert.throws(() => c.decrypt(bad.toString('base64')));
});

test('KDF: pbkdf2/scrypt/hkdf derive a usable AES key', () => {
  const pass = Buffer.from('correct horse battery staple', 'utf8');
  for (const kdf of ['pbkdf2', 'scrypt', 'hkdf']) {
    const spec = { alg: 'aes-256-cbc', kdf, iv: { value: '00'.repeat(16), encoding: 'hex' }, kdfParams: { salt: { value: '01'.repeat(16), encoding: 'hex' }, keyLen: 32, iterations: 1000, info: { value: 'ct', encoding: 'utf8' } } };
    const dk = deriveKey(spec, pass);
    assert.equal(dk.length, 32, kdf);
    const c = symmetricCipher(spec, dk);
    assert.equal(c.decrypt(c.encrypt('hello')), 'hello', kdf);
  }
});

test('integrity sign: RSA-PSS and ECDSA signatures verify with the public key', () => {
  const cases = [
    { ...crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }), padding: 'pss', vopts: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING } },
    { ...crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }), padding: undefined, vopts: {} },
  ];
  for (const kp of cases) {
    const privPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const cfg = {
      schemaVersion: 1, profile: 'sg',
      scope: [{ host: 'api.test', pathRegex: '.*' }],
      keys: { sk: { source: 'static', value: privPem, encoding: 'utf8' } },
      ciphers: {}, apply: { request: [], response: [] },
      integrity: [{ type: 'sign', alg: 'sha256', padding: kp.padding, key: 'sk', input: '{body}', outEncoding: 'base64', target: { in: 'header', name: 'X-Sig' } }],
    };
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-sign-'));
    const file = path.join(dir, 'c.json');
    fs.writeFileSync(file, JSON.stringify(cfg));
    const eng = createEngine();
    assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);
    const body = '{"amount":100}';
    const res = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/x' } });
    const sig = res.request.headers.find(([n]) => n === 'X-Sig')[1];
    const ok = crypto.verify('sha256', Buffer.from(body), { key: kp.publicKey, ...kp.vopts }, Buffer.from(sig, 'base64'));
    assert.ok(ok, 'signature verifies');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('encodings: base32, base58, and a nested [hex,base64] chain round-trip through a cipher', () => {
  for (const outEncoding of ['base32', 'base58', ['hex', 'base64']]) {
    const c = symmetricCipher({ alg: 'aes-256-cbc', iv: { value: '00'.repeat(16), encoding: 'hex' }, outEncoding }, k32);
    assert.equal(c.decrypt(c.encrypt('hello 세계')), 'hello 세계', JSON.stringify(outEncoding));
  }
});

const roundTripConfig = (apply) => {
  const cfg = {
    schemaVersion: 1, profile: 'rt',
    scope: [{ host: 'api.test', pathRegex: '.*' }],
    keys: { k: { source: 'static', value: '11'.repeat(32), encoding: 'hex' } },
    ciphers: { c1: { alg: 'aes-256-cbc', key: 'k', iv: { value: '22'.repeat(16), encoding: 'hex' }, padding: 'pkcs7' } },
    apply, integrity: [],
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-rt-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);
  return { eng, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
};

test('apply in:form encrypts a urlencoded body field and round-trips', () => {
  const { eng, cleanup } = roundTripConfig({ request: [{ in: 'form', name: 'q', cipher: 'c1' }], response: [] });
  const body = 'q=secret&x=1';
  const enc = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/p' } });
  assert.ok(enc.applied[0].ok);
  assert.notEqual(new URLSearchParams(enc.request.body).get('q'), 'secret');
  const dec = eng.handle({ op: 'decryptRequest', host: 'api.test', port: 443, request: { headers: [], body: enc.request.body, path: '/p' } });
  assert.equal(new URLSearchParams(dec.request.body).get('q'), 'secret');
  cleanup();
});

test('apply in:json with [*] and ..key encrypts every match and round-trips', () => {
  for (const jpath of ['$.items[*]', '$..token']) {
    const { eng, cleanup } = roundTripConfig({ request: [{ in: 'json', path: jpath, cipher: 'c1' }], response: [] });
    const body = JSON.stringify({ items: ['a', 'b'], nested: { token: 'c' }, token: 'd' });
    const enc = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body, path: '/p' } });
    assert.ok(enc.applied[0].ok, jpath);
    const dec = eng.handle({ op: 'decryptRequest', host: 'api.test', port: 443, request: { headers: [], body: enc.request.body, path: '/p' } });
    const back = JSON.parse(dec.request.body);
    if (jpath === '$.items[*]') assert.deepEqual(back.items, ['a', 'b']);
    else { assert.equal(back.nested.token, 'c'); assert.equal(back.token, 'd'); }
    cleanup();
  }
});

test('binary body: bodyEncoding echoes on encrypt, drops on decrypt, in:body round-trips', () => {
  const cfg = {
    schemaVersion: 1, profile: 'bin',
    scope: [{ host: 'api.test', pathRegex: '.*' }],
    keys: { k: { source: 'static', value: '11'.repeat(32), encoding: 'hex' } },
    ciphers: { c1: { alg: 'aes-256-cbc', key: 'k', iv: { value: '22'.repeat(16), encoding: 'hex' }, padding: 'pkcs7', inEncoding: 'utf8', outEncoding: 'base64' } },
    apply: { request: [{ in: 'body', cipher: 'c1' }], response: [] }, integrity: [],
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-bin-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);

  // encrypt a plaintext body; a declared binary wire (bodyEncoding) is echoed back for Burp to decode.
  const enc = eng.handle({ op: 'encryptRequest', host: 'api.test', port: 443, request: { headers: [], body: 'hello', path: '/p', bodyEncoding: 'base64' } });
  assert.equal(enc.request.bodyEncoding, 'base64');
  // decrypt returns plaintext for the editor with no transport flag.
  const dec = eng.handle({ op: 'decryptRequest', host: 'api.test', port: 443, request: { headers: [], body: enc.request.body, path: '/p', bodyEncoding: 'base64' } });
  assert.equal(dec.request.bodyEncoding, undefined);
  assert.equal(dec.request.body, 'hello');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('scope host wildcard *.example.test matches subdomains and apex, not others', () => {
  const cfg = {
    schemaVersion: 1, profile: 'wild',
    scope: [{ host: '*.example.test', pathRegex: '.*' }],
    keys: {}, ciphers: {}, apply: { request: [], response: [] }, integrity: [],
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-wild-'));
  const file = path.join(dir, 'c.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  const eng = createEngine();
  assert.equal(eng.handle({ op: 'load', files: [file] }).results[0].error, undefined);
  const matched = (host) => eng.handle({ op: 'decryptRequest', host, port: 443, request: { headers: [], body: '{}', path: '/x' } }).matched;
  assert.equal(matched('api.example.test'), 'wild');
  assert.equal(matched('example.test'), 'wild');
  assert.equal(matched('a.b.example.test'), 'wild');
  assert.equal(matched('evil.test'), null);
  assert.equal(matched('notexample.test'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});
