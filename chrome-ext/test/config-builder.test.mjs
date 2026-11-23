// Runs the browser-side config-builder under a window shim, then checks the output
// loads and self-tests in the real server engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import { createEngine } from '../../server/src/engine.mjs';
import { aesCbcEncrypt, gcmEncrypt, C_KEY } from '../../samples/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const CryptoJS = require(path.join(HERE, '../../samples/public/vendor/crypto-js-4.2.0.js'));

function loadIntoEngine(cfg) {
  const { cfg: file, dir } = write(cfg);
  const res = createEngine().handle({ op: 'load', files: [file] }).results[0];
  fs.rmSync(dir, { recursive: true, force: true });
  return res;
}

function loadBuilder() {
  const src = fs.readFileSync(path.join(HERE, '../config-builder.js'), 'utf8');
  const sandbox = { window: {}, URL, Date };
  vm.runInNewContext(src, sandbox);
  return sandbox.window.buildConfig;
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

test('CryptoJS AES-CBC record -> config that self-tests', () => {
  const buildConfig = loadBuilder();
  // Mirror what hook.js reports for CryptoJS AES with hex key+iv WordArrays.
  const keyHex = Buffer.from('ct-sample-aes-key-0123456789abcd', 'utf8').toString('hex');
  const ivHex = Buffer.from('ct-sample-iv-016', 'utf8').toString('hex');
  const plain = '{"id":"alice","pw":"pw1234"}';
  const cipher = aesCbcEncrypt(plain);
  const records = [{
    lib: 'cryptojs', op: 'encrypt', alg: { name: 'AES' }, padding: 'Pkcs7',
    key: { encoding: 'cryptojs', value: keyHex },
    iv: { encoding: 'cryptojs', value: ivHex },
    input: { encoding: 'utf8', value: plain },
    output: { encoding: 'cryptojs', value: cipher },
    frame: 'http://127.0.0.1:8088/',
  }];
  const cfg = buildConfig(records);
  // output encoding from CryptoJS is base64 here; make the selftest vector usable
  cfg.selftest = [{ cipher: Object.keys(cfg.ciphers)[0], plain, ciphertext: cipher }];
  assert.equal(cfg.schemaVersion, 1);
  assert.equal(cfg.scope[0].host, '127.0.0.1');
  assert.equal(cfg.scope[0].port, 8088);

  const { cfg: written, dir } = write(cfg);
  const eng = createEngine();
  const res = eng.handle({ op: 'load', files: [written] }).results[0];
  assert.equal(res.error, undefined, res.error);
  assert.ok(res.selftest.every((t) => t.ok), JSON.stringify(res.selftest));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('WebCrypto AES-GCM (IV prefix) record -> config that self-tests', () => {
  const buildConfig = loadBuilder();
  const plain = '{"name":"Alice","email":"alice@shop.test"}';
  const { iv, ct } = gcmEncrypt(C_KEY, plain, Buffer.alloc(12, 7));
  const wire = Buffer.concat([iv, ct]).toString('base64');
  const records = [{
    lib: 'webcrypto', op: 'encrypt', alg: { name: 'AES-GCM', iv: { encoding: 'base64', value: b64(iv) } },
    key: { encoding: 'base64', value: b64(C_KEY) },
    input: { encoding: 'utf8', value: plain },
    output: { encoding: 'base64', value: wire },
    frame: 'http://127.0.0.1:8088/',
  }];
  const cfg = buildConfig(records);
  const cid = Object.keys(cfg.ciphers)[0];
  assert.equal(cfg.ciphers[cid].alg, 'aes-256-gcm');
  cfg.selftest = [{ cipher: cid, plain, ciphertext: wire }];

  const { cfg: written, dir } = write(cfg);
  const eng = createEngine();
  const res = eng.handle({ op: 'load', files: [written] }).results[0];
  assert.equal(res.error, undefined, res.error);
  assert.ok(res.selftest.every((t) => t.ok), JSON.stringify(res.selftest));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('correlated apply + RSA note survive into the config', () => {
  const buildConfig = loadBuilder();
  const records = [
    { lib: 'webcrypto', op: 'encrypt', alg: { name: 'AES-CBC' }, key: { encoding: 'base64', value: b64(Buffer.alloc(32, 1)) },
      iv: { encoding: 'base64', value: b64(Buffer.alloc(16, 2)) }, input: { encoding: 'utf8', value: 'x' },
      output: { encoding: 'base64', value: 'ZZZ' }, apply: { in: 'json', path: '$.data' }, frame: 'https://api.shop.test/' },
    { lib: 'jsencrypt', op: 'encrypt', alg: { name: 'RSA' }, input: { encoding: 'utf8', value: 'k' },
      output: { encoding: 'utf8', value: 'YQ==' }, frame: 'https://api.shop.test/' },
  ];
  const cfg = buildConfig(records);
  assert.equal(JSON.stringify(cfg.apply.request[0]), JSON.stringify({ in: 'json', path: '$.data', cipher: 'c1' }));
  assert.equal(cfg.ciphers.c2.alg, 'rsa');
  assert.match(cfg.ciphers.c2._note, /publicKey\/privateKey/);
});

test('CryptoJS AES-128 WordArray key -> aes-128-cbc (not 256) and self-tests', () => {
  const buildConfig = loadBuilder();
  const keyHex = '00112233445566778899aabbccddeeff'; // 16 bytes = AES-128  leakcheck:allow
  const ivHex = '0102030405060708090a0b0c0d0e0f10'; // leakcheck:allow
  const plain = '{"timeout":0,"useTimeout":false}';
  const ct = CryptoJS.AES.encrypt(plain, CryptoJS.enc.Hex.parse(keyHex), { iv: CryptoJS.enc.Hex.parse(ivHex) }).toString();
  const records = [{
    lib: 'cryptojs', op: 'encrypt', alg: { name: 'AES' }, padding: 'Pkcs7',
    key: { encoding: 'cryptojs', value: keyHex }, iv: { encoding: 'cryptojs', value: ivHex },
    input: { encoding: 'utf8', value: plain }, output: { encoding: 'cryptojs', value: ct }, frame: 'http://127.0.0.1:8088/',
  }];
  const cfg = buildConfig(records);
  const cid = Object.keys(cfg.ciphers)[0];
  assert.equal(cfg.ciphers[cid].alg, 'aes-128-cbc'); // the "Invalid key length" regression
  cfg.selftest = [{ cipher: cid, plain, ciphertext: ct }];
  const res = loadIntoEngine(cfg);
  assert.equal(res.error, undefined, res.error);
  assert.ok(res.selftest.every((t) => t.ok), JSON.stringify(res.selftest));
});

test('CryptoJS passphrase mode -> openssl-md5 kdf and self-tests', () => {
  const buildConfig = loadBuilder();
  const pass = 'secretpass';
  const plain = 'hello world';
  const ct = CryptoJS.AES.encrypt(plain, pass).toString(); // Salted__ blob
  assert.match(ct, /^U2FsdGVkX1/);
  const records = [{
    lib: 'cryptojs', op: 'encrypt', alg: { name: 'AES' }, padding: 'Pkcs7',
    key: { encoding: 'cryptojs', value: pass },
    input: { encoding: 'utf8', value: plain }, output: { encoding: 'cryptojs', value: ct }, frame: 'http://127.0.0.1:8088/',
  }];
  const cfg = buildConfig(records);
  const cid = Object.keys(cfg.ciphers)[0];
  assert.equal(cfg.ciphers[cid].kdf, 'openssl-md5');
  cfg.selftest = [{ cipher: cid, plain, ciphertext: ct }];
  const res = loadIntoEngine(cfg);
  assert.equal(res.error, undefined, res.error);
  assert.ok(res.selftest.every((t) => t.ok), JSON.stringify(res.selftest));
});

test('repeated captures of one field -> a single apply rule (no stacked re-encryption)', () => {
  const buildConfig = loadBuilder();
  const keyHex = '00112233445566778899aabbccddeeff'; // leakcheck:allow
  const ivHex = '0102030405060708090a0b0c0d0e0f10'; // leakcheck:allow
  const key = CryptoJS.enc.Hex.parse(keyHex);
  const iv = CryptoJS.enc.Hex.parse(ivHex);
  // A page encrypts $.data on every user action: same location, many different plaintexts.
  const plains = ['{"a":1}', '{"a":2}', '{"a":3,"b":"x"}', '{"a":4}'];
  const records = plains.map((plain) => ({
    lib: 'cryptojs', op: 'encrypt', alg: { name: 'AES' }, padding: 'Pkcs7',
    key: { encoding: 'cryptojs', value: keyHex }, iv: { encoding: 'cryptojs', value: ivHex },
    input: { encoding: 'utf8', value: plain },
    output: { encoding: 'cryptojs', value: CryptoJS.AES.encrypt(plain, key, { iv }).toString() },
    apply: { in: 'json', path: '$.data' }, frame: 'http://127.0.0.1:8088/',
  }));
  const cfg = buildConfig(records);

  // Exactly one rule for $.data — not one per capture (which would stack ciphers on encrypt).
  const dataRules = cfg.apply.request.filter((r) => r.in === 'json' && r.path === '$.data');
  assert.equal(dataRules.length, 1, JSON.stringify(cfg.apply.request));
  // Every capture became a selftest vector for that one cipher.
  assert.equal(cfg.selftest.length, plains.length);
  assert.ok(cfg.selftest.every((v) => v.cipher === dataRules[0].cipher));

  const res = loadIntoEngine(cfg);
  assert.equal(res.error, undefined, res.error);
  assert.ok(res.selftest.every((t) => t.ok), JSON.stringify(res.selftest));
});

test('captured hash/HMAC with a correlated location -> draft integrity rules', () => {
  const buildConfig = loadBuilder();
  const records = [
    // a hash token that landed in $.token
    { lib: 'cryptojs', op: 'hash', alg: { name: 'SHA256' }, input: { encoding: 'utf8', value: 'whatever' },
      output: { encoding: 'hex', value: 'deadbeef' }, apply: { in: 'json', path: '$.token' }, frame: 'http://127.0.0.1:8088/' },
    // an HMAC signature in the X-Sign header, with a captured key
    { lib: 'cryptojs', op: 'hmac', alg: { name: 'SHA256' }, key: { encoding: 'cryptojs', value: '00112233445566778899aabbccddeeff' }, // leakcheck:allow
      input: { encoding: 'utf8', value: 'body+ts' }, output: { encoding: 'hex', value: 'abcd' },
      apply: { in: 'header', name: 'X-Sign' }, frame: 'http://127.0.0.1:8088/' },
  ];
  const cfg = buildConfig(records);
  assert.equal(cfg.integrity.length, 2);
  const hash = cfg.integrity.find((r) => r.type === 'hash');
  assert.equal(hash.alg, 'sha256');
  assert.equal(JSON.stringify(hash.target), JSON.stringify({ in: 'json', path: '$.token' }));
  const hmac = cfg.integrity.find((r) => r.type === 'hmac');
  assert.equal(JSON.stringify(hmac.target), JSON.stringify({ in: 'header', name: 'X-Sign' }));
  assert.ok(hmac.key && cfg.keys[hmac.key], 'hmac key stored');
  // The draft loads into the real engine without error.
  const res = loadIntoEngine(cfg);
  assert.equal(res.error, undefined, res.error);
});

test('CryptoJS block mode and stream ciphers map correctly (not forced to CBC)', () => {
  const buildConfig = loadBuilder();
  const rec = (over) => ({ lib: 'cryptojs', op: 'encrypt', alg: { name: 'AES' },
    key: { encoding: 'cryptojs', value: '00112233445566778899aabbccddeeff' }, // leakcheck:allow
    input: { encoding: 'utf8', value: 'x' }, output: { encoding: 'cryptojs', value: 'ZZ' },
    frame: 'http://127.0.0.1:8088/', ...over });

  let cfg = buildConfig([rec({ mode: 'CTR' })]);
  let c = cfg.ciphers[Object.keys(cfg.ciphers)[0]];
  assert.equal(c.alg, 'aes-128-ctr');
  assert.equal(c.padding, undefined); // CTR/GCM carry no block padding

  cfg = buildConfig([rec({ alg: { name: 'RC4' } })]);
  c = cfg.ciphers[Object.keys(cfg.ciphers)[0]];
  assert.equal(c.alg, 'rc4');

  cfg = buildConfig([rec({ mode: 'ECB' })]);
  c = cfg.ciphers[Object.keys(cfg.ciphers)[0]];
  assert.equal(c.alg, 'aes-128-ecb');
});

test('correlated response location -> apply.response rule (deduped per location)', () => {
  const buildConfig = loadBuilder();
  const dec = (ct) => ({ lib: 'cryptojs', op: 'decrypt', alg: { name: 'AES' },
    key: { encoding: 'cryptojs', value: '00112233445566778899aabbccddeeff' }, // leakcheck:allow
    iv: { encoding: 'cryptojs', value: '0102030405060708090a0b0c0d0e0f10' }, // leakcheck:allow
    input: { encoding: 'cryptojs', value: ct }, output: { encoding: 'utf8', value: '{"ok":1}' },
    applyResponse: { in: 'json', path: '$.data' }, frame: 'http://127.0.0.1:8088/' });
  const cfg = buildConfig([dec('CT1'), dec('CT2')]); // same response field captured twice
  assert.equal(cfg.apply.response.length, 1);
  assert.equal(cfg.apply.response[0].path, '$.data');
  assert.equal(cfg.apply.request.length, 0);
  assert.ok(cfg.ciphers[cfg.apply.response[0].cipher], 'response cipher exists');
});

function write(cfg) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-cb-'));
  const file = path.join(dir, 'config.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  return { cfg: file, dir };
}

test('Send to Burp drops ciphers the capture could not complete, and the rest loads', () => {
  const sandbox = { window: {}, URL, Date };
  vm.runInNewContext(fs.readFileSync(path.join(HERE, '../config-builder.js'), 'utf8'), sandbox);
  const keyHex = Buffer.from(C_KEY).toString('hex');
  // Shape of the sample page after A + B + C: B's per-request AES-GCM key and RSA key are not capturable.
  const draft = {
    schemaVersion: 1, profile: 'p', scope: [{ host: '127.0.0.1', pathRegex: '.*', port: 8088 }],
    keys: { k1: { source: 'static', value: keyHex, encoding: 'hex' } },
    ciphers: {
      c1: { alg: 'aes-256-gcm', iv: { from: 'prefix', length: 12 }, tag: { length: 16 }, key: 'k1' },
      c3: { alg: 'rsa', padding: 'oaep', oaepHash: 'sha1' },
      c4: { alg: 'aes-256-gcm', iv: { from: 'prefix', length: 12 }, tag: { length: 16 } },
    },
    apply: { request: [{ in: 'body', cipher: 'c1' }, { in: 'json', path: '$.ek', cipher: 'c3' }, { in: 'json', path: '$.ct', cipher: 'c4' }],
             response: [{ in: 'json', path: '$.ct', cipher: 'c4' }] },
    integrity: [], selftest: [{ cipher: 'c4', plain: 'x', ciphertext: 'y' }],
  };
  const { cfg, skipped } = sandbox.window.loadableConfig(draft);
  assert.deepEqual(Object.keys(cfg.ciphers), ['c1']);
  assert.equal(skipped.length, 3);
  assert.match(skipped[0], /\$\.ek: RSA key not captured/);
  assert.equal(cfg.selftest.length, 0);
  assert.ok(draft.ciphers.c4, 'the Export draft is left untouched');
  assert.equal(loadIntoEngine(cfg).error, undefined, 'the trimmed profile loads in the real server');
});

test('whole-body and JSON-field endpoints on one host get pinned paths, load without the clobber warning, and route correctly', () => {
  const buildConfig = loadBuilder();
  const keyHex = Buffer.from('ct-sample-aes-key-0123456789abcd', 'utf8').toString('hex');
  const ivHex = Buffer.from('ct-sample-iv-016', 'utf8').toString('hex');
  const loginPlain = '{"id":"alice","pw":"pw1234"}';
  const loginCt = aesCbcEncrypt(loginPlain);
  const profPlain = '{"name":"Alice"}';
  const { iv, ct } = gcmEncrypt(C_KEY, profPlain, Buffer.alloc(12, 7));
  const profWire = Buffer.concat([iv, ct]).toString('base64');
  const records = [
    { lib: 'cryptojs', op: 'encrypt', alg: { name: 'AES' }, padding: 'Pkcs7', key: { encoding: 'cryptojs', value: keyHex },
      iv: { encoding: 'cryptojs', value: ivHex }, input: { encoding: 'utf8', value: loginPlain },
      output: { encoding: 'cryptojs', value: loginCt }, apply: { in: 'json', path: '$.data', at: '/api/login' }, frame: 'http://127.0.0.1:8088/' },
    { lib: 'webcrypto', op: 'encrypt', alg: { name: 'AES-GCM', iv: { encoding: 'base64', value: b64(iv) } },
      key: { encoding: 'base64', value: b64(C_KEY) }, input: { encoding: 'utf8', value: profPlain },
      output: { encoding: 'base64', value: profWire }, apply: { in: 'body', at: '/api/users/42/profile' }, frame: 'http://127.0.0.1:8088/' },
  ];
  const cfg = buildConfig(records);
  assert.equal(JSON.stringify(cfg.apply.request.map((r) => r.pathRegex)), JSON.stringify(['^/api/login$', '^/api/users/[^/]+/profile$']));
  assert.ok(!JSON.stringify(cfg).includes('"at"'), 'the captured path is not leaked as an unknown field');

  const { cfg: written, dir } = write(cfg);
  const eng = createEngine();
  const res = eng.handle({ op: 'load', files: [written] }).results[0];
  assert.equal(res.error, undefined, res.error);
  assert.ok(!(res.warnings || []).some((w) => /clobber/.test(w)), JSON.stringify(res.warnings));
  // the JSON rule touches only /api/login, the body rule only the profile endpoint
  const login = eng.handle({ op: 'decryptRequest', host: '127.0.0.1', port: 8088,
    request: { method: 'POST', path: '/api/login', headers: [], body: JSON.stringify({ data: loginCt }) } });
  assert.equal(JSON.stringify(JSON.parse(login.request.body).data), loginPlain);   // decrypted JSON is embedded as an object
  const prof = eng.handle({ op: 'decryptRequest', host: '127.0.0.1', port: 8088,
    request: { method: 'POST', path: '/api/users/7/profile', headers: [], body: profWire } });
  assert.equal(prof.request.body, JSON.stringify(JSON.parse(profPlain), null, 2)); // whole-body JSON is pretty-printed
  fs.rmSync(dir, { recursive: true, force: true });
});

test('WebCrypto RSA-OAEP with a captured key (spki or JWK) -> rsa cipher with its key, loads and round-trips', () => {
  const buildConfig = loadBuilder();
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = b64(publicKey.export({ type: 'spki', format: 'der' }));
  const ct = crypto.publicEncrypt({ key: publicKey, oaepHash: 'sha256' }, Buffer.from('secret')).toString('base64');
  const cfg = buildConfig([
    { lib: 'webcrypto', op: 'encrypt', alg: { name: 'RSA-OAEP' }, key: { encoding: 'base64', value: spki },
      input: { encoding: 'utf8', value: 'secret' }, output: { encoding: 'base64', value: ct },
      apply: { in: 'json', path: '$.ek' }, frame: 'https://api.shop.test/' },
  ]);
  const c = cfg.ciphers.c1;
  assert.equal(c.alg, 'rsa');
  assert.equal(c.padding, 'oaep');
  assert.ok(c.publicKey, 'publicKey filled from the capture');
  assert.equal(cfg.keys[c.publicKey].value, spki);
  assert.equal(c._note, undefined, 'no "add keys manually" note when the key was captured');
  const res = loadIntoEngine(cfg);
  assert.equal(res.error, undefined, res.error);

  // decrypt side with a JWK private key -> privateKey
  const jwk = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const cfg2 = buildConfig([
    { lib: 'webcrypto', op: 'decrypt', alg: { name: 'RSA-OAEP', hash: 'SHA-256' }, key: { encoding: 'jwk', value: jwk },
      input: { encoding: 'base64', value: ct }, output: { encoding: 'base64', value: b64(Buffer.from('secret')) }, frame: 'https://api.shop.test/' },
  ]);
  const c2 = cfg2.ciphers.c1;
  assert.equal(cfg2.keys[c2.privateKey].value, jwk);
  assert.equal(cfg2.keys[c2.privateKey].encoding, 'utf8');
  const res2 = loadIntoEngine(cfg2);
  assert.equal(res2.error, undefined, res2.error);
  assert.ok(res2.selftest.length && res2.selftest.every((t) => t.ok), JSON.stringify(res2.selftest));
});

test('a key that changes between captures at one location is flagged per-request and skipped on Send to Burp', () => {
  const sandbox = { window: {}, URL, Date };
  vm.runInNewContext(fs.readFileSync(path.join(HERE, '../config-builder.js'), 'utf8'), sandbox);
  const rec = (keyByte, ctx) => ({ lib: 'webcrypto', op: 'encrypt', alg: { name: 'AES-GCM' },
    key: { encoding: 'base64', value: b64(Buffer.alloc(32, keyByte)) }, input: { encoding: 'utf8', value: 'p' },
    output: { encoding: 'base64', value: ctx }, apply: { in: 'json', path: '$.ct' }, frame: 'https://api.shop.test/' });
  const cfg = sandbox.window.buildConfig([rec(1, 'AAAAAAAAAAAA'), rec(2, 'BBBBBBBBBBBB')]);
  assert.equal(Object.keys(cfg.ciphers).length, 1);
  assert.equal(cfg.ciphers.c1._perRequestKey, true);
  assert.equal(cfg.selftest.length, 1, 'only the vector made with the cipher key is kept');
  const { cfg: out, skipped } = sandbox.window.loadableConfig(cfg);
  assert.deepEqual(Object.keys(out.ciphers), []);
  assert.match(skipped[0], /key changes per request/);
});

test('jsbn RSAKey record (hex n/e[/d...]) -> rsa pkcs1 cipher with a JWK key, hex output; private half self-tests', () => {
  const buildConfig = loadBuilder();
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const pj = privateKey.export({ format: 'jwk' });
  const hex = (b64u) => Buffer.from(b64u, 'base64url').toString('hex').replace(/^0+/, ''); // BigInteger.toString(16) drops leading zeros
  const ct = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from('pw1234!')).toString('hex');
  const pubRec = { lib: 'jsbn', op: 'encrypt', alg: { name: 'RSA', padding: 'pkcs1' },
    key: { encoding: 'rsa-hex', value: JSON.stringify({ n: hex(pj.n), e: hex(pj.e) }) },
    input: { encoding: 'utf8', value: 'pw1234!' }, output: { encoding: 'hex', value: ct },
    apply: { in: 'form', name: 'encPw' }, frame: 'https://bank.example.test/login' };
  const cfg = buildConfig([pubRec]);
  const c = cfg.ciphers.c1;
  assert.deepEqual({ alg: c.alg, padding: c.padding, inEncoding: c.inEncoding, outEncoding: c.outEncoding },
    { alg: 'rsa', padding: 'pkcs1', inEncoding: 'utf8', outEncoding: 'hex' });
  const jwk = JSON.parse(cfg.keys[c.publicKey].value);
  assert.deepEqual({ kty: jwk.kty, n: jwk.n, e: jwk.e }, { kty: 'RSA', n: pj.n, e: pj.e });
  assert.equal(loadIntoEngine(cfg).error, undefined);

  // a key with the private fields (setPrivateEx) -> privateKey, and the captured vector self-tests
  const full = { ...pubRec, key: { encoding: 'rsa-hex', value: JSON.stringify({ n: hex(pj.n), e: hex(pj.e), d: hex(pj.d),
    p: hex(pj.p), q: hex(pj.q), dmp1: hex(pj.dp), dmq1: hex(pj.dq), coeff: hex(pj.qi) }) } };
  const cfg2 = buildConfig([full]);
  const c2 = cfg2.ciphers.c1;
  assert.ok(c2.privateKey, 'private fields -> privateKey');
  const res = loadIntoEngine(cfg2);
  assert.equal(res.error, undefined, res.error);
  assert.ok(res.selftest.length === 1 && res.selftest[0].ok, JSON.stringify(res.selftest));
});

test('a key the page generated (keySource generateKey) is per-request even when captured once', () => {
  const sandbox = { window: {}, URL, Date };
  vm.runInNewContext(fs.readFileSync(path.join(HERE, '../config-builder.js'), 'utf8'), sandbox);
  const cfg = sandbox.window.buildConfig([{ lib: 'webcrypto', op: 'encrypt', alg: { name: 'AES-GCM' }, keySource: 'generateKey',
    key: { encoding: 'base64', value: b64(Buffer.alloc(32, 3)) }, input: { encoding: 'utf8', value: 'p' },
    output: { encoding: 'base64', value: 'AAAAAAAAAAAA' }, apply: { in: 'json', path: '$.ct' }, frame: 'https://api.shop.test/' }]);
  assert.equal(cfg.ciphers.c1._perRequestKey, true);
  assert.match(cfg.ciphers.c1._note, /generated by the page/);
  const { skipped } = sandbox.window.loadableConfig(cfg);
  assert.match(skipped[0], /key changes per request/);
});

// What hook.js records for a WebCrypto AES call: output = ciphertext(+tag) bytes WITHOUT the IV.
function wcRecord(alg, key, iv, plain, extra) {
  const c = crypto.createCipheriv(`aes-256-${alg}`, key, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), alg === 'gcm' ? c.getAuthTag() : Buffer.alloc(0)]);
  return { lib: 'webcrypto', op: 'encrypt', alg: { name: `AES-${alg.toUpperCase()}` }, keySource: 'importKey',
    key: { encoding: 'base64', value: b64(key) }, iv: { encoding: 'base64', value: b64(iv) },
    input: { encoding: 'base64', value: b64(Buffer.from(plain)) }, output: { encoding: 'base64', value: b64(ct) },
    frame: 'https://api.shop.test/', ct, ...extra };
}

test('IV in its own field (ivApply) -> iv {from:"field"}; selftest vector carries the iv', () => {
  const buildConfig = loadBuilder();
  const rec = wcRecord('gcm', Buffer.alloc(32, 7), crypto.randomBytes(12), '{"amount":5}', {
    apply: { in: 'json', path: '$.ct' }, ivApply: { in: 'json', path: '$.iv', encoding: 'base64' } });
  const cfg = buildConfig([rec]);
  assert.deepEqual(JSON.parse(JSON.stringify(cfg.ciphers.c1.iv)), { from: 'field', in: 'json', path: '$.iv', encoding: 'base64' });
  assert.equal(JSON.stringify(cfg.apply.request[0]), JSON.stringify({ in: 'json', path: '$.ct', cipher: 'c1' }));
  assert.equal(cfg.selftest[0].iv, rec.iv.value);
  const res = loadIntoEngine(cfg);
  assert.equal(res.error, undefined, res.error);
  assert.deepEqual(res.selftest, [{ cipher: 'c1', ok: true }]);
});

test('IV prefixed on the wire (ivPrefix) -> iv {from:"prefix", length}; vector = iv || ciphertext', () => {
  const buildConfig = loadBuilder();
  const iv = crypto.randomBytes(16);
  const rec = wcRecord('cbc', Buffer.alloc(32, 8), iv, 'hello cbc', { apply: { in: 'body', ivPrefix: 16 } });
  const cfg = buildConfig([rec]);
  assert.deepEqual(JSON.parse(JSON.stringify(cfg.ciphers.c1.iv)), { from: 'prefix', length: 16 });
  assert.equal(JSON.stringify(cfg.apply.request[0]), JSON.stringify({ in: 'body', cipher: 'c1' }));
  assert.equal(cfg.selftest[0].ciphertext, b64(Buffer.concat([iv, rec.ct])));
  const res = loadIntoEngine(cfg);
  assert.deepEqual(res.selftest, [{ cipher: 'c1', ok: true }], JSON.stringify(res));
});

test('WebCrypto GCM with the default IV-prefix assumption still self-tests (vector includes the IV)', () => {
  const buildConfig = loadBuilder();
  const iv = crypto.randomBytes(12);
  const rec = wcRecord('gcm', Buffer.alloc(32, 9), iv, 'plain', { apply: { in: 'body' } });
  const res = loadIntoEngine(buildConfig([rec]));
  assert.deepEqual(res.selftest, [{ cipher: 'c1', ok: true }], JSON.stringify(res));
});

test('ciphertext re-encoded as hex on the wire (apply.encoding) -> outEncoding hex; vector in hex', () => {
  const buildConfig = loadBuilder();
  const iv = crypto.randomBytes(16);
  const rec = wcRecord('cbc', Buffer.alloc(32, 10), iv, 'hex wire', {
    apply: { in: 'form', name: 'encData', encoding: 'hex' }, ivApply: { in: 'form', name: 'encIv', encoding: 'hex' } });
  const cfg = buildConfig([rec]);
  assert.equal(cfg.ciphers.c1.outEncoding, 'hex');
  assert.equal(cfg.selftest[0].ciphertext, rec.ct.toString('hex'));
  assert.equal(cfg.selftest[0].iv, iv.toString('hex'));
  const res = loadIntoEngine(cfg);
  assert.deepEqual(res.selftest, [{ cipher: 'c1', ok: true }], JSON.stringify(res));
});
