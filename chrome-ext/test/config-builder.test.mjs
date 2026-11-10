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

function write(cfg) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-cb-'));
  const file = path.join(dir, 'config.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  return { cfg: file, dir };
}
