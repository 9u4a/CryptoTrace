// Runs the browser-side config-builder under a window shim, then checks the output
// loads and self-tests in the real server engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { createEngine } from '../../server/src/engine.mjs';
import { aesCbcEncrypt, gcmEncrypt, C_KEY } from '../../samples/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

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

function write(cfg) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-cb-'));
  const file = path.join(dir, 'config.json');
  fs.writeFileSync(file, JSON.stringify(cfg));
  return { cfg: file, dir };
}
