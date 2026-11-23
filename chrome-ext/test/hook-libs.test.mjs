// End-to-end hook check against the REAL vendored libraries (not mock objects).
// hook.js is evaluated in this process, which installs getter/setter traps on globalThis for each
// known library. Loading the actual crypto-js / sjcl / forge bundles then triggers the installer via
// the trap, exactly as in the browser. We call each library's real crypto and assert hook.js captured
// a record with the right shape. This is the regression that proves the installers still match the
// libraries' public APIs — if an upgrade renames an entry point, a case here fails.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const VENDOR = path.join(ROOT, 'samples/public/vendor');
const read = (rel) => fs.readFileSync(path.join(VENDOR, rel), 'utf8');
const records = [];

before(() => {
  // hook.js emits one JSON line per captured call through this binding.
  globalThis.__cryptotrace_emit = (line) => { try { records.push(JSON.parse(line)); } catch (_) {} };
  // Install the hooks (defines globalThis getters/setters for CryptoJS/sjcl/forge).
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'chrome-ext/hook.js'), 'utf8'), { filename: 'hook.js' });
  // Load each real bundle. UMD in this global scope assigns globalThis.<Lib>, firing the trap setter.
  vm.runInThisContext(read('crypto-js-4.2.0.js'), { filename: 'crypto-js.js' });
  vm.runInThisContext(read('sjcl-1.0.8.js'), { filename: 'sjcl.js' });
  // The forge UMD bundle passes `window` as its root (the global object in a browser); shim it for forge only.
  globalThis.window = globalThis;
  vm.runInThisContext(read('forge-1.3.1.min.js'), { filename: 'forge.js' });
  delete globalThis.window;
});

const last = (lib, op) => [...records].reverse().find((r) => r.lib === lib && r.op === op);

test('crypto-js AES encrypt/decrypt is captured and still works', () => {
  const C = globalThis.CryptoJS;
  assert.ok(C && C.__ct_wrapped, 'crypto-js was detected and wrapped');
  const ct = C.AES.encrypt('secret message', 'pass phrase').toString();
  const back = C.AES.decrypt(ct, 'pass phrase').toString(C.enc.Utf8);
  assert.equal(back, 'secret message', 'library still decrypts correctly through the wrapper');
  const enc = last('cryptojs', 'encrypt');
  assert.ok(enc, 'encrypt captured');
  assert.equal(enc.alg.name, 'AES');
  assert.equal(enc.input.value, 'secret message');
  const dec = last('cryptojs', 'decrypt');
  assert.ok(dec, 'decrypt captured');
  // decrypt returns a WordArray: recorded as the UTF-8 text, not its hex string labelled utf8
  assert.deepEqual({ ...dec.output }, { encoding: 'utf8', value: 'secret message' });
  // a WordArray plaintext passed to encrypt is recorded the same way
  C.AES.encrypt(C.enc.Utf8.parse('wa input'), 'pass phrase');
  assert.deepEqual({ ...last('cryptojs', 'encrypt').input }, { encoding: 'utf8', value: 'wa input' });
});

test('sjcl encrypt/decrypt is captured and still works', () => {
  const S = globalThis.sjcl;
  assert.ok(S && S.__ct_wrapped, 'sjcl was detected and wrapped');
  S.random.addEntropy(new Array(64).fill(0x42), 512, 'test'); // deterministic seed so encrypt doesn't block
  const ct = S.encrypt('password', 'secret message');
  const back = S.decrypt('password', ct);
  assert.equal(back, 'secret message');
  const enc = last('sjcl', 'encrypt');
  assert.ok(enc, 'encrypt captured');
  assert.equal(enc.input.value, 'secret message');
  assert.equal(enc.key.value, 'password');
  assert.ok(last('sjcl', 'decrypt'), 'decrypt captured');
});

test('forge AES-CBC cipher is captured through start/update/finish', () => {
  const F = globalThis.forge;
  assert.ok(F && F.__ct_wrapped, 'forge was detected and wrapped');
  const key = '0123456789abcdef', iv = 'abcdef9876543210'; // 16-byte latin1 keys (no PRNG needed)
  const c = F.cipher.createCipher('AES-CBC', key);
  c.start({ iv });
  c.update(F.util.createBuffer('secret message'));
  c.finish();
  const ctHex = c.output.toHex();
  assert.ok(ctHex.length > 0);
  // round-trip through forge decipher to prove the wrapper didn't corrupt the stream
  const d = F.cipher.createDecipher('AES-CBC', key);
  d.start({ iv });
  d.update(F.util.createBuffer(F.util.hexToBytes(ctHex)));
  d.finish();
  assert.equal(d.output.toString(), 'secret message');
  const enc = last('forge', 'encrypt');
  assert.ok(enc, 'encrypt captured');
  assert.equal(enc.alg.name, 'AES-CBC');
  assert.equal(enc.input.value, 'secret message');
  assert.ok(enc.iv && enc.iv.value === iv, 'iv captured');
  assert.ok(last('forge', 'decrypt'), 'decrypt captured');
});

test('jsbn RSAKey declared as global functions (classic <script> include) is captured with its key', async () => {
  // Korean sites include Tom Wu's jsbn/rsa.js as plain scripts: `function RSAKey() {...}` at top level.
  // A global function declaration replaces hook.js's setter trap without calling it, so the hook has to
  // find RSAKey by sweeping globals after load. Unwrap the vendored copy's IIFE to get that exact shape.
  const src = read('jsbn-rsa-1.0.4.js').replace(/^\s*\(function\(\) \{/, '').replace(/\}\)\.call\(this\);\s*$/, '');
  vm.runInThisContext(src, { filename: 'rsa.js' });
  assert.equal(typeof globalThis.RSAKey, 'function', 'RSAKey is a global function');
  await new Promise((r) => setTimeout(r, 700)); // the hook's post-load sweep
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const jwk = publicKey.export({ format: 'jwk' });
  const hex = (b64u) => Buffer.from(b64u, 'base64url').toString('hex');
  const rsa = new globalThis.RSAKey();
  rsa.setPublic(hex(jwk.n), hex(jwk.e));
  const ct = rsa.encrypt('pw1234!');
  assert.equal(crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(ct, 'hex')).toString(), 'pw1234!',
    'library still encrypts correctly through the wrapper');
  const rec = last('jsbn', 'encrypt');
  assert.ok(rec, 'encrypt captured');
  assert.equal(rec.input.value, 'pw1234!');
  assert.deepEqual({ ...rec.output }, { encoding: 'hex', value: ct });
  const key = JSON.parse(rec.key.value);
  assert.equal(rec.key.encoding, 'rsa-hex');
  assert.equal(BigInt('0x' + key.n), BigInt('0x' + hex(jwk.n)));
  assert.equal(parseInt(key.e, 16), 65537);
  assert.equal(Object.keys(globalThis.RSAKey.prototype).includes('__ct_wrapped'), false, 'no enumerable marker on the prototype');
});

test('aes-js ModeOfOperation (CBC, CTR, CFB) is captured with key, per-call IV/counter, and still works', () => {
  vm.runInThisContext(read('aes-js-3.1.2.js'), { filename: 'aes-js.js' });
  const A = globalThis.aesjs;
  assert.ok(A && A.__ct_wrapped, 'aes-js was detected and wrapped');
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const padded = A.padding.pkcs7.pad(A.utils.utf8.toBytes('hello aes-js'));
  const ct = new A.ModeOfOperation.cbc([...key], [...iv]).encrypt(padded);
  const ref = crypto.createCipheriv('aes-256-cbc', key, iv);
  assert.equal(Buffer.from(ct).toString('hex'), Buffer.concat([ref.update('hello aes-js'), ref.final()]).toString('hex'), 'library output unchanged');
  const rec = last('aesjs', 'encrypt');
  assert.ok(rec, 'encrypt captured');
  assert.deepEqual({ ...rec.alg }, { name: 'AES', mode: 'cbc' });
  assert.equal(rec.key.value, key.toString('base64'));
  assert.equal(rec.iv.value, iv.toString('base64'));
  assert.equal(rec.input.value, Buffer.from(padded).toString('base64'));
  assert.equal(rec.output.value, Buffer.from(ct).toString('base64'));
  const back = new A.ModeOfOperation.cbc([...key], [...iv]).decrypt(ct);
  assert.equal(A.utils.utf8.fromBytes(A.padding.pkcs7.strip(back)), 'hello aes-js');
  assert.equal(last('aesjs', 'decrypt').output.value, Buffer.from(back).toString('base64'));

  const ctr = new A.ModeOfOperation.ctr([...key.subarray(0, 16)], new A.Counter(5));
  ctr.encrypt(A.utils.utf8.toBytes('counter mode'));
  const c = last('aesjs', 'encrypt');
  assert.equal(c.alg.mode, 'ctr');
  assert.equal(Buffer.from(c.iv.value, 'base64').toString('hex'), '00000000000000000000000000000005', 'initial counter block = OpenSSL CTR iv'); // leakcheck:allow

  new A.ModeOfOperation.cfb([...key], [...iv], 1).encrypt(A.utils.utf8.toBytes('cfb8'));
  assert.deepEqual({ ...last('aesjs', 'encrypt').alg }, { name: 'AES', mode: 'cfb', segmentSize: 1 });
});

test('Node-crypto API in a webpack module (crypto-browserify polyfill shape) is captured via createCipheriv', async () => {
  // webpack 4 injects crypto-browserify when app code does `import crypto from 'crypto'`; its exports have
  // Node's API. Node's own crypto stands in for it here, exported from a module in a webpack 5 chunk.
  globalThis.webpackChunkdemo_app = [];
  await new Promise((r) => setTimeout(r, 700)); // the hook's webpackChunk poll finds the array
  const factories = { 42: function (module) { module.exports = { createCipheriv: crypto.createCipheriv, createDecipheriv: crypto.createDecipheriv,
    createHash: crypto.createHash, randomBytes: crypto.randomBytes }; } };
  globalThis.webpackChunkdemo_app.push([[7], factories]); // queued before the runtime loads
  globalThis.webpackChunkdemo_app.push = function webpackJsonpCallback() {}; // the runtime installs its callback
  const module = { exports: {} };
  factories[42](module, module.exports); // webpack runs the (now wrapped) factory
  const C = module.exports;
  assert.ok(C.__ct_wrapped, 'module exports detected and wrapped');
  assert.ok(!globalThis.crypto.subtle.__ct_wrapped && typeof globalThis.crypto.createCipheriv === 'undefined', 'WebCrypto global untouched');

  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = C.createCipheriv('aes-256-cbc', key, iv);
  const ct = c.update('node api text', 'utf8', 'base64') + c.final('base64');
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  assert.equal(d.update(ct, 'base64', 'utf8') + d.final('utf8'), 'node api text', 'output unchanged');
  const rec = last('nodecrypto', 'encrypt');
  assert.ok(rec, 'encrypt captured');
  assert.equal(rec.alg.name, 'aes-256-cbc');
  assert.equal(rec.key.value, key.toString('base64'));
  assert.equal(rec.iv.value, iv.toString('base64'));
  assert.deepEqual({ ...rec.input }, { encoding: 'utf8', value: 'node api text' });
  assert.deepEqual({ ...rec.output }, { encoding: 'base64', value: ct });

  const iv12 = crypto.randomBytes(12);
  const g = C.createCipheriv('aes-256-gcm', key, iv12);
  const gct = Buffer.concat([g.update(Buffer.from('gcm bytes')), g.final()]);
  const tag = g.getAuthTag();
  const gr = last('nodecrypto', 'encrypt');
  assert.equal(gr.output.value, gct.toString('base64'));
  assert.equal(gr.tag.value, tag.toString('base64'), 'GCM tag recorded');

  const dd = C.createDecipheriv('aes-256-cbc', key, iv);
  dd.setAutoPadding(false);
  dd.update(Buffer.from(ct, 'base64'));
  dd.final();
  assert.equal(last('nodecrypto', 'decrypt').autoPadding, false);
});
