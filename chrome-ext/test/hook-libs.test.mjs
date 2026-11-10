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
  vm.runInThisContext(read('forge-1.3.1.min.js'), { filename: 'forge.js' });
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
  assert.ok(last('cryptojs', 'decrypt'), 'decrypt captured');
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
