// WebCrypto capture against Node's real SubtleCrypto (same API as the browser's).
// hook.js wraps globalThis.crypto.subtle in this process; each case calls the real API and checks the record.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const records = [];
const subtle = () => globalThis.crypto.subtle;
const last = (op) => [...records].reverse().find((r) => r.lib === 'webcrypto' && r.op === op);
const b64 = (u8) => Buffer.from(u8).toString('base64');

before(() => {
  globalThis.__cryptotrace_emit = (line) => { try { records.push(JSON.parse(line)); } catch (_) {} };
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'chrome-ext/hook.js'), 'utf8'), { filename: 'hook.js' });
});

const KEY = new Uint8Array(32).map((_, i) => i + 1);
const IV = new Uint8Array(12).map((_, i) => 0xa0 + i);

// Pages often use .then() chains (no await), where V8's async stack traces can't reach the caller from a
// promise callback. Call without await so the site must be captured synchronously at call time.
// A timer task with no awaiting async function anywhere in the chain, like an event handler on a page.
const viaThen = (fn) => new Promise((resolve, reject) => {
  setTimeout(function pageHandler() { fn().then((v) => setTimeout(() => resolve(v), 0), reject); }, 0);
});
test('call site points at the caller, not the promise callback', async () => {
  const k = await viaThen(() => subtle().importKey('raw', KEY, 'AES-GCM', false, ['encrypt']));
  assert.match(String(last('importKey').site && last('importKey').site.url), /hook-webcrypto\.test/);
  await viaThen(() => subtle().encrypt({ name: 'AES-GCM', iv: IV }, k, new TextEncoder().encode('hi')));
  assert.match(String(last('encrypt').site && last('encrypt').site.url), /hook-webcrypto\.test/);
  await viaThen(() => subtle().digest('SHA-256', new TextEncoder().encode('hi')));
  assert.match(String(last('digest').site && last('digest').site.url), /hook-webcrypto\.test/);
});

test('a TypedArray view records only its own bytes, not the whole backing buffer', async () => {
  const big = new Uint8Array(64).map((_, i) => i);
  const view = big.subarray(16, 48); // 32 bytes at offset 16
  const k = await subtle().importKey('raw', view, 'AES-CBC', false, ['encrypt']);
  assert.equal(last('importKey').key.value, b64(view));
  const iv = big.subarray(0, 16);
  await subtle().encrypt({ name: 'AES-CBC', iv }, k, big.subarray(48, 52));
  const rec = last('encrypt');
  assert.equal(rec.iv.value, b64(iv));
  assert.equal(rec.input.value, b64(big.subarray(48, 52)));
});

test('a symmetric JWK key is recorded as its raw bytes', async () => {
  const jwk = { kty: 'oct', k: Buffer.from(KEY).toString('base64url'), alg: 'A256GCM', ext: true };
  const k = await subtle().importKey('jwk', jwk, 'AES-GCM', false, ['encrypt']);
  assert.deepEqual({ ...last('importKey').key }, { encoding: 'base64', value: b64(KEY) });
  await subtle().encrypt({ name: 'AES-GCM', iv: IV }, k, new Uint8Array([1]));
  assert.equal(last('encrypt').key.value, b64(KEY));
});

test('an asymmetric JWK key is recorded as JWK', async () => {
  const pair = await subtle().generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const jwk = await subtle().exportKey('jwk', pair.publicKey);
  await subtle().importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  const rec = last('importKey');
  assert.equal(rec.key.encoding, 'jwk');
  assert.equal(JSON.parse(rec.key.value).n, jwk.n);
});

test('a non-extractable generated key still has its bytes captured, and stays non-extractable', async () => {
  const k = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  assert.equal(k.extractable, false, 'page still gets a non-extractable key');
  assert.deepEqual(k.usages.sort(), ['decrypt', 'encrypt']);
  const gen = last('generateKey');
  assert.ok(gen && gen.key && gen.key.encoding === 'base64', 'generateKey recorded with key bytes');
  assert.equal(Buffer.from(gen.key.value, 'base64').length, 32);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv: IV }, k, new TextEncoder().encode('per-request'));
  assert.equal(last('encrypt').key.value, gen.key.value, 'encrypt record carries the generated key');
  const pt = await subtle().decrypt({ name: 'AES-GCM', iv: IV }, k, ct);
  assert.equal(new TextDecoder().decode(pt), 'per-request', 'key still works');
  await assert.rejects(subtle().exportKey('raw', k), 'still non-extractable for the page');
  assert.equal(last('encrypt').keySource, 'generateKey', 'a page-generated (random) key is marked as such');
  const imported = await subtle().importKey('raw', KEY, 'AES-GCM', false, ['encrypt']);
  await subtle().encrypt({ name: 'AES-GCM', iv: IV }, imported, new Uint8Array([1]));
  assert.equal(last('encrypt').keySource, 'importKey');
});

test('a generated RSA key pair records both halves', async () => {
  const pair = await subtle().generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['encrypt', 'decrypt']);
  assert.equal(pair.privateKey.extractable, false);
  assert.equal(pair.publicKey.extractable, true, 'public keys are always extractable');
  const gen = last('generateKey');
  assert.equal(gen.publicKey.encoding, 'base64');
  assert.equal(gen.privateKey.encoding, 'base64');
  const ct = await subtle().encrypt({ name: 'RSA-OAEP' }, pair.publicKey, new Uint8Array([7]));
  assert.equal(last('encrypt').key.value, gen.publicKey.value);
  assert.deepEqual([...new Uint8Array(await subtle().decrypt({ name: 'RSA-OAEP' }, pair.privateKey, ct))], [7]);
});

test('a PBKDF2-derived key records its bytes and derivation parameters', async () => {
  const base = await subtle().importKey('raw', new TextEncoder().encode('password'), 'PBKDF2', false, ['deriveKey', 'deriveBits']);
  const salt = new Uint8Array(8).fill(9);
  const k = await subtle().deriveKey({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, base,
    { name: 'AES-CBC', length: 128 }, false, ['encrypt']);
  assert.equal(k.extractable, false);
  const d = last('deriveKey');
  assert.equal(d.alg.name, 'PBKDF2');
  assert.equal(d.alg.iterations, 1000);
  assert.equal(d.alg.salt.value, b64(salt));
  assert.equal(d.baseKey.value, b64(new TextEncoder().encode('password')));
  assert.equal(Buffer.from(d.key.value, 'base64').length, 16);
  await subtle().encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, k, new Uint8Array([1]));
  assert.equal(last('encrypt').key.value, d.key.value);
  const bits = await subtle().deriveBits({ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' }, base, 128);
  assert.equal(last('deriveBits').output.value, b64(new Uint8Array(bits)));
  assert.equal(last('deriveBits').output.value, d.key.value, 'same params -> same bytes');
});

test('unwrapKey records the unwrapped key bytes; wrapKey/exportKey are recorded', async () => {
  const kek = await subtle().generateKey({ name: 'AES-KW', length: 128 }, true, ['wrapKey', 'unwrapKey']);
  const inner = await subtle().importKey('raw', KEY, 'AES-GCM', true, ['encrypt']);
  const wrapped = await subtle().wrapKey('raw', inner, kek, 'AES-KW');
  const w = last('wrapKey');
  assert.equal(w.wrappedKey.value, b64(KEY));
  assert.equal(w.output.value, b64(new Uint8Array(wrapped)));
  const un = await subtle().unwrapKey('raw', wrapped, kek, 'AES-KW', 'AES-GCM', false, ['encrypt']);
  assert.equal(un.extractable, false);
  assert.equal(last('unwrapKey').key.value, b64(KEY));
  await subtle().exportKey('raw', inner);
  assert.equal(last('exportKey').key.value, b64(KEY));
});
