// Constant-signature scan (signatures.json + signatures.js).
// 1) every computable constant in the table is re-derived here from its definition, so a typo can't hide;
// 2) the scanner must find each algorithm in real implementations (hex, decimal and signed literals);
// 3) our own app code must not trigger strong findings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const VENDOR = path.join(ROOT, 'samples/public/vendor');
const SIGS = JSON.parse(fs.readFileSync(path.join(ROOT, 'chrome-ext/signatures.json'), 'utf8'));
const sandbox = { window: {} };
vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'chrome-ext/signatures.js'), 'utf8'), sandbox);
const { scanSource } = sandbox.window.CryptoTraceScan;
const sig = (id) => SIGS.find((s) => s.id === id) || assert.fail('no signature ' + id);
const nums = (s) => s.values.map((v) => Number(v));
const ids = (src) => [...new Set(scanSource(src, SIGS).map((f) => f.id))].sort();

// ---- reference derivations -------------------------------------------------
function aesSbox() {
  const mul = (a, b) => { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const hi = a & 0x80; a = (a << 1) & 0xff; if (hi) a ^= 0x1b; b >>= 1; } return p; };
  const inv = (x) => { if (!x) return 0; for (let y = 1; y < 256; y++) if (mul(x, y) === 1) return y; return 0; };
  const rot = (b, n) => ((b << n) | (b >> (8 - n))) & 0xff;
  const sbox = [];
  for (let x = 0; x < 256; x++) { const b = inv(x); sbox.push(b ^ rot(b, 1) ^ rot(b, 2) ^ rot(b, 3) ^ rot(b, 4) ^ 0x63); }
  return { sbox, mul };
}
// pi with BigInt (Machin): returns floor(pi * 2^bits)
function piScaled(bits) {
  const one = 1n << BigInt(bits + 32);
  const atanInv = (x) => { let sum = 0n, term = one / x, n = 1n, sign = 1n; const x2 = x * x; while (term) { sum += sign * (term / n); term /= x2; n += 2n; sign = -sign; } return sum; };
  return (16n * atanInv(5n) - 4n * atanInv(239n)) >> 32n;
}
const words = (bigFrac, bits, count) => Array.from({ length: count }, (_, i) => Number((bigFrac >> BigInt(bits - 32 * (i + 1))) & 0xffffffffn));

test('table constants match their mathematical definitions', () => {
  const { sbox, mul } = aesSbox();
  assert.deepEqual(nums(sig('aes-sbox')), sbox.slice(0, sig('aes-sbox').values.length));
  const invS = []; sbox.forEach((v, i) => { invS[v] = i; });
  assert.deepEqual(nums(sig('aes-inv-sbox')), invS.slice(0, sig('aes-inv-sbox').values.length));
  const te0 = [0, 1, 2, 3].map((x) => { const s = sbox[x]; return ((mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3)) >>> 0; });
  assert.deepEqual(nums(sig('aes-te0')), te0);
  const primes = [2, 3, 5, 7];
  assert.deepEqual(nums(sig('sha256-k')), primes.map((p) => Math.floor((Math.cbrt(p) % 1) * 2 ** 32)));
  assert.deepEqual(nums(sig('sha1-k')), [2, 3, 5, 10].map((n) => Math.floor(Math.sqrt(n) * 2 ** 30)));
  assert.deepEqual(nums(sig('md5-t')), [1, 2, 3, 4].map((i) => Math.floor(Math.abs(Math.sin(i)) * 2 ** 32)));
  const pi = piScaled(512); // floor(pi * 2^512)
  const fracPi = pi & ((1n << 512n) - 1n);
  assert.deepEqual(nums(sig('blowfish-p')), words(fracPi, 512, 4));
  const invPi = ((1n << 1024n) / pi) & ((1n << 512n) - 1n); // frac(1/pi) * 2^512
  assert.deepEqual(nums(sig('aria-ck')), words(invPi, 512, 12).slice(0, sig('aria-ck').values.length));
  const kc0 = Math.floor(2 ** 32 / ((1 + Math.sqrt(5)) / 2));
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  assert.deepEqual(nums(sig('seed-kc')), [0, 1, 2, 3].map((i) => rol(kc0, i)));
});

const read = (f) => fs.readFileSync(path.join(VENDOR, f), 'utf8');

test('finds each algorithm in real implementations (hex, decimal and signed literals)', () => {
  assert.ok(ids(read('korea-forge-seed-1.3.3.js')).includes('seed-ss0'), 'SEED, hex literals');
  assert.ok(ids(read('korea-forge-seed-1.3.3.js')).includes('seed-kc'));
  assert.ok(ids(read('kisa-seed-1.1.0.js')).includes('seed-ss0'), 'SEED, decimal literals');
  assert.ok(ids(read('sm-crypto-sm4-0.5.9.js')).includes('sm4-sbox'));
  assert.ok(ids(read('sm-crypto-sm4-0.5.9.js')).includes('sm4-fk'));
  const aesjs = ids(read('aes-js-3.1.2.js'));
  for (const id of ['aes-sbox', 'aes-inv-sbox', 'aes-te0']) assert.ok(aesjs.includes(id), 'aes-js ' + id);
  const forge = ids(read('forge-1.3.1.min.js'));
  for (const id of ['sha256-k', 'des-sp1']) assert.ok(forge.includes(id), 'forge ' + id + ' ' + forge);
  assert.ok(ids(read('jsbn-rsa-1.0.4.js')).includes('jsbn-rsa'));
  // MD5 written with signed decimal literals, the usual hand-written form
  assert.ok(ids('function ff(a){return a+-680876936}ff(-389564586);ff(606105819);ff(-1044525330);').includes('md5-t'));
});

test('reports line/col (0-based) of the match and a snippet', () => {
  const src = 'var a = 1;\nvar S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76];';
  const f = scanSource(src, SIGS).find((x) => x.id === 'aes-sbox');
  assert.equal(f.line, 1);
  assert.equal(f.col, src.split('\n')[1].indexOf('0x63'));
  assert.match(f.snippet, /0x63, 0x7c/);
  assert.equal(f.algo, 'AES');
});

test('a hex-string table and a custom base64 alphabet are found', () => {
  assert.ok(ids('var SB="637c777bf26b6fc53001672bfed7ab76ca82c97d";').includes('aes-sbox')); // AES S-box (public constant)  leakcheck:allow
  const custom = ids('var T = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/";'); // leakcheck:allow
  assert.ok(custom.includes('base64-custom'), custom);
  assert.ok(!ids('var T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";').includes('base64-custom')); // leakcheck:allow
});

test('no strong findings in ordinary app code', () => {
  for (const f of ['../app.js', '../worker.js']) {
    const strong = scanSource(read(f), SIGS).filter((x) => x.strength === 'strong');
    assert.equal(JSON.stringify(strong.map((x) => x.id)), '[]', f);
  }
});
