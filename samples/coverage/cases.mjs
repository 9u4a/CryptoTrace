// Coverage lab: one case per real-world way a page encrypts what it sends. Every case states up front how far
// CryptoTrace SHOULD get (`expect`); scripts/coverage.mjs measures how far it does. All keys are fake.
//
// expect / status (best first):
//   auto          hooked automatically -> Burp decrypts the request and re-encryption is accepted
//   trace         no hookable API: found, traced, cipher identified by the server -> same as auto
//   encrypt-only  re-encryption accepted, but the plaintext can't be shown (public-key encryption)
//   skip          located, left out of Send to Burp with a reason (e.g. per-request key; needs the L4 oracle)
//   locate        the code that produced the ciphertext is located, nothing more
//   scan-only     only the constant scan points at the crypto code
//   none          nothing (out of scope: crypto not in page JS)
//
// client: a function serialized into the page; it must define window.__run(plain) -> Promise (sends once).
// decrypt(req, ctx): what the target server does -> the plaintext (throws if it rejects the request).
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const SEED = require('../public/vendor/kisa-seed-1.1.0.js').KISA_SEED_CBC;

const aes = (alg, key, iv, data, { padding = true } = {}) => {
  const d = crypto.createDecipheriv(alg, key, iv);
  d.setAutoPadding(padding);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
};
const gcm = (key, iv, data) => {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(data.subarray(data.length - 16));
  return Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]).toString('utf8');
};
const evp = (pass, salt) => { // OpenSSL EVP_BytesToKey(MD5), CryptoJS passphrase mode
  let d = Buffer.alloc(0), prev = Buffer.alloc(0);
  while (d.length < 48) { prev = crypto.createHash('md5').update(Buffer.concat([prev, Buffer.from(pass), salt])).digest(); d = Buffer.concat([d, prev]); }
  return { key: d.subarray(0, 32), iv: d.subarray(32, 48) };
};
const seedDec = (key, iv, data) => Buffer.from(SEED.SEED_CBC_Decrypt(Buffer.from(key), Buffer.from(iv), data, 0, data.length)).toString('utf8');
const b64 = (s) => Buffer.from(String(s), 'base64');
const rsaPkcs1 = (ctx, buf) => crypto.privateDecrypt({ key: ctx.rsa, padding: crypto.constants.RSA_PKCS1_PADDING }, buf).toString('utf8');
const post = (id) => `/cov/${id}/api`;

export const CASES = [
  // ---------------- L1: library APIs ----------------
  {
    id: 'cjs-cbc-json', group: 'library', title: 'CryptoJS AES-256-CBC, WordArray key/IV, JSON field', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-cjs-key-0123456789abcdef0123');
      const IV = CryptoJS.enc.Utf8.parse('cov-cjs-iv-01234');
      window.__run = async (plain) => {
        const data = CryptoJS.AES.encrypt(plain, K, { iv: IV }).toString();
        await fetch('/cov/cjs-cbc-json/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data, v: 1 }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', Buffer.from('cov-cjs-key-0123456789abcdef0123'), Buffer.from('cov-cjs-iv-01234'), b64(req.json().data)),
  },
  {
    id: 'cjs-passphrase', group: 'library', title: 'CryptoJS AES passphrase mode (OpenSSL Salted__), whole body', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      window.__run = async (plain) => {
        await fetch('/cov/cjs-passphrase/api', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: CryptoJS.AES.encrypt(plain, 'cov pass phrase').toString() });
      };
    },
    decrypt: (req) => { const raw = b64(req.body); const { key, iv } = evp('cov pass phrase', raw.subarray(8, 16)); return aes('aes-256-cbc', key, iv, raw.subarray(16)); },
  },
  {
    id: 'cjs-ecb-hex-form', group: 'library', title: 'CryptoJS AES-128-ECB, ciphertext sent as hex in a form field', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-ecb-key-0016');
      window.__run = async (plain) => {
        const enc = CryptoJS.AES.encrypt(plain, K, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).ciphertext.toString();
        await fetch('/cov/cjs-ecb-hex-form/api', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ user: 'u1', enc }).toString() });
      };
    },
    decrypt: (req) => aes('aes-128-ecb', Buffer.from('cov-ecb-key-0016'), null, Buffer.from(req.form().get('enc'), 'hex')),
  },
  {
    id: 'cjs-webpack-lazy', group: 'bundler', title: 'CryptoJS in a webpack 5 chunk loaded after the runtime', expect: 'auto',
    libs: ['/wp/runtime.js', '/wp/crypto-js-chunk.js'],
    client() {
      const C = window.__wpRequire(101);
      const K = C.enc.Utf8.parse('cov-wpl-key-0123456789abcdef0123');
      const IV = C.enc.Utf8.parse('cov-wpl-iv-01234');
      window.__run = async (plain) => {
        const data = C.AES.encrypt(plain, K, { iv: IV }).toString();
        await fetch('/cov/cjs-webpack-lazy/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', Buffer.from('cov-wpl-key-0123456789abcdef0123'), Buffer.from('cov-wpl-iv-01234'), b64(req.json().data)),
  },
  {
    id: 'cjs-webpack-vendor-first', group: 'bundler', title: 'CryptoJS in a webpack 5 vendor chunk loaded BEFORE the runtime (usual split)', expect: 'auto',
    libs: ['/wp/crypto-js-chunk.js', '/wp/runtime.js'],
    client() {
      const C = window.__wpRequire(101);
      const K = C.enc.Utf8.parse('cov-wpv-key-0123456789abcdef0123');
      const IV = C.enc.Utf8.parse('cov-wpv-iv-01234');
      window.__run = async (plain) => {
        const data = C.AES.encrypt(plain, K, { iv: IV }).toString();
        await fetch('/cov/cjs-webpack-vendor-first/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', Buffer.from('cov-wpv-key-0123456789abcdef0123'), Buffer.from('cov-wpv-iv-01234'), b64(req.json().data)),
  },
  {
    id: 'cjs-esm', group: 'bundler', title: 'CryptoJS inlined in an ES module (Vite/Rollup style, no global, no webpack)', expect: 'trace',
    module: true, prelude: "import CryptoJS from '/mod/crypto-js.mjs';",
    client() {
      const KEY = CryptoJS.enc.Utf8.parse('cov-esm-key-0123456789abcdef0123');
      const IV = CryptoJS.enc.Utf8.parse('cov-esm-iv-01234');
      function encryptPayload(text) { return CryptoJS.AES.encrypt(text, KEY, { iv: IV }).toString(); }
      window.__run = async (plain) => {
        await fetch('/cov/cjs-esm/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ payload: encryptPayload(plain) }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', Buffer.from('cov-esm-key-0123456789abcdef0123'), Buffer.from('cov-esm-iv-01234'), b64(req.json().payload)),
  },
  {
    id: 'wc-gcm-prefix', group: 'library', title: 'WebCrypto AES-256-GCM, static key, body = base64(iv || ct)', expect: 'auto',
    client() {
      const kp = crypto.subtle.importKey('raw', new TextEncoder().encode('cov-gcm-key-0123456789abcdef0123'), 'AES-GCM', false, ['encrypt']);
      const b64 = (u8) => btoa(String.fromCharCode(...u8));
      window.__run = async (plain) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await kp, new TextEncoder().encode(plain)));
        const all = new Uint8Array(12 + ct.length); all.set(iv); all.set(ct, 12);
        await fetch('/cov/wc-gcm-prefix/api', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: b64(all) });
      };
    },
    decrypt: (req) => { const raw = b64(req.body); return gcm(Buffer.from('cov-gcm-key-0123456789abcdef0123'), raw.subarray(0, 12), raw.subarray(12)); },
  },
  {
    id: 'wc-cbc-ivfield', group: 'library', title: 'WebCrypto AES-256-CBC, random IV in its own JSON field', expect: 'auto',
    client() {
      const kp = crypto.subtle.importKey('raw', new TextEncoder().encode('cov-cbc-key-0123456789abcdef0123'), 'AES-CBC', false, ['encrypt']);
      const b64 = (u8) => btoa(String.fromCharCode(...u8));
      window.__run = async (plain) => {
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, await kp, new TextEncoder().encode(plain)));
        await fetch('/cov/wc-cbc-ivfield/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ iv: b64(iv), ct: b64(ct) }) });
      };
    },
    decrypt: (req) => { const j = req.json(); return aes('aes-256-cbc', Buffer.from('cov-cbc-key-0123456789abcdef0123'), b64(j.iv), b64(j.ct)); },
  },
  {
    id: 'wc-ctr-query', group: 'library', title: 'WebCrypto AES-CTR (static counter), base64url ciphertext in a GET query', expect: 'auto',
    client() {
      const kp = crypto.subtle.importKey('raw', new TextEncoder().encode('cov-ctr-key-0016'), 'AES-CTR', false, ['encrypt']);
      const counter = new TextEncoder().encode('cov-ctr-counter!');
      const b64u = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      window.__run = async (plain) => {
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter, length: 64 }, await kp, new TextEncoder().encode(plain)));
        await fetch('/cov/wc-ctr-query/api?q=' + b64u(ct) + '&page=1');
      };
    },
    decrypt: (req) => aes('aes-128-ctr', Buffer.from('cov-ctr-key-0016'), Buffer.from('cov-ctr-counter!'), Buffer.from(req.query.get('q'), 'base64url')),
  },
  {
    id: 'wc-pbkdf2', group: 'library', title: 'WebCrypto PBKDF2-derived non-extractable AES-CBC key', expect: 'auto',
    client() {
      const enc = new TextEncoder();
      const kp = crypto.subtle.importKey('raw', enc.encode('cov password'), 'PBKDF2', false, ['deriveKey'])
        .then((base) => crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode('cov-salt'), iterations: 1000, hash: 'SHA-256' }, base, { name: 'AES-CBC', length: 256 }, false, ['encrypt']));
      const b64 = (u8) => btoa(String.fromCharCode(...u8));
      window.__run = async (plain) => {
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: enc.encode('cov-pbkdf2-iv-16') }, await kp, enc.encode(plain)));
        await fetch('/cov/wc-pbkdf2/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enc: b64(ct) }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', crypto.pbkdf2Sync('cov password', 'cov-salt', 1000, 32, 'sha256'), Buffer.from('cov-pbkdf2-iv-16'), b64(req.json().enc)),
  },
  {
    id: 'wc-envelope', group: 'library', title: 'WebCrypto RSA-OAEP envelope + fresh AES-GCM key per request', expect: 'skip',
    note: 'a new random key per request cannot be a fixed config: needs the live bridge / L4 oracle',
    client() {
      const b64 = (u8) => btoa(String.fromCharCode(...new Uint8Array(u8)));
      const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      window.__run = async (plain) => {
        const { spki } = await (await fetch('/cov/key')).json();
        const rsa = await crypto.subtle.importKey('spki', unb64(spki), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
        const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(plain));
        const ek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsa, await crypto.subtle.exportKey('raw', k));
        await fetch('/cov/wc-envelope/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ek: b64(ek), iv: b64(iv), ct: b64(ct) }) });
      };
    },
    decrypt: (req, ctx) => {
      const j = req.json();
      const key = crypto.privateDecrypt({ key: ctx.rsa, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, b64(j.ek));
      const ct = b64(j.ct);
      const d = crypto.createDecipheriv('aes-256-gcm', key, b64(j.iv)); d.setAuthTag(ct.subarray(ct.length - 16));
      return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8');
    },
  },
  {
    id: 'jsbn-form', group: 'library', title: 'jsbn RSAKey PKCS#1 v1.5 hex in a form field (Korean login pattern)', expect: 'encrypt-only',
    libs: ['/vendor/jsbn-rsa-1.0.4.js'],
    client() {
      window.__run = async (plain) => {
        const { n, e } = await (await fetch('/cov/key')).json();
        const rsa = new jsbn.RSAKey(); rsa.setPublic(n, e);
        await fetch('/cov/jsbn-form/api', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ id: 'u1', encPw: rsa.encrypt(plain) }).toString() });
      };
    },
    decrypt: (req, ctx) => rsaPkcs1(ctx, Buffer.from(req.form().get('encPw'), 'hex')),
  },
  {
    id: 'jsencrypt', group: 'library', title: 'JSEncrypt (setPublicKey PEM) base64 in a JSON field', expect: 'encrypt-only',
    libs: ['/vendor/jsencrypt-3.3.2.min.js'],
    client() {
      window.__run = async (plain) => {
        const { pem } = await (await fetch('/cov/key')).json();
        const j = new JSEncrypt(); j.setPublicKey(pem);
        await fetch('/cov/jsencrypt/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pw: j.encrypt(plain) }) });
      };
    },
    decrypt: (req, ctx) => rsaPkcs1(ctx, b64(req.json().pw)),
  },
  {
    id: 'forge-cbc', group: 'library', title: 'node-forge AES-CBC, base64 (forge.util.encode64) in a JSON field', expect: 'auto',
    libs: ['/vendor/forge-1.3.1.min.js'],
    client() {
      window.__run = async (plain) => {
        const c = forge.cipher.createCipher('AES-CBC', 'cov-forge-key-16');
        c.start({ iv: 'cov-forge-iv--16' });
        c.update(forge.util.createBuffer(plain, 'utf8'));
        c.finish();
        await fetch('/cov/forge-cbc/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ d: forge.util.encode64(c.output.getBytes()) }) });
      };
    },
    decrypt: (req) => aes('aes-128-cbc', Buffer.from('cov-forge-key-16'), Buffer.from('cov-forge-iv--16'), b64(req.json().d)),
  },
  {
    id: 'aesjs-ctr-hex', group: 'library', title: 'aes-js CTR (Counter 7), hex in a JSON field', expect: 'auto',
    libs: ['/vendor/aes-js-3.1.2.js'],
    client() {
      const key = aesjs.utils.utf8.toBytes('cov-aesjs-key-16');
      window.__run = async (plain) => {
        const ct = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(7)).encrypt(aesjs.utils.utf8.toBytes(plain));
        await fetch('/cov/aesjs-ctr-hex/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ x: aesjs.utils.hex.fromBytes(ct) }) });
      };
    },
    decrypt: (req) => aes('aes-128-ctr', Buffer.from('cov-aesjs-key-16'), Buffer.from('00000000000000000000000000000007', 'hex'), Buffer.from(req.json().x, 'hex')),
  },
  {
    id: 'xhr-header', group: 'transport', title: 'CryptoJS ciphertext sent by XMLHttpRequest in a header', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-xhr-key-0016');
      const IV = CryptoJS.enc.Utf8.parse('cov-xhr-iv--0016');
      window.__run = (plain) => new Promise((resolve) => {
        const x = new XMLHttpRequest();
        x.open('POST', '/cov/xhr-header/api');
        x.setRequestHeader('X-Enc', CryptoJS.AES.encrypt(plain, K, { iv: IV }).toString());
        x.onloadend = () => resolve();
        x.send('{}');
      });
    },
    decrypt: (req) => aes('aes-128-cbc', Buffer.from('cov-xhr-key-0016'), Buffer.from('cov-xhr-iv--0016'), b64(req.headers['x-enc'])),
  },
  {
    id: 'hmac-sign', group: 'integrity', title: 'CryptoJS AES field + X-Sign = HmacSHA256(field) checked by the server', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-sig-key-0016');
      const IV = CryptoJS.enc.Utf8.parse('cov-sig-iv--0016');
      window.__run = async (plain) => {
        const data = CryptoJS.AES.encrypt(plain, K, { iv: IV }).toString();
        const sign = CryptoJS.HmacSHA256(data, 'cov-hmac-secret').toString();
        await fetch('/cov/hmac-sign/api', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Sign': sign }, body: JSON.stringify({ data }) });
      };
    },
    decrypt: (req) => {
      const data = req.json().data;
      const want = crypto.createHmac('sha256', 'cov-hmac-secret').update(data).digest('hex');
      if (req.headers['x-sign'] !== want) throw new Error('bad signature');
      return aes('aes-128-cbc', Buffer.from('cov-sig-key-0016'), Buffer.from('cov-sig-iv--0016'), b64(data));
    },
  },

  // ---------------- L2/L3: no hookable API ----------------
  {
    id: 'seed-site', group: 'no-api', title: 'KISA SEED-CBC behind a site function, key/IV in script variables', expect: 'trace',
    libs: ['/shim/kisa-seed.js'],
    client() {
      const SEED_KEY = new TextEncoder().encode('cov-seed-key-016');
      const SEED_IV = new TextEncoder().encode('cov-seed-iv--016');
      const b64 = (u8) => btoa(String.fromCharCode(...u8));
      function encSeed(text) { const m = new TextEncoder().encode(text); return b64(window.KISA_SEED_CBC.SEED_CBC_Encrypt(SEED_KEY, SEED_IV, m, 0, m.length)); }
      window.__run = async (plain) => {
        await fetch('/cov/seed-site/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ encData: encSeed(plain) }) });
      };
    },
    decrypt: (req) => seedDec('cov-seed-key-016', 'cov-seed-iv--016', b64(req.json().encData)),
  },
  {
    id: 'seed-key-local', group: 'no-api', title: 'SEED with the key built inside the function on each call (local variable)', expect: 'trace',
    libs: ['/shim/kisa-seed.js'],
    client() {
      const b64 = (u8) => btoa(String.fromCharCode(...u8));
      function encryptField(text) {
        const key = new TextEncoder().encode(['cov', 'seed', 'local', 'k'].join('-'));
        const iv = new TextEncoder().encode('cov-local-iv-016');
        const m = new TextEncoder().encode(text);
        return b64(window.KISA_SEED_CBC.SEED_CBC_Encrypt(key, iv, m, 0, m.length));
      }
      window.__run = async (plain) => {
        await fetch('/cov/seed-key-local/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ f: encryptField(plain) }) });
      };
    },
    decrypt: (req) => seedDec('cov-seed-local-k', 'cov-local-iv-016', b64(req.json().f)),
  },
  {
    id: 'seed-class-method', group: 'no-api', title: 'SEED in a class method, key/IV on `this`', expect: 'trace',
    libs: ['/shim/kisa-seed.js'],
    client() {
      class CryptoService {
        constructor() { this.key = new TextEncoder().encode('cov-class-key-16'); this.iv = new TextEncoder().encode('cov-class-iv--16'); }
        encrypt(text) { const m = new TextEncoder().encode(text); return btoa(String.fromCharCode(...window.KISA_SEED_CBC.SEED_CBC_Encrypt(this.key, this.iv, m, 0, m.length))); }
      }
      const svc = new CryptoService();
      window.__run = async (plain) => {
        await fetch('/cov/seed-class-method/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ e: svc.encrypt(plain) }) });
      };
    },
    decrypt: (req) => seedDec('cov-class-key-16', 'cov-class-iv--16', b64(req.json().e)),
  },
  {
    id: 'aes-module-site', group: 'no-api', title: 'aes-js inlined in an ES module (no global), CBC + PKCS#7, hex, key in module scope', expect: 'trace',
    module: true, prelude: "import aesjs from '/mod/aes-js.mjs';",
    client() {
      const KEY = aesjs.utils.utf8.toBytes('cov-mod-key-0123456789abcdef0123');
      const IV = aesjs.utils.utf8.toBytes('cov-mod-iv--0016');
      const encryptBody = (text) => aesjs.utils.hex.fromBytes(new aesjs.ModeOfOperation.cbc(KEY, IV).encrypt(aesjs.padding.pkcs7.pad(aesjs.utils.utf8.toBytes(text))));
      window.__run = async (plain) => {
        await fetch('/cov/aes-module-site/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body: encryptBody(plain) }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', Buffer.from('cov-mod-key-0123456789abcdef0123'), Buffer.from('cov-mod-iv--0016'), Buffer.from(req.json().body, 'hex')),
  },
  {
    id: 'cjs-esm-wordarray', group: 'no-api', title: 'Same as cjs-esm (traced): key/IV are CryptoJS WordArrays, not bytes/strings', expect: 'trace',
    module: true, prelude: "import CryptoJS from '/mod/crypto-js.mjs';",
    client() {
      const KEY = CryptoJS.enc.Utf8.parse('cov-wa-key-0123456789abcdef01234');
      const IV = CryptoJS.enc.Utf8.parse('cov-wa-iv--01234');
      function seal(text) { return CryptoJS.AES.encrypt(text, KEY, { iv: IV }).toString(); }
      window.__run = async (plain) => {
        await fetch('/cov/cjs-esm-wordarray/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ s: seal(plain) }) });
      };
    },
    decrypt: (req) => aes('aes-256-cbc', Buffer.from('cov-wa-key-0123456789abcdef01234'), Buffer.from('cov-wa-iv--01234'), b64(req.json().s)),
  },
  {
    id: 'xor-custom', group: 'no-api', title: 'Home-made XOR + base64 "encryption" (no standard algorithm)', expect: 'encrypt-only',
    note: 'not a standard cipher: the page function itself re-encrypts edits (L4 oracle); the plaintext of captured traffic is not shown',
    client() {
      function scramble(text) { const b = new TextEncoder().encode(text); return btoa(String.fromCharCode(...b.map((x, i) => x ^ (0x5a + i) & 0xff))); }
      window.__run = async (plain) => {
        await fetch('/cov/xor-custom/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ z: scramble(plain) }) });
      };
    },
    decrypt: (req) => Buffer.from(b64(req.json().z).map((x, i) => x ^ (0x5a + i) & 0xff)).toString('utf8'),
  },
  {
    id: 'double-layer', group: 'transport', title: 'CryptoJS ciphertext wrapped in JSON, the whole JSON base64-encoded again', expect: 'locate',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    note: 'nested encodings around the ciphertext are not modelled by apply rules',
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-dbl-key-0016');
      const IV = CryptoJS.enc.Utf8.parse('cov-dbl-iv--0016');
      window.__run = async (plain) => {
        const inner = CryptoJS.AES.encrypt(plain, K, { iv: IV }).toString();
        await fetch('/cov/double-layer/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ wrapped: btoa(JSON.stringify({ d: inner, ts: 1 })) }) });
      };
    },
    decrypt: (req) => aes('aes-128-cbc', Buffer.from('cov-dbl-key-0016'), Buffer.from('cov-dbl-iv--0016'), b64(JSON.parse(b64(req.json().wrapped).toString()).d)),
  },
  // ---------------- round 2: harder real-world shapes ----------------
  {
    id: 'resp-cjs-body', group: 'response', title: 'Response: whole body CryptoJS AES-CBC, decrypted by the page', expect: 'auto', kind: 'response',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-rsp-key-0016');
      const IV = CryptoJS.enc.Utf8.parse('cov-rsp-iv--0016');
      window.__run = async (plain) => {
        const text = await (await fetch('/cov/resp-cjs-body/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ q: plain }) })).text();
        window.__last = JSON.parse(CryptoJS.AES.decrypt(text, K, { iv: IV }).toString(CryptoJS.enc.Utf8));
      };
    },
    decrypt: (req) => req.json().q,
    respond: (plain) => { const c = crypto.createCipheriv('aes-128-cbc', Buffer.from('cov-rsp-key-0016'), Buffer.from('cov-rsp-iv--0016'));
      return { type: 'text/plain', body: Buffer.concat([c.update(JSON.stringify({ echo: plain })), c.final()]).toString('base64') }; },
  },
  {
    id: 'resp-wc-json-iv', group: 'response', title: 'Response: WebCrypto AES-CBC {iv, data} JSON, decrypted by the page', expect: 'auto', kind: 'response',
    client() {
      const kp = crypto.subtle.importKey('raw', new TextEncoder().encode('cov-rsw-key-0123456789abcdef0123'), 'AES-CBC', false, ['decrypt']);
      const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      window.__run = async (plain) => {
        const j = await (await fetch('/cov/resp-wc-json-iv/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ q: plain }) })).json();
        const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: unb64(j.iv) }, await kp, unb64(j.data));
        window.__last = JSON.parse(new TextDecoder().decode(pt));
      };
    },
    decrypt: (req) => req.json().q,
    respond: (plain) => { const iv = crypto.randomBytes(16); const c = crypto.createCipheriv('aes-256-cbc', Buffer.from('cov-rsw-key-0123456789abcdef0123'), iv);
      return { type: 'application/json', body: JSON.stringify({ iv: iv.toString('base64'), data: Buffer.concat([c.update(JSON.stringify({ echo: plain })), c.final()]).toString('base64'), ok: true }) }; },
  },
  {
    id: 'session-handshake', group: 'library', title: 'Key handed out by a handshake per page session, then CryptoJS AES', expect: 'auto',
    note: 'valid for the captured session; a new session needs a re-capture or a session-key capture rule',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const keyP = fetch('/cov/session-handshake/key').then((r) => r.json());
      window.__run = async (plain) => {
        const { k, iv } = await keyP;
        const data = CryptoJS.AES.encrypt(plain, CryptoJS.enc.Base64.parse(k), { iv: CryptoJS.enc.Base64.parse(iv) }).toString();
        await fetch('/cov/session-handshake/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ data }) });
      };
    },
    decrypt: (req, ctx) => aes('aes-128-cbc', ctx.session.k, ctx.session.iv, b64(req.json().data)),
  },
  {
    id: 'hmac-ts', group: 'integrity', title: 'X-Sign = HmacSHA256(data + "|" + X-Ts) with a timestamp header', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-hts-key-0016');
      const IV = CryptoJS.enc.Utf8.parse('cov-hts-iv--0016');
      window.__run = async (plain) => {
        const data = CryptoJS.AES.encrypt(plain, K, { iv: IV }).toString();
        const ts = String(Date.now());
        const sign = CryptoJS.HmacSHA256(data + '|' + ts, 'cov-hts-secret').toString();
        await fetch('/cov/hmac-ts/api', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Ts': ts, 'X-Sign': sign }, body: JSON.stringify({ data }) });
      };
    },
    decrypt: (req) => {
      const data = req.json().data;
      const want = crypto.createHmac('sha256', 'cov-hts-secret').update(data + '|' + req.headers['x-ts']).digest('hex');
      if (req.headers['x-sign'] !== want) throw new Error('bad signature');
      return aes('aes-128-cbc', Buffer.from('cov-hts-key-0016'), Buffer.from('cov-hts-iv--0016'), b64(data));
    },
  },
  {
    id: 'multi-field', group: 'transport', title: 'Two fields in one request, different keys and libraries (CryptoJS CBC + aes-js CTR)', expect: 'auto', markers: 2,
    libs: ['/vendor/crypto-js-4.2.0.js', '/vendor/aes-js-3.1.2.js'],
    client() {
      const K1 = CryptoJS.enc.Utf8.parse('cov-mf1-key-0016');
      const IV1 = CryptoJS.enc.Utf8.parse('cov-mf1-iv--0016');
      const K2 = aesjs.utils.utf8.toBytes('cov-mf2-key-0016');
      window.__run = async (plain) => {
        const a = CryptoJS.AES.encrypt(plain, K1, { iv: IV1 }).toString();
        const b = aesjs.utils.hex.fromBytes(new aesjs.ModeOfOperation.ctr(K2, new aesjs.Counter(1)).encrypt(aesjs.utils.utf8.toBytes(plain)));
        await fetch('/cov/multi-field/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ a, b, n: 1 }) });
      };
    },
    decrypt: (req) => { const j = req.json();
      return aes('aes-128-cbc', Buffer.from('cov-mf1-key-0016'), Buffer.from('cov-mf1-iv--0016'), b64(j.a)) + ' | '
        + aes('aes-128-ctr', Buffer.from('cov-mf2-key-0016'), Buffer.from('00000000000000000000000000000001', 'hex'), Buffer.from(j.b, 'hex')); },
  },
  {
    id: 'cookie-token', group: 'transport', title: 'Ciphertext set with document.cookie and sent as a cookie', expect: 'auto',
    libs: ['/vendor/crypto-js-4.2.0.js'],
    client() {
      const K = CryptoJS.enc.Utf8.parse('cov-ck-key--0016');
      const IV = CryptoJS.enc.Utf8.parse('cov-ck-iv---0016');
      window.__run = async (plain) => {
        document.cookie = 'enc=' + encodeURIComponent(CryptoJS.AES.encrypt(plain, K, { iv: IV }).toString()) + '; path=/';
        await fetch('/cov/cookie-token/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"x":1}' });
      };
    },
    decrypt: (req) => {
      const c = Object.fromEntries(String(req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((p) => [p.split('=')[0], decodeURIComponent(p.slice(p.indexOf('=') + 1))]));
      return aes('aes-128-cbc', Buffer.from('cov-ck-key--0016'), Buffer.from('cov-ck-iv---0016'), b64(c.enc));
    },
  },
  {
    id: 'worker-seed', group: 'no-api', title: 'SEED inside a Web Worker that also sends the request (no hookable API)', expect: 'trace',
    client() {
      const w = new Worker('/cov/worker-seed/worker.js');
      window.__run = (plain) => new Promise((resolve) => { w.onmessage = () => resolve(); w.postMessage(plain); });
    },
    worker() {
      importScripts('/shim/kisa-seed.js');
      const WKEY = new TextEncoder().encode('cov-wrk-key--016');
      const WIV = new TextEncoder().encode('cov-wrk-iv---016');
      function sealInWorker(text) { const m = new TextEncoder().encode(text); return btoa(String.fromCharCode(...self.KISA_SEED_CBC.SEED_CBC_Encrypt(WKEY, WIV, m, 0, m.length))); }
      self.onmessage = async (e) => {
        await fetch('/cov/worker-seed/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ w: sealInWorker(e.data) }) });
        self.postMessage('done');
      };
    },
    decrypt: (req) => seedDec('cov-wrk-key--016', 'cov-wrk-iv---016', b64(req.json().w)),
  },
  {
    id: 'eval-obfuscated', group: 'no-api', title: 'SEED site code run through new Function (eval script, no URL), names mangled', expect: 'trace',
    libs: ['/shim/kisa-seed.js'],
    client() {
      const src = 'var _0x1=new TextEncoder().encode("cov-evl-key--016"),_0x2=new TextEncoder().encode("cov-evl-iv---016");'
        + 'window._0xe=function _0xe(t){var m=new TextEncoder().encode(t);'
        + 'return btoa(String.fromCharCode.apply(null,window.KISA_SEED_CBC.SEED_CBC_Encrypt(_0x1,_0x2,m,0,m.length)));};';
      new Function(src)();
      window.__run = async (plain) => {
        await fetch('/cov/eval-obfuscated/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ v: window._0xe(plain) }) });
      };
    },
    decrypt: (req) => seedDec('cov-evl-key--016', 'cov-evl-iv---016', b64(req.json().v)),
  },
  {
    id: 'native-agent', group: 'out-of-scope', title: 'Ciphertext produced outside page JS (security-module agent on localhost)', expect: 'none',
    note: 'the page only relays a value it received; no crypto runs in the browser',
    client() {
      window.__run = async (plain) => {
        const { ct } = await (await fetch('/cov/agent', { method: 'POST', body: plain })).json();
        await fetch('/cov/native-agent/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secure: ct }) });
      };
    },
    decrypt: (req) => aes('aes-128-cbc', Buffer.from('cov-agent-key-16'), Buffer.from('cov-agent-iv--16'), b64(req.json().secure)),
  },
];

export const RANK = ['none', 'scan-only', 'locate', 'skip', 'encrypt-only', 'trace', 'auto'];
