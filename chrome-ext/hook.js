// Injected into the page (and workers/iframes) before its own scripts run.
// Wraps the common crypto entry points and records each call: library, algorithm,
// key/iv material the page itself supplies, inputs, outputs, and the call site.
// Records are posted out via a CDP binding (preferred) or window.postMessage.
//
// This observes values the page already holds in order to encrypt; it adds no
// behaviour of its own. Use only against systems you are authorized to test.
(() => {
  'use strict';
  if (globalThis.__cryptotrace_hooked) return;
  globalThis.__cryptotrace_hooked = true;

  const CHANNEL = '__cryptotrace__';
  const send = (rec) => {
    try {
      rec.t = Date.now();
      rec.frame = (globalThis.location && globalThis.location.href) || '';
      const line = JSON.stringify(rec);
      if (typeof globalThis.__cryptotrace_emit === 'function') globalThis.__cryptotrace_emit(line);
      else if (typeof postMessage === 'function') postMessage({ [CHANNEL]: line }, '*');
    } catch (_) {
      /* a value wasn't serializable; drop this record rather than throw into the page */
    }
  };

  // ---- helpers -----------------------------------------------------------
  // A view covers only [byteOffset, byteOffset+byteLength) of its buffer -- never encode the whole buffer.
  const bytesOf = (v) => (v instanceof ArrayBuffer ? new Uint8Array(v)
    : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : null);
  const toB64 = (buf) => {
    const b = bytesOf(buf) || new Uint8Array(0);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  };
  const enc = (v) => {
    if (v == null) return null;
    if (typeof v === 'string') return { encoding: 'utf8', value: v };
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return { encoding: 'base64', value: toB64(v) };
    return null;
  };
  // null/undefined → "": libraries encrypt them as the empty string, so the selftest vector must match.
  const text = (v) => (v == null ? "" : String(v));
  // A CryptoJS WordArray stringifies to hex. Record it as the UTF-8 text it holds (what the page sees),
  // or as hex when the bytes aren't valid UTF-8 -- never hex labelled utf8 (breaks selftest vectors).
  const waText = (C, v) => {
    if (v && typeof v === 'object' && typeof v.sigBytes === 'number') {
      try {
        const u = v.toString(C.enc.Utf8);
        if (u || v.sigBytes === 0) return { encoding: 'utf8', value: u };
      } catch (_) { /* not UTF-8 */ }
      return { encoding: 'hex', value: String(v) };
    }
    return { encoding: 'utf8', value: text(v) };
  };
  const site = () => {
    const stack = (new Error().stack || '').split('\n').slice(2);
    for (const line of stack) {
      const m = line.match(/(https?:\/\/[^\s)]+?):(\d+):(\d+)/) || line.match(/((?:file|blob):[^\s)]+?):(\d+):(\d+)/);
      if (m) return { url: m[1], line: Number(m[2]), col: Number(m[3]) };
    }
    return null;
  };
  // ---- hook hiding (R4) --------------------------------------------------
  // A page that calls `fn.toString()` on a hooked API (or matches it against the
  // "[native code]" pattern) sees the ORIGINAL function source, not our wrapper.
  // Unmapped functions — everything the page itself defines — behave exactly as before.
  const fnSource = new WeakMap(); // our wrapper -> the function whose source it should mirror
  const hideFn = (wrapper, original) => {
    if (typeof wrapper === 'function') { try { fnSource.set(wrapper, original); } catch (_) {} }
    return wrapper;
  };
  (() => {
    const nativeToString = Function.prototype.toString;
    const patched = function toString() {
      const orig = fnSource.get(this);
      return nativeToString.call(orig !== undefined ? orig : this);
    };
    hideFn(patched, nativeToString); // the disguise disguises itself
    try {
      Object.defineProperty(Function.prototype, 'toString', { value: patched, writable: true, configurable: true });
    } catch (_) { /* toString not configurable here; skip hiding */ }
  })();

  const wrap = (obj, name, make) => {
    if (!obj || typeof obj[name] !== 'function') return;
    const original = obj[name];
    obj[name] = hideFn(make(original), original);
  };

  // ---- WebCrypto (SubtleCrypto) ------------------------------------------
  // Capture raw key bytes at importKey time (keys may be non-extractable later).
  // The call site is captured synchronously in every wrapper: inside a promise callback the page's frame
  // is gone from the stack (unless the page happens to `await`).
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (subtle) {
    const O = {}; // the real methods, for our own internal calls (which must not be recorded)
    for (const n of ['importKey', 'exportKey']) O[n] = subtle[n];
    const keyInfo = new WeakMap(); // CryptoKey -> { key: {encoding, value}, source: how the page got it }
    const b64urlToB64 = (s) => { const t = String(s).replace(/-/g, '+').replace(/_/g, '/'); return t + '='.repeat((4 - (t.length % 4)) % 4); };
    // Key material as the page supplied it. A symmetric JWK becomes its raw bytes (what every cipher spec
    // wants); an asymmetric JWK is kept whole.
    const keyMaterial = (format, data) => {
      if (format === 'jwk') {
        if (!data || typeof data !== 'object') return null;
        if (data.kty === 'oct' && typeof data.k === 'string') return { encoding: 'base64', value: b64urlToB64(data.k) };
        return { encoding: 'jwk', value: JSON.stringify(data) };
      }
      return enc(data);
    };
    const algOf = (a) => (typeof a === 'string' ? { name: a } : a);
    // Algorithm params as JSON: byte fields (iv/salt/info/label/...) encoded, a CryptoKey (ECDH `public`) as its bytes.
    const algParams = (a) => {
      a = algOf(a);
      if (!a || typeof a !== 'object') return a;
      const out = {};
      for (const k of Object.keys(a)) {
        const v = a[k];
        if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) out[k] = enc(v);
        else if (typeof CryptoKey !== 'undefined' && v instanceof CryptoKey) out[k] = (keyInfo.get(v) || {}).key || null;
        else if (v && typeof v === 'object') out[k] = algParams(v);
        else out[k] = v;
      }
      return out;
    };
    // Raw bytes of an extractable key, via the real exportKey (not recorded).
    const exportBytes = async (key) => {
      const format = key.type === 'secret' ? 'raw' : key.type === 'public' ? 'spki' : 'pkcs8';
      return { encoding: 'base64', value: toB64(await O.exportKey.call(subtle, format, key)) };
    };
    const remember = async (key) => {
      if (!key || keyInfo.has(key) || !key.extractable) return;
      try { keyInfo.set(key, { key: await exportBytes(key), source: 'unknown' }); } catch (_) {}
    };
    const infoOf = async (key) => { await remember(key); const i = key && keyInfo.get(key); return i ? i.key : null; };
    // Produce a key the page asked for as non-extractable WITHOUT losing its bytes: make it extractable,
    // read the bytes, then import those bytes back with the page's own extractable flag and usages.
    // The page gets a key with the same algorithm/usages/extractable it requested. Any failure -> the
    // unmodified original call, so the page is never broken by this.
    const reimport = async (k, extractable, source) => {
      const bytes = await exportBytes(k);
      keyInfo.set(k, { key: bytes, source });
      if (extractable || k.type === 'public') return k; // public keys are always extractable
      const format = k.type === 'secret' ? 'raw' : 'pkcs8';
      const raw = Uint8Array.from(atob(bytes.value), (c) => c.charCodeAt(0));
      const again = await O.importKey.call(subtle, format, raw, k.algorithm, false, k.usages);
      keyInfo.set(again, { key: bytes, source });
      return again;
    };
    const capturing = (orig, self, args, extIdx, source, finish) => {
      const forced = Array.prototype.slice.call(args);
      const extractable = !!forced[extIdx];
      forced[extIdx] = true;
      return orig.apply(self, forced).then(async (out) => {
        const result = out && out.publicKey
          ? { publicKey: await reimport(out.publicKey, true, source), privateKey: await reimport(out.privateKey, extractable, source) }
          : await reimport(out, extractable, source);
        finish(result);
        return result;
      }).catch(() => orig.apply(self, args)); // e.g. an algorithm that can't be exported -> plain call
    };
    const keyFields = (k) => (k && k.publicKey
      ? { publicKey: (keyInfo.get(k.publicKey) || {}).key || null, privateKey: (keyInfo.get(k.privateKey) || {}).key || null }
      : { key: (keyInfo.get(k) || {}).key || null });

    wrap(subtle, 'importKey', (orig) => function (format, keyData, algorithm) {
      const where = site();
      return orig.apply(this, arguments).then((key) => {
        keyInfo.set(key, { key: keyMaterial(format, keyData), source: 'importKey' });
        send({ lib: 'webcrypto', op: 'importKey', alg: algParams(algorithm), format, key: keyInfo.get(key).key, site: where });
        return key;
      });
    });
    wrap(subtle, 'exportKey', (orig) => function (format, key) {
      const where = site();
      return orig.apply(this, arguments).then((out) => {
        send({ lib: 'webcrypto', op: 'exportKey', format, alg: algParams(key && key.algorithm), key: keyMaterial(format, out), site: where });
        return out;
      });
    });
    // generateKey(alg, extractable, usages): per-request random keys (e.g. an RSA-wrapped AES session key).
    wrap(subtle, 'generateKey', (orig) => function (algorithm) {
      const where = site();
      return capturing(orig, this, arguments, 1, 'generateKey', (k) =>
        send({ lib: 'webcrypto', op: 'generateKey', alg: algParams(algorithm), ...keyFields(k), site: where }));
    });
    // deriveKey(alg, baseKey, derivedAlg, extractable, usages): PBKDF2/HKDF/ECDH -> the cipher key.
    wrap(subtle, 'deriveKey', (orig) => function (algorithm, baseKey, derivedAlg) {
      const where = site();
      return capturing(orig, this, arguments, 3, 'deriveKey', (k) =>
        send({ lib: 'webcrypto', op: 'deriveKey', alg: algParams(algorithm), baseKey: (keyInfo.get(baseKey) || {}).key || null,
          derivedAlg: algParams(derivedAlg), ...keyFields(k), site: where }));
    });
    wrap(subtle, 'deriveBits', (orig) => function (algorithm, baseKey, length) {
      const where = site();
      return orig.apply(this, arguments).then((out) => {
        send({ lib: 'webcrypto', op: 'deriveBits', alg: algParams(algorithm), baseKey: (keyInfo.get(baseKey) || {}).key || null,
          length, output: enc(out), site: where });
        return out;
      });
    });
    // wrapKey(format, key, wrappingKey, wrapAlg): the key being shipped, and its wrapped form.
    wrap(subtle, 'wrapKey', (orig) => function (format, key, wrappingKey, wrapAlg) {
      const where = site();
      return orig.apply(this, arguments).then(async (out) => {
        send({ lib: 'webcrypto', op: 'wrapKey', format, alg: algParams(wrapAlg), wrappedKey: await infoOf(key),
          key: await infoOf(wrappingKey), output: enc(out), site: where });
        return out;
      });
    });
    // unwrapKey(format, wrapped, unwrappingKey, unwrapAlg, unwrappedAlg, extractable, usages)
    wrap(subtle, 'unwrapKey', (orig) => function (format, wrapped, unwrappingKey, unwrapAlg, unwrappedAlg) {
      const where = site();
      return capturing(orig, this, arguments, 5, 'unwrapKey', (k) =>
        send({ lib: 'webcrypto', op: 'unwrapKey', format, alg: algParams(unwrapAlg), unwrappedAlg: algParams(unwrappedAlg),
          input: enc(wrapped), unwrappingKey: (keyInfo.get(unwrappingKey) || {}).key || null, ...keyFields(k), site: where }));
    });
    // Hashing (SubtleCrypto.digest) — integrity tokens are often built from a digest.
    wrap(subtle, 'digest', (orig) => function (algorithm, data) {
      const where = site();
      return orig.apply(this, arguments).then((out) => {
        send({ lib: 'webcrypto', op: 'digest', alg: algOf(algorithm), input: enc(data), output: enc(out), site: where });
        return out;
      });
    });
    for (const op of ['encrypt', 'decrypt', 'sign', 'verify']) {
      wrap(subtle, op, (orig) => function (algorithm, key, data) {
        const where = site();
        const alg = algOf(algorithm);
        return orig.apply(this, arguments).then(async (out) => {
          send({
            lib: 'webcrypto', op, alg: algParams(alg),
            iv: alg && alg.iv ? enc(alg.iv) : null,
            key: await infoOf(key), // a key we never saw created (e.g. from IndexedDB) is read now if extractable
            keySource: (keyInfo.get(key) || {}).source || null, // generateKey = random per use, not a fixed key
            input: enc(data),
            output: op === 'verify' ? { encoding: 'bool', value: String(out) } : enc(out),
            site: where,
          });
          return out;
        });
      });
    }
  }

  // ---- library globals installed later: trap the assignment --------------
  const trapGlobal = (name, install) => {
    if (globalThis[name]) { install(globalThis[name]); return; }
    let held;
    try {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        get: () => held,
        set: (v) => { held = v; try { install(v); } catch (_) {} },
      });
    } catch (_) { /* already non-configurable */ }
  };

  // CryptoJS: AES/DES/TripleDES/Rabbit/RC4 .encrypt/.decrypt. Reused for both the
  // global and any bundled copy found inside a webpack module.
  const installCryptoJS = (C) => {
    if (!C || C.__ct_wrapped) return;
    C.__ct_wrapped = true;
    // Hashes and HMACs: integrity tokens (e.g. a "token"/"sign" field) are usually built here.
    for (const h of ['SHA256', 'SHA1', 'SHA512', 'SHA224', 'SHA384', 'SHA3', 'MD5', 'RIPEMD160']) {
      if (typeof C[h] !== 'function') continue;
      wrap(C, h, (orig) => function (message) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'hash', alg: { name: h }, input: { encoding: 'utf8', value: text(message) }, output: { encoding: 'hex', value: text(out) }, site: site() });
        return out;
      });
    }
    for (const h of ['HmacSHA256', 'HmacSHA1', 'HmacSHA512', 'HmacMD5', 'HmacSHA224', 'HmacSHA384']) {
      if (typeof C[h] !== 'function') continue;
      wrap(C, h, (orig) => function (message, key) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'hmac', alg: { name: h.replace('Hmac', '') }, key: { encoding: 'cryptojs', value: text(key) }, input: { encoding: 'utf8', value: text(message) }, output: { encoding: 'hex', value: text(out) }, site: site() });
        return out;
      });
    }
    for (const algName of ['AES', 'DES', 'TripleDES', 'Rabbit', 'RC4', 'RC4Drop']) {
      const algo = C[algName];
      if (!algo || typeof algo.encrypt !== 'function') continue;
      wrap(algo, 'encrypt', (orig) => function (message, key, cfg) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'encrypt', alg: { name: algName }, key: { encoding: 'cryptojs', value: text(key) },
          iv: cfg && cfg.iv ? { encoding: 'cryptojs', value: text(cfg.iv) } : null,
          mode: cfg && cfg.mode && cfg.mode.name, padding: cfg && cfg.padding && cfg.padding.name,
          input: waText(C, message), output: { encoding: 'cryptojs', value: text(out) }, site: site() });
        return out;
      });
      wrap(algo, 'decrypt', (orig) => function (ciphertext, key, cfg) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'decrypt', alg: { name: algName }, key: { encoding: 'cryptojs', value: text(key) },
          iv: cfg && cfg.iv ? { encoding: 'cryptojs', value: text(cfg.iv) } : null,
          input: { encoding: 'cryptojs', value: text(ciphertext) }, output: waText(C, out), site: site() });
        return out;
      });
    }
  };
  // sjcl: high-level sjcl.encrypt(password, plaintext) / sjcl.decrypt(password, ciphertext).
  const installSjcl = (S) => {
    if (!S || typeof S !== 'object' || S.__ct_wrapped) return;
    if (typeof S.encrypt !== 'function' || typeof S.decrypt !== 'function') {
      // sjcl.js starts with `var sjcl = {cipher:{}, codec:{}, ...}` and attaches encrypt/decrypt later, so the
      // global trap sees an empty skeleton. Trap the two properties and install once both are assigned.
      if (S.__ct_pending) return;
      S.__ct_pending = true;
      const held = { encrypt: S.encrypt, decrypt: S.decrypt };
      for (const name of ['encrypt', 'decrypt']) {
        try {
          Object.defineProperty(S, name, {
            configurable: true,
            enumerable: true,
            get: () => held[name],
            set: (v) => {
              held[name] = v;
              if (typeof held.encrypt !== 'function' || typeof held.decrypt !== 'function') return;
              for (const n of ['encrypt', 'decrypt']) {
                Object.defineProperty(S, n, { value: held[n], writable: true, configurable: true, enumerable: true });
              }
              delete S.__ct_pending;
              try { installSjcl(S); } catch (_) {}
            },
          });
        } catch (_) { /* frozen object: nothing to hook */ }
      }
      return;
    }
    S.__ct_wrapped = true;
    wrap(S, 'encrypt', (orig) => function (password, plaintext) {
      const out = orig.apply(this, arguments);
      send({ lib: 'sjcl', op: 'encrypt', alg: { name: 'AES' }, key: { encoding: 'utf8', value: text(password) },
        input: { encoding: 'utf8', value: text(plaintext) }, output: { encoding: 'utf8', value: text(out) }, site: site() });
      return out;
    });
    wrap(S, 'decrypt', (orig) => function (password, ciphertext) {
      const out = orig.apply(this, arguments);
      send({ lib: 'sjcl', op: 'decrypt', alg: { name: 'AES' }, key: { encoding: 'utf8', value: text(password) },
        input: { encoding: 'utf8', value: text(ciphertext) }, output: { encoding: 'utf8', value: text(out) }, site: site() });
      return out;
    });
  };

  // node-forge: forge.cipher.createCipher/createDecipher(algorithm, key) -> streaming cipher.
  // Wrap the returned object's start/update/finish to capture iv, accumulated input and output.
  // forge ByteBuffers carry their raw bytes in `.data` (a binary/latin1 string).
  const forgeBytes = (v) => (v && v.data != null ? v.data : v == null ? '' : String(v));
  const installForge = (F) => {
    if (!F || F.__ct_wrapped || !F.cipher || typeof F.cipher.createCipher !== 'function') return;
    F.__ct_wrapped = true;
    const wrapFactory = (fnName, op) => wrap(F.cipher, fnName, (orig) => function (algorithm, key) {
      const cipher = orig.apply(this, arguments);
      try {
        let iv = null;
        const chunks = [];
        const oStart = cipher.start, oUpdate = cipher.update, oFinish = cipher.finish;
        cipher.start = function (opts) { if (opts && opts.iv != null) iv = forgeBytes(opts.iv); return oStart.apply(this, arguments); };
        cipher.update = function (buf) { try { chunks.push(forgeBytes(buf)); } catch (_) {} return oUpdate.apply(this, arguments); };
        cipher.finish = function () {
          const r = oFinish.apply(this, arguments);
          send({ lib: 'forge', op, alg: { name: String(algorithm) }, key: { encoding: 'latin1', value: forgeBytes(key) },
            iv: iv != null ? { encoding: 'latin1', value: iv } : null,
            input: { encoding: 'latin1', value: chunks.join('') }, output: { encoding: 'latin1', value: forgeBytes(this.output) }, site: site() });
          return r;
        };
      } catch (_) { /* leave the cipher usable even if wrapping fails */ }
      return cipher;
    });
    wrapFactory('createCipher', 'encrypt');
    wrapFactory('createDecipher', 'decrypt');
  };

  // jsbn (Tom Wu's rsa.js): `new RSAKey(); setPublic(nHex, eHex); encrypt(text)` -> PKCS#1 v1.5 hex.
  // Very common on Korean banking/public sites. The key lives on the instance as BigIntegers, so it is
  // read at call time and recorded as hex fields ({n, e[, d, p, q, dmp1, dmq1, coeff]}).
  const mark = (o) => { try { Object.defineProperty(o, '__ct_wrapped', { value: true }); } catch (_) {} };
  const jsbnKey = (k) => {
    const h = (b) => (b && typeof b.toString === 'function' ? b.toString(16) : null);
    const o = { n: h(k && k.n), e: k && typeof k.e === 'number' ? k.e.toString(16) : null };
    if (k && k.d) Object.assign(o, { d: h(k.d), p: h(k.p), q: h(k.q), dmp1: h(k.dmp1), dmq1: h(k.dmq1), coeff: h(k.coeff) });
    return { encoding: 'rsa-hex', value: JSON.stringify(o) };
  };
  const isRSAKey = (R) => typeof R === 'function' && R.prototype && typeof R.prototype.encrypt === 'function'
    && typeof R.prototype.setPublic === 'function';
  const installJsbnRSA = (R) => {
    if (!isRSAKey(R) || R.prototype.__ct_wrapped) return;
    const P = R.prototype;
    mark(P);
    wrap(P, 'encrypt', (orig) => function (msg) {
      const where = site();
      const out = orig.apply(this, arguments);
      send({ lib: 'jsbn', op: 'encrypt', alg: { name: 'RSA', padding: 'pkcs1' }, key: jsbnKey(this),
        input: { encoding: 'utf8', value: text(msg) }, output: out == null ? null : { encoding: 'hex', value: String(out) }, site: where });
      return out;
    });
    wrap(P, 'decrypt', (orig) => function (ctext) { // rsa2.js, when included
      const where = site();
      const out = orig.apply(this, arguments);
      send({ lib: 'jsbn', op: 'decrypt', alg: { name: 'RSA', padding: 'pkcs1' }, key: jsbnKey(this),
        input: { encoding: 'hex', value: text(ctext) }, output: out == null ? null : { encoding: 'utf8', value: String(out) }, site: where });
      return out;
    });
  };

  // aes-js: `new aesjs.ModeOfOperation.cbc(key, iv).encrypt(bytes)` (also ecb/ctr/cfb/ofb). No padding of its
  // own -- the page pads (aesjs.padding.pkcs7) before encrypting, so `input` is the padded bytes. The key
  // stays on the instance (`_aes.key`); the IV is read from the mode's chaining state just before each call,
  // which is exactly the IV that call uses (the constructor IV on the first call).
  const bytesEnc = (v) => {
    if (Array.isArray(v)) { try { return enc(Uint8Array.from(v)); } catch (_) { return null; } }
    return enc(v);
  };
  const aesjsIv = (m) => {
    if (!m) return null;
    if (m._lastCipherblock) return bytesEnc(m._lastCipherblock); // cbc
    if (m._shiftRegister) return bytesEnc(m._shiftRegister); // cfb
    if (m._lastPrecipher) return bytesEnc(m._lastPrecipher); // ofb
    if (m._counter && m._counter._counter) return bytesEnc(m._counter._counter); // ctr: the counter block
    return null; // ecb
  };
  const installAesjs = (A) => {
    if (!A || !A.ModeOfOperation || A.__ct_wrapped) return;
    mark(A);
    for (const mode of Object.keys(A.ModeOfOperation)) {
      const M = A.ModeOfOperation[mode];
      if (typeof M !== 'function' || !M.prototype) continue;
      for (const op of ['encrypt', 'decrypt']) {
        wrap(M.prototype, op, (orig) => function (data) {
          const where = site();
          const key = this._aes && this._aes.key ? bytesEnc(this._aes.key) : null;
          const iv = aesjsIv(this);
          const input = bytesEnc(data);
          const out = orig.apply(this, arguments);
          const alg = { name: 'AES', mode };
          if (mode === 'cfb' && this.segmentSize) alg.segmentSize = this.segmentSize;
          send({ lib: 'aesjs', op, alg, key, iv, input, output: bytesEnc(out), site: where });
          return out;
        });
      }
    }
  };

  // Node's crypto API as bundled for the browser (crypto-browserify, which webpack 4 injects for
  // `import crypto from 'crypto'`): createCipheriv(alg, key, iv) -> update()/final() streams. Strings keep
  // their encoding label; Buffers (Uint8Array subclasses) become base64. One record per stream, at final().
  const chunkJoin = (parts) => {
    if (!parts.length) return null;
    if (parts.every((p) => typeof p.v === 'string')) {
      const encs = new Set(parts.map((p) => p.e));
      return encs.size === 1 ? { encoding: parts[0].e, value: parts.map((p) => p.v).join('') } : null;
    }
    if (parts.some((p) => typeof p.v === 'string')) return null; // mixed string/bytes: not representable
    const len = parts.reduce((n, p) => n + p.v.byteLength, 0);
    const all = new Uint8Array(len);
    let o = 0;
    for (const p of parts) { all.set(bytesOf(p.v), o); o += p.v.byteLength; }
    return enc(all);
  };
  const piece = (v, e) => (v == null ? null : typeof v === 'string' ? { v, e: e || 'utf8' } : ArrayBuffer.isView(v) ? { v } : null);
  const installNodeCrypto = (X) => {
    if (!X || X.__ct_wrapped) return;
    mark(X);
    const factory = (fnName, op) => wrap(X, fnName, (orig) => function (algorithm, key, iv) {
      const where = site();
      const c = orig.apply(this, arguments);
      try {
        const ins = [], outs = [];
        let autoPadding = true, tag = null, aad = null;
        const keep = (list, p) => { if (p) list.push(p); };
        const w = (name, make) => { if (typeof c[name] === 'function') { const o = c[name]; c[name] = make(o); } };
        w('update', (o) => function (data, inEnc, outEnc) {
          keep(ins, piece(data, inEnc));
          const r = o.apply(this, arguments);
          keep(outs, piece(r, outEnc));
          return r;
        });
        w('setAutoPadding', (o) => function (on) { autoPadding = on !== false; return o.apply(this, arguments); });
        w('setAAD', (o) => function (buf) { aad = bytesEnc(buf); return o.apply(this, arguments); });
        w('setAuthTag', (o) => function (t) { tag = bytesEnc(t); return o.apply(this, arguments); });
        w('final', (o) => function (outEnc) {
          const r = o.apply(this, arguments);
          keep(outs, piece(r, outEnc));
          if (op === 'encrypt' && typeof this.getAuthTag === 'function') { try { tag = bytesEnc(this.getAuthTag()); } catch (_) {} }
          send({ lib: 'nodecrypto', op, alg: { name: String(algorithm).toLowerCase() }, key: bytesEnc(key) || (typeof key === 'string' ? { encoding: 'utf8', value: key } : null),
            iv: bytesEnc(iv) || (typeof iv === 'string' ? { encoding: 'utf8', value: iv } : null),
            input: chunkJoin(ins), output: chunkJoin(outs), autoPadding, tag, aad, site: where });
          return r;
        });
      } catch (_) { /* leave the stream usable even if wrapping fails */ }
      return c;
    });
    factory('createCipheriv', 'encrypt');
    factory('createDecipheriv', 'decrypt');
  };

  // Object-exporting crypto libraries. To add one: write an installer above and append
  // { name, detect, install } here — it is then hooked both as a global and inside webpack bundles.
  const isCryptoJS = (x) => x && x.AES && typeof x.AES.encrypt === 'function' && x.enc && x.lib;
  const isSjcl = (x) => x && typeof x.encrypt === 'function' && typeof x.decrypt === 'function' && x.cipher && x.codec;
  const isForge = (x) => x && x.cipher && typeof x.cipher.createCipher === 'function' && x.util && x.md;
  const LIBS = [
    { name: 'CryptoJS', detect: isCryptoJS, install: installCryptoJS },
    { name: 'sjcl', detect: isSjcl, install: installSjcl },
    { name: 'forge', detect: isForge, install: installForge },
    { name: 'RSAKey', detect: isRSAKey, install: installJsbnRSA },
    // no global name: only ever found as a bundled module's exports (a `crypto` global is WebCrypto)
    { name: null, detect: (x) => x && typeof x.createCipheriv === 'function' && typeof x.createDecipheriv === 'function'
      && typeof x.createHash === 'function' && typeof x.randomBytes === 'function', install: installNodeCrypto },
    { name: 'aesjs', detect: (x) => x && x.ModeOfOperation && typeof x.ModeOfOperation.cbc === 'function' && x.padding, install: installAesjs },
    { name: 'jsbn', detect: (x) => x && isRSAKey(x.RSAKey), install: (x) => installJsbnRSA(x.RSAKey) },
  ];
  for (const l of LIBS) if (l.name) trapGlobal(l.name, l.install);
  // A top-level `function RSAKey() {}` in a classic script REPLACES the trap above without calling its
  // setter (global function declarations redefine the property). So also sweep the globals once the page
  // has loaded its scripts, and a few more times while the webpack poll below runs.
  const sweepGlobals = () => {
    for (const l of LIBS) {
      if (!l.name) continue;
      try { const v = globalThis[l.name]; if (v && l.detect(v)) l.install(v); } catch (_) {}
    }
  };
  if (typeof addEventListener === 'function') {
    try { addEventListener('DOMContentLoaded', sweepGlobals); addEventListener('load', sweepGlobals); } catch (_) {}
  }

  // ---- bundled libraries (webpack) ---------------------------------------
  // Real apps bundle crypto-js inside webpack modules, off `window`. Intercept the
  // chunk loader, wrap each module factory, and when its exports look like a known
  // library, hook it with the same installer used for the global.
  const scanExports = (exp) => {
    if (!exp || (typeof exp !== 'object' && typeof exp !== 'function')) return; // a module may export a constructor
    for (const cand of [exp, exp.default]) for (const l of LIBS) if (l.detect(cand)) l.install(cand);
  };
  const wrapFactories = (modules) => {
    if (!modules || typeof modules !== 'object') return;
    for (const id of Object.keys(modules)) {
      const f = modules[id];
      if (typeof f !== 'function' || f.__ct_fw) continue;
      const wrapped = function (module, exports, require) {
        const r = f.apply(this, arguments);
        try { scanExports(module && module.exports); } catch (_) {}
        return r;
      };
      wrapped.__ct_fw = true;
      hideFn(wrapped, f);
      modules[id] = wrapped;
    }
  };
  // A loaded chunk is `[[chunkIds], modules, ...]`; modules is `{id: factory}`.
  const scanQueue = (arr) => { for (const item of arr) { try { wrapFactories(item && item[1]); } catch (_) {} } };
  const hookChunkArray = (arr) => {
    if (!arr || arr.__ct_push) return;
    arr.__ct_push = true;
    // Wrap only the callback webpack ASSIGNS to push. The getter must return a stable
    // reference (never a fresh closure), or webpack's saved old-push forms a call cycle.
    const wrapCb = (fn) => {
      if (typeof fn !== 'function' || fn.__ct_cb) return fn;
      const w = function (...items) {
        for (const item of items) { try { wrapFactories(item && item[1]); } catch (_) {} }
        return fn.apply(this, items);
      };
      w.__ct_cb = true;
      hideFn(w, fn);
      return w;
    };
    let current = arr.push; // native push now; webpack hasn't replaced it yet
    try {
      Object.defineProperty(arr, 'push', {
        configurable: true,
        enumerable: false,
        get: () => current,
        set: (fn) => { current = wrapCb(fn); scanQueue(arr); }, // webpack installs its callback here
      });
    } catch (_) {}
    scanQueue(arr); // chunks already queued before we hooked
  };
  // webpack 1 uses a function; 2/3 an array named `webpackJsonp`.
  const trapWebpackJsonp = () => {
    if (globalThis.webpackJsonp) {
      if (Array.isArray(globalThis.webpackJsonp)) hookChunkArray(globalThis.webpackJsonp);
      return;
    }
    let val;
    try {
      Object.defineProperty(globalThis, 'webpackJsonp', {
        configurable: true,
        get: () => val,
        set: (v) => {
          if (typeof v === 'function') {
            const orig = v;
            val = function (chunkIds, modules) { try { wrapFactories(modules); } catch (_) {} return orig.apply(this, arguments); };
          } else { if (Array.isArray(v)) hookChunkArray(v); val = v; }
        },
      });
    } catch (_) {}
  };
  trapWebpackJsonp();
  // webpack 4/5 use a per-build `webpackChunk<name>` array — poll briefly for it.
  let polls = 0;
  const chunkPoll = setInterval(() => {
    for (const k of Object.keys(globalThis)) {
      if (/^webpackChunk/.test(k) && Array.isArray(globalThis[k])) hookChunkArray(globalThis[k]);
    }
    sweepGlobals();
    if (++polls > 40) clearInterval(chunkPoll);
  }, 300);

  // JSEncrypt (RSA)
  trapGlobal('JSEncrypt', (J) => {
    const proto = J && J.prototype;
    for (const op of ['encrypt', 'decrypt']) {
      wrap(proto, op, (orig) => function (str) {
        const out = orig.apply(this, arguments);
        send({ lib: 'jsencrypt', op, alg: { name: 'RSA' }, input: { encoding: 'utf8', value: text(str) },
          output: out ? { encoding: 'utf8', value: text(out) } : null, site: site() });
        return out;
      });
    }
  });

  globalThis.__cryptotrace_ready = true;
})();
