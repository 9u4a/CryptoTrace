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
    const keyInfo = new WeakMap(); // CryptoKey -> { key: {encoding, value} }
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
      try { keyInfo.set(key, { key: await exportBytes(key) }); } catch (_) {}
    };
    const infoOf = async (key) => { await remember(key); const i = key && keyInfo.get(key); return i ? i.key : null; };
    // Produce a key the page asked for as non-extractable WITHOUT losing its bytes: make it extractable,
    // read the bytes, then import those bytes back with the page's own extractable flag and usages.
    // The page gets a key with the same algorithm/usages/extractable it requested. Any failure -> the
    // unmodified original call, so the page is never broken by this.
    const reimport = async (k, extractable) => {
      const bytes = await exportBytes(k);
      keyInfo.set(k, { key: bytes });
      if (extractable || k.type === 'public') return k; // public keys are always extractable
      const format = k.type === 'secret' ? 'raw' : 'pkcs8';
      const raw = Uint8Array.from(atob(bytes.value), (c) => c.charCodeAt(0));
      const again = await O.importKey.call(subtle, format, raw, k.algorithm, false, k.usages);
      keyInfo.set(again, { key: bytes });
      return again;
    };
    const capturing = (orig, self, args, extIdx, finish) => {
      const forced = Array.prototype.slice.call(args);
      const extractable = !!forced[extIdx];
      forced[extIdx] = true;
      return orig.apply(self, forced).then(async (out) => {
        const result = out && out.publicKey
          ? { publicKey: await reimport(out.publicKey, true), privateKey: await reimport(out.privateKey, extractable) }
          : await reimport(out, extractable);
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
        keyInfo.set(key, { key: keyMaterial(format, keyData) });
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
      return capturing(orig, this, arguments, 1, (k) =>
        send({ lib: 'webcrypto', op: 'generateKey', alg: algParams(algorithm), ...keyFields(k), site: where }));
    });
    // deriveKey(alg, baseKey, derivedAlg, extractable, usages): PBKDF2/HKDF/ECDH -> the cipher key.
    wrap(subtle, 'deriveKey', (orig) => function (algorithm, baseKey, derivedAlg) {
      const where = site();
      return capturing(orig, this, arguments, 3, (k) =>
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
      return capturing(orig, this, arguments, 5, (k) =>
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

  // Object-exporting crypto libraries. To add one: write an installer above and append
  // { name, detect, install } here — it is then hooked both as a global and inside webpack bundles.
  const isCryptoJS = (x) => x && x.AES && typeof x.AES.encrypt === 'function' && x.enc && x.lib;
  const isSjcl = (x) => x && typeof x.encrypt === 'function' && typeof x.decrypt === 'function' && x.cipher && x.codec;
  const isForge = (x) => x && x.cipher && typeof x.cipher.createCipher === 'function' && x.util && x.md;
  const LIBS = [
    { name: 'CryptoJS', detect: isCryptoJS, install: installCryptoJS },
    { name: 'sjcl', detect: isSjcl, install: installSjcl },
    { name: 'forge', detect: isForge, install: installForge },
  ];
  for (const l of LIBS) trapGlobal(l.name, l.install);

  // ---- bundled libraries (webpack) ---------------------------------------
  // Real apps bundle crypto-js inside webpack modules, off `window`. Intercept the
  // chunk loader, wrap each module factory, and when its exports look like a known
  // library, hook it with the same installer used for the global.
  const scanExports = (exp) => {
    if (!exp || typeof exp !== 'object') return;
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
