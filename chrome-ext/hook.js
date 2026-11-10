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
  const toB64 = (buf) => {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  };
  const enc = (v) => {
    if (v == null) return null;
    if (typeof v === 'string') return { encoding: 'utf8', value: v };
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) {
      return { encoding: 'base64', value: toB64(v instanceof ArrayBuffer ? v : v.buffer) };
    }
    return null;
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
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (subtle) {
    const keyInfo = new WeakMap(); // CryptoKey -> {alg, bytes?}
    wrap(subtle, 'importKey', (orig) => function (format, keyData, algorithm, extractable, usages) {
      const p = orig.apply(this, arguments);
      return p.then((key) => {
        const alg = typeof algorithm === 'string' ? { name: algorithm } : algorithm;
        keyInfo.set(key, { alg, key: format === 'raw' || format === 'pkcs8' || format === 'spki' ? enc(keyData) : null, format });
        send({ lib: 'webcrypto', op: 'importKey', alg, format, key: keyInfo.get(key).key, site: site() });
        return key;
      });
    });
    // Hashing (SubtleCrypto.digest) — integrity tokens are often built from a digest.
    wrap(subtle, 'digest', (orig) => function (algorithm, data) {
      const p = orig.apply(this, arguments);
      return p.then((out) => {
        send({ lib: 'webcrypto', op: 'digest', alg: typeof algorithm === 'string' ? { name: algorithm } : algorithm, input: enc(data), output: enc(out), site: site() });
        return out;
      });
    });
    for (const op of ['encrypt', 'decrypt', 'sign', 'verify']) {
      wrap(subtle, op, (orig) => function (algorithm, key, data) {
        const p = orig.apply(this, arguments);
        const info = keyInfo.get(key);
        const alg = typeof algorithm === 'string' ? { name: algorithm } : algorithm;
        return p.then((out) => {
          send({
            lib: 'webcrypto', op, alg,
            iv: alg && alg.iv ? enc(alg.iv) : null,
            key: info ? info.key : null,
            input: enc(data),
            output: op === 'verify' ? { encoding: 'bool', value: String(out) } : enc(out),
            site: site(),
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
        send({ lib: 'cryptojs', op: 'hash', alg: { name: h }, input: { encoding: 'utf8', value: String(message) }, output: { encoding: 'hex', value: String(out) }, site: site() });
        return out;
      });
    }
    for (const h of ['HmacSHA256', 'HmacSHA1', 'HmacSHA512', 'HmacMD5', 'HmacSHA224', 'HmacSHA384']) {
      if (typeof C[h] !== 'function') continue;
      wrap(C, h, (orig) => function (message, key) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'hmac', alg: { name: h.replace('Hmac', '') }, key: { encoding: 'cryptojs', value: String(key) }, input: { encoding: 'utf8', value: String(message) }, output: { encoding: 'hex', value: String(out) }, site: site() });
        return out;
      });
    }
    for (const algName of ['AES', 'DES', 'TripleDES', 'Rabbit', 'RC4', 'RC4Drop']) {
      const algo = C[algName];
      if (!algo || typeof algo.encrypt !== 'function') continue;
      wrap(algo, 'encrypt', (orig) => function (message, key, cfg) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'encrypt', alg: { name: algName }, key: { encoding: 'cryptojs', value: String(key) },
          iv: cfg && cfg.iv ? { encoding: 'cryptojs', value: String(cfg.iv) } : null,
          mode: cfg && cfg.mode && cfg.mode.name, padding: cfg && cfg.padding && cfg.padding.name,
          input: { encoding: 'utf8', value: String(message) }, output: { encoding: 'cryptojs', value: String(out) }, site: site() });
        return out;
      });
      wrap(algo, 'decrypt', (orig) => function (ciphertext, key, cfg) {
        const out = orig.apply(this, arguments);
        send({ lib: 'cryptojs', op: 'decrypt', alg: { name: algName }, key: { encoding: 'cryptojs', value: String(key) },
          iv: cfg && cfg.iv ? { encoding: 'cryptojs', value: String(cfg.iv) } : null,
          input: { encoding: 'cryptojs', value: String(ciphertext) }, output: { encoding: 'utf8', value: String(out) }, site: site() });
        return out;
      });
    }
  };
  // sjcl: high-level sjcl.encrypt(password, plaintext) / sjcl.decrypt(password, ciphertext).
  const installSjcl = (S) => {
    if (!S || S.__ct_wrapped || typeof S.encrypt !== 'function' || typeof S.decrypt !== 'function') return;
    S.__ct_wrapped = true;
    wrap(S, 'encrypt', (orig) => function (password, plaintext) {
      const out = orig.apply(this, arguments);
      send({ lib: 'sjcl', op: 'encrypt', alg: { name: 'AES' }, key: { encoding: 'utf8', value: String(password) },
        input: { encoding: 'utf8', value: String(plaintext) }, output: { encoding: 'utf8', value: String(out) }, site: site() });
      return out;
    });
    wrap(S, 'decrypt', (orig) => function (password, ciphertext) {
      const out = orig.apply(this, arguments);
      send({ lib: 'sjcl', op: 'decrypt', alg: { name: 'AES' }, key: { encoding: 'utf8', value: String(password) },
        input: { encoding: 'utf8', value: String(ciphertext) }, output: { encoding: 'utf8', value: String(out) }, site: site() });
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
        send({ lib: 'jsencrypt', op, alg: { name: 'RSA' }, input: { encoding: 'utf8', value: String(str) },
          output: out ? { encoding: 'utf8', value: String(out) } : null, site: site() });
        return out;
      });
    }
  });

  globalThis.__cryptotrace_ready = true;
})();
