'use strict';

/* Turn recorded crypto calls into a draft config.json for the CryptoTrace server.
 * Heuristic: the analyst reviews keys, encodings and scope before use. Produces
 * schemaVersion 1 (see server/src/profile.mjs). Exposed as window.buildConfig. */
(function () {
  // Key byte length drives AES-128/192/256 — the #1 cause of "Invalid key length" is
  // assuming 256 for what is really a 16-byte (128-bit) key.
  function hexByteLen(v) { const s = String(v || ''); return /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 ? s.length / 2 : 0; }
  function b64ByteLen(v) { const s = String(v || '').replace(/=+$/, ''); return Math.floor((s.length * 3) / 4); }
  function keyByteLen(k) {
    if (!k || k.value == null) return 0;
    return k.encoding === 'base64' ? b64ByteLen(k.value) : (hexByteLen(k.value) || 0);
  }
  function aesBits(bytes) { return bytes === 16 ? 128 : bytes === 24 ? 192 : bytes === 32 ? 256 : 256; }

  // WebCrypto algorithm object -> server cipher spec (alg + hints). Returns null if unknown.
  function webcryptoAlg(alg, keyBytes) {
    if (!alg || !alg.name) return null;
    const name = alg.name.toUpperCase();
    const bits = aesBits(keyBytes);
    if (name === 'AES-GCM') return { alg: `aes-${bits}-gcm`, iv: { from: 'prefix', length: 12 }, tag: { length: 16 } };
    if (name === 'AES-CBC') return { alg: `aes-${bits}-cbc`, padding: 'pkcs7' };
    if (name === 'AES-CTR') return { alg: `aes-${bits}-ctr` };
    if (name === 'RSA-OAEP') return { alg: 'rsa', padding: 'oaep', oaepHash: (alg.hash && (alg.hash.name || alg.hash)) ? String(alg.hash.name || alg.hash).replace('SHA-', 'sha').toLowerCase() : 'sha1' };
    return null;
  }

  function cryptojsAlg(rec, keyBytes) {
    // Passphrase mode: `AES.encrypt(plain, "string")` emits base64("Salted__"+salt+ct),
    // and key+IV come from OpenSSL EVP_BytesToKey — the server handles this via kdf.
    const out = String((rec.output && rec.output.value) || '');
    const io = { inEncoding: 'utf8', outEncoding: 'base64' };
    if (/^U2FsdGVkX1/.test(out)) {
      return { alg: 'aes-256-cbc', kdf: 'openssl-md5', ...io, _passphrase: true };
    }
    const name = (rec.alg && rec.alg.name) || 'AES';
    // Stream ciphers: no block mode / IV / padding.
    if (name === 'RC4' || name === 'RC4Drop') {
      return { alg: 'rc4', ...io, ...(name === 'RC4Drop' ? { _note: 'RC4Drop drops leading keystream; verify against target' } : {}) };
    }
    if (name === 'Rabbit') {
      return { custom: 'custom/rabbit.js', ...io, _note: 'Rabbit is not in OpenSSL; provide custom/rabbit.js or replace this cipher' };
    }
    // Honor the captured block mode instead of forcing CBC (hook.js records cfg.mode.name).
    const mode = String(rec.mode || 'CBC').toLowerCase();
    const modeOk = ['cbc', 'cfb', 'ofb', 'ctr', 'ecb', 'gcm'].includes(mode) ? mode : 'cbc';
    const pad = String(rec.padding || 'Pkcs7').toLowerCase();
    const padding = pad.includes('pkcs') ? 'pkcs7' : pad.includes('zero') ? 'zero' : 'none';
    if (name === 'DES') return { alg: `des-${modeOk === 'ecb' ? 'ecb' : 'cbc'}`, padding, ...io };
    if (name === 'TripleDES') return { alg: `des-ede3-${modeOk === 'ecb' ? 'ecb' : 'cbc'}`, padding, ...io };
    const spec = { alg: `aes-${aesBits(keyBytes)}-${modeOk}`, ...io }; // WordArray key + explicit IV
    if (modeOk !== 'gcm' && modeOk !== 'ctr') spec.padding = padding;
    return spec;
  }

  // WebCrypto hands plaintext over as bytes (recorded base64). The server's selftest compares text, so a
  // plaintext that is valid UTF-8 becomes that text; anything else yields no vector. Self-contained (no
  // atob/TextDecoder) so it runs the same in the panel and in the test sandbox.
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; // base64 alphabet, not a key  leakcheck:allow
  function b64Bytes(s) {
    const t = String(s).replace(/=+$/, '');
    const out = [];
    let acc = 0, bits = 0;
    for (const ch of t) {
      const v = B64.indexOf(ch);
      if (v < 0) return null;
      acc = (acc << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    return out;
  }
  function utf8Text(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length;) {
      const b = bytes[i];
      const n = b < 0x80 ? 0 : (b & 0xe0) === 0xc0 ? 1 : (b & 0xf0) === 0xe0 ? 2 : (b & 0xf8) === 0xf0 ? 3 : -1;
      if (n < 0 || i + n > bytes.length - 1) return null; // invalid lead byte / truncated sequence
      let cp = n ? b & (0x3f >> n) : b;
      for (let j = 1; j <= n; j++) { const c = bytes[i + j]; if ((c & 0xc0) !== 0x80) return null; cp = (cp << 6) | (c & 0x3f); }
      if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) return null; // control bytes: not text
      s += String.fromCodePoint(cp);
      i += n + 1;
    }
    return s;
  }
  // Hex (BigInteger.toString(16): no leading zeros, maybe odd length) -> unpadded base64url, for JWK fields.
  function hexToB64url(h) {
    let t = String(h || '').replace(/^0+(?=.)/, '');
    if (t.length % 2) t = '0' + t;
    let out = '', acc = 0, bits = 0;
    for (let i = 0; i < t.length; i += 2) {
      acc = (acc << 8) | parseInt(t.slice(i, i + 2), 16); bits += 8;
      while (bits >= 6) { bits -= 6; out += B64[(acc >> bits) & 63]; }
      acc &= (1 << bits) - 1;
    }
    if (bits) out += B64[(acc << (6 - bits)) & 63];
    return out.replace(/\+/g, '-').replace(/\//g, '_');
  }
  // Bytes of a recorded binary value (base64/hex), or null.
  function recBytes(v) {
    if (!v || v.value == null) return null;
    if (v.encoding === 'base64') return b64Bytes(v.value);
    if (v.encoding === 'hex' && /^[0-9a-fA-F]*$/.test(v.value) && v.value.length % 2 === 0) {
      const out = [];
      for (let i = 0; i < v.value.length; i += 2) out.push(parseInt(v.value.slice(i, i + 2), 16));
      return out;
    }
    return null;
  }
  function encodeBytes(bytes, enc) {
    if (enc === 'hex') return bytes.map((b) => (b < 16 ? '0' : '') + b.toString(16)).join('');
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
      const k = Math.min(3, bytes.length - i);
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (k > 1 ? B64[(n >> 6) & 63] : '=') + (k > 2 ? B64[n & 63] : '=');
    }
    return enc === 'base64url' ? out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : out;
  }
  // The ciphertext as it travels (what the server's decrypt sees) for a selftest vector: the cipher's
  // outEncoding, with the IV in front when the spec says so. Falls back to the recorded text.
  function wireCiphertext(spec, ct, iv, tag) {
    const bytes = recBytes(ct);
    if (!bytes) return ct.value;
    const ivb = recBytes(iv);
    const prefix = spec.iv && spec.iv.from === 'prefix' && ivb ? ivb : [];
    const tagb = recBytes(tag) || []; // an AEAD tag read separately (Node API): the server expects ct || tag
    const enc = spec.outEncoding || 'base64';
    if (!prefix.length && !tagb.length && enc === ct.encoding) return ct.value;
    return encodeBytes(prefix.concat(bytes, tagb), enc);
  }
  function asText(v) {
    if (!v) return null;
    if (v.encoding === 'utf8') return String(v.value);
    if (v.encoding !== 'base64') return null;
    const bytes = b64Bytes(v.value);
    return bytes ? utf8Text(bytes) : null;
  }

  // PKCS#7 pad length at the end of `bytes` (1..16), or 0 if it isn't PKCS#7-padded.
  function pkcs7Len(bytes) {
    if (!bytes || !bytes.length || bytes.length % 16) return 0;
    const n = bytes[bytes.length - 1];
    if (n < 1 || n > 16) return 0;
    for (let i = bytes.length - n; i < bytes.length; i++) if (bytes[i] !== n) return 0;
    return n;
  }
  // aes-js: mode from the record; the page pads by itself, so PKCS#7 is read off the padded plaintext.
  function aesjsAlg(r, keyBytes) {
    const mode = String((r.alg && r.alg.mode) || 'cbc').toLowerCase();
    const seg = r.alg && r.alg.segmentSize;
    const m = mode === 'cfb' ? (seg === 1 ? 'cfb8' : seg === 16 ? 'cfb' : null) : mode;
    if (!['cbc', 'ecb', 'ctr', 'cfb', 'cfb8', 'ofb'].includes(m)) return null;
    const spec = { alg: `aes-${aesBits(keyBytes)}-${m}`, inEncoding: 'utf8', outEncoding: 'base64' };
    if (m === 'cbc' || m === 'ecb') spec.padding = pkcs7Len(recBytes(r.op === 'encrypt' ? r.input : r.output)) ? 'pkcs7' : 'none';
    else spec.padding = 'none'; // stream modes
    return spec;
  }
  // Node's crypto API (crypto-browserify): the algorithm name is already an OpenSSL name (or the old
  // `aes256`-style alias for CBC). Ciphertext encoding = whatever the page asked update()/final() for.
  function nodecryptoAlg(r) {
    let name = String((r.alg && r.alg.name) || '').toLowerCase();
    const alias = name.match(/^aes(128|192|256)$/);
    if (alias) name = `aes-${alias[1]}-cbc`;
    if (!name) return null;
    const ct = r.op === 'encrypt' ? r.output : r.input;
    const spec = { alg: name, inEncoding: 'utf8', outEncoding: ct && ct.encoding !== 'utf8' ? ct.encoding : 'base64' };
    if (!/-(gcm|ctr|ccm|ocb|cfb\d*|ofb)$/.test(name) && name !== 'chacha20-poly1305') spec.padding = r.autoPadding === false ? 'none' : 'pkcs7';
    if (r.tag) spec._note = 'GCM: the selftest assumes the tag follows the ciphertext -- check how the page sends it';
    return spec;
  }
  // node-forge: createCipher('AES-CBC' | 'AES-ECB' | 'AES-CTR' | '3DES-CBC' ..., key). Bytes arrive base64;
  // forge pads CBC/ECB with PKCS#7 itself.
  function forgeAlg(r, keyBytes) {
    const m = String((r.alg && r.alg.name) || '').toUpperCase().match(/^(AES|3DES|DES)-(CBC|ECB|CTR|CFB|OFB|GCM)$/);
    if (!m) return null;
    const mode = m[2].toLowerCase();
    const alg = m[1] === 'AES' ? `aes-${aesBits(keyBytes)}-${mode}` : m[1] === '3DES' ? `des-ede3-${mode}` : `des-${mode}`;
    const spec = { alg, inEncoding: 'utf8', outEncoding: 'base64' };
    if (mode === 'cbc' || mode === 'ecb') spec.padding = 'pkcs7';
    if (mode === 'gcm') spec._note = 'forge GCM: the tag is read separately (cipher.mode.tag) -- check how the page sends it';
    return spec;
  }

  // A traced page function (tracer.js): its algorithm is unknown, so the cipher becomes an `identify` grid --
  // every block cipher that fits the byte-sized values found in its scopes -- and the server keeps the
  // combination that reproduces the captured calls (server/src/identify.mjs).
  function candLen(v) {
    if (!v || v.value == null) return 0;
    if (v.encoding === 'base64') { const b = b64Bytes(v.value); return b ? b.length : 0; }
    if (v.encoding === 'utf8') return unescape(encodeURIComponent(String(v.value))).length;
    return 0;
  }
  function tracedSpec(r) {
    const i = r.input, o = r.output;
    if (!i || !o || o.value == null || i.value === o.value) return null; // an encoding step (bytes -> base64), not a cipher
    if (!r.apply && !r.applyResponse) return null; // its result never reached a request: nothing to configure
    if (o.encoding !== 'utf8' && o.encoding !== 'base64') return null; // e.g. a JSON object / Promise: not ciphertext
    const ct = String(o.value);
    const outEncoding = /^[0-9a-fA-F]+$/.test(ct) && ct.length % 2 === 0 ? 'hex'
      : /[-_]/.test(ct) && !/[+/]/.test(ct) ? 'base64url' : 'base64';
    const lens = new Set((r.candidates || []).map((c) => candLen(c.value)));
    const algs = [];
    for (const n of [16, 24, 32]) {
      if (!lens.has(n)) continue;
      const bits = n * 8;
      for (const m of ['cbc', 'ecb', 'ctr', 'cfb', 'ofb']) algs.push(`aes-${bits}-${m}`);
      algs.push(`aria-${bits}-cbc`, `aria-${bits}-ecb`);
      if (n === 16) algs.push('seed-cbc', 'seed-ecb');
    }
    const where = r.site ? `${String(r.site.url).split('/').pop()}:${r.site.line}` : '';
    return { identify: { algs, keys: [], ivs: [], paddings: ['pkcs7', 'zero', 'none'], inEncoding: 'utf8', outEncoding }, _traced: true,
      _note: `traced ${r.fn}() ${where}: algorithm/key/IV chosen by the server from scope candidates (see load result "identified")` };
  }

  // Plaintext text for a selftest vector: aes-js plaintext still carries the page's PKCS#7 padding.
  function plainOf(r, spec) {
    const pv = r.op === 'decrypt' ? r.output : r.input;
    if (r.lib === 'aesjs' && spec.padding === 'pkcs7') {
      const b = recBytes(pv);
      const n = pkcs7Len(b);
      return n ? utf8Text(b.slice(0, b.length - n)) : null;
    }
    return asText(pv);
  }

  // Guess byte-encoding of a captured key/iv string.
  function keyEntry(obj) {
    if (!obj) return null;
    if (obj.encoding === 'base64') return { source: 'static', value: obj.value, encoding: 'base64' };
    if (obj.encoding === 'cryptojs') {
      const v = String(obj.value);
      if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return { source: 'static', value: v, encoding: 'hex' };
      return { source: 'static', value: v, encoding: 'utf8' };
    }
    return { source: 'static', value: String(obj.value), encoding: 'utf8' };
  }

  function hostFromFrame(frame) {
    try {
      const u = new URL(frame);
      const port = u.port ? Number(u.port) : null;
      return JSON.stringify({ host: u.hostname, port });
    } catch (_) { return ''; }
  }

  // /api/users/123/profile -> ^/api/users/[^/]+/profile$ (IDs, UUIDs and long hex become one segment).
  function pathRegexFor(p) {
    const seg = (s) => (/^\d+$/.test(s) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(s) || /^[0-9a-f]{16,}$/i.test(s))
      ? '[^/]+' : s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return '^' + String(p).split('/').map(seg).join('/') + '$';
  }

  window.buildConfig = function buildConfig(records) {
    const cfg = {
      schemaVersion: 1,
      profile: 'captured-' + new Date().toISOString().slice(0, 10),
      scope: [],
      keys: {},
      ciphers: {},
      apply: { request: [], response: [] },
      integrity: [],
      selftest: [],
      _notes: [
        'Draft produced by CryptoTrace capture. REVIEW before use:',
        '- confirm key lengths/encodings (aes-256 vs 128), IV handling, and padding',
        '- CryptoJS string keys use EVP key derivation unless a WordArray key+iv is passed',
        '- set scope host/pathRegex to the real endpoints',
      ],
    };

    const hosts = new Set();
    let ci = 0;
    // One cipher + one rule per apply location. A page re-encrypts the same field on
    // every user action, so the same $.data is captured many times over a session.
    // Emitting a rule per capture makes the server stack encryption layers on re-encrypt
    // (each adds ~1.33x via base64 -> NN-fold body blow-up and a broken request). The
    // first capture at a location defines the cipher; later ones only add selftest vectors.
    // A location (in|path|name) can be used by several endpoints. Per side: location -> [{id, at, keyVal, rule}].
    // Same endpoint -> same cipher (a different key there = a per-request key); another endpoint with the same
    // key -> shares that cipher and rule; another endpoint with another key -> its own cipher, and every rule at
    // that location is then pinned to its endpoint (pathRegex) so each request gets the right one.
    const locs = { request: new Map(), response: new Map() };
    const keyValOf = new Map(); // cipher id -> the key value of the capture that defined it
    const locKeyOf = (a) => (a ? `${a.in}|${a.path || ''}|${a.name || ''}` : null);
    const findLoc = (side, a, keyVal) => {
      const list = (a && locs[side].get(locKeyOf(a))) || [];
      const sameAt = list.find((e) => e.at === a.at);
      if (sameAt) return { e: sameAt, sameAt: true };
      const sameKey = keyVal != null && list.find((e) => e.keyVal === keyVal);
      return sameKey ? { e: sameKey, sameAt: false } : null;
    };
    const keyNameFor = (entry) => {
      const sig = JSON.stringify(entry);
      for (const [n, e] of Object.entries(cfg.keys)) if (JSON.stringify(e) === sig) return n;
      const name = 'k' + (Object.keys(cfg.keys).length + 1);
      cfg.keys[name] = entry;
      return name;
    };

    const wsNotes = new Set();
    for (const r of records) {
      if (r.lib === 'transport' || (r.op !== 'encrypt' && r.op !== 'decrypt' && !(r.lib === 'traced' && r.op === 'call'))) continue; // traced call = plaintext in, ciphertext out
      if (r.frame) hosts.add(hostFromFrame(r.frame));
      let spec = null;
      const keyBytes = keyByteLen(r.key);
      if (r.lib === 'webcrypto') spec = webcryptoAlg(r.alg, keyBytes);
      else if (r.lib === 'cryptojs') spec = cryptojsAlg(r, keyBytes);
      else if (r.lib === 'jsencrypt') spec = { alg: 'rsa', padding: 'pkcs1', inEncoding: 'utf8', outEncoding: 'base64' };
      else if (r.lib === 'aesjs') spec = aesjsAlg(r, keyBytes);
      else if (r.lib === 'nodecrypto') spec = nodecryptoAlg(r);
      else if (r.lib === 'forge') spec = forgeAlg(r, keyBytes);
      else if (r.lib === 'traced') spec = tracedSpec(r);
      else if (r.lib === 'jsbn') spec = { alg: 'rsa', padding: 'pkcs1', inEncoding: 'utf8', outEncoding: 'hex' };
      if (!spec) continue;

      // Reuse the cipher already chosen for this apply location (request or response) instead of
      // stacking a new one per capture. The first capture at a location defines the cipher.
      const now = r.key && r.key.value != null ? String(r.key.value) : null;
      const hit = (r.apply && findLoc('request', r.apply, now)) || (r.applyResponse && findLoc('response', r.applyResponse, now));
      let id;
      let otherKey = false; // this capture used a different key than the one the location's cipher holds
      if (hit) {
        id = hit.e.id;
        const seen = keyValOf.get(id);
        if (hit.sameAt && seen != null && now != null && seen !== now && cfg.ciphers[id].alg !== 'rsa') {
          otherKey = true;
          if (!cfg.ciphers[id]._perRequestKey) {
            cfg.ciphers[id]._perRequestKey = true;
            cfg.ciphers[id]._note = 'key differs between captures at this location (per-request / session key)';
          }
        }
      } else {
        id = 'c' + ++ci;
        if (r.key && r.key.value != null) keyValOf.set(id, String(r.key.value));
        // A key the page made with generateKey is random by construction: never a fixed key, even if it was
        // captured only once (e.g. a fresh AES key per request, sent RSA-wrapped).
        if (r.keySource === 'generateKey') {
          spec._perRequestKey = true;
          spec._note = 'key generated by the page (random per request): needs the live bridge, not a fixed key';
        }
        if (spec._traced) {
          delete spec._traced;
          for (const c of r.candidates || []) {
            const n = candLen(c.value);
            const entry = { source: 'static', value: String(c.value.value), encoding: c.value.encoding === 'base64' ? 'base64' : 'utf8' };
            if (n === 16 || n === 24 || n === 32) spec.identify.keys.push(keyNameFor(entry));
            if (n === 16) spec.identify.ivs.push({ value: entry.value, encoding: entry.encoding });
          }
          const placed = r.apply || r.applyResponse || {};
          if (r.ivApply) {
            const { in: w, path: p, name, encoding } = r.ivApply;
            spec.identify.ivs.unshift({ from: 'field', in: w, ...(p ? { path: p } : { name }), encoding });
          } else if (placed.ivPrefix) spec.identify.ivs.unshift({ from: 'prefix', length: placed.ivPrefix });
          cfg.ciphers[id] = spec;
        } else if (spec.alg === 'rsa') {
          cfg.ciphers[id] = spec;
          // WebCrypto hands over the key it encrypts/decrypts with (spki/pkcs8 base64, or a JWK): an encrypt
          // capture carries the public half, a decrypt capture the private half.
          if (r.lib === 'webcrypto' && r.key && r.key.value) {
            const entry = r.key.encoding === 'jwk'
              ? { source: 'static', value: String(r.key.value), encoding: 'utf8' }
              : { source: 'static', value: String(r.key.value), encoding: 'base64' };
            spec[r.op === 'decrypt' ? 'privateKey' : 'publicKey'] = keyNameFor(entry);
          } else if ((r.lib === 'jsbn' || r.lib === 'jsencrypt') && r.key && r.key.encoding === 'rsa-hex') {
            // jsbn keeps n/e (and with setPrivateEx d + CRT params) as hex: rebuild them as JWK, which the
            // server loads directly. A JWK private key needs every CRT field; with only n/e/d it stays public.
            const k = JSON.parse(String(r.key.value));
            const b = (h) => hexToB64url(h);
            const pub = { kty: 'RSA', n: b(k.n), e: b(k.e) };
            spec.publicKey = keyNameFor({ source: 'static', value: JSON.stringify(pub), encoding: 'utf8' });
            if (['d', 'p', 'q', 'dmp1', 'dmq1', 'coeff'].every((f) => k[f])) {
              const priv = { ...pub, d: b(k.d), p: b(k.p), q: b(k.q), dp: b(k.dmp1), dq: b(k.dmq1), qi: b(k.coeff) };
              spec.privateKey = keyNameFor({ source: 'static', value: JSON.stringify(priv), encoding: 'utf8' });
            }
          } else {
            spec._note = 'RSA: add publicKey/privateKey (DER base64 or PEM) manually';
          }
        } else {
          const passphrase = spec._passphrase;
          delete spec._passphrase;
          // passphrase mode stores the string passphrase (utf8); the salt/IV are derived per message
          const ke = passphrase
            ? { source: 'static', value: String(r.key && r.key.value), encoding: 'utf8' }
            : keyEntry(r.key);
          if (ke) spec.key = keyNameFor(ke);
          // Where the IV travels, learned by correlate.js: its own field, or glued in front of the ciphertext.
          const placed = r.apply || r.applyResponse || {};
          if (!passphrase && r.ivApply) {
            const { in: where, path: p, name, encoding } = r.ivApply;
            spec.iv = { from: 'field', in: where, ...(p ? { path: p } : { name }), encoding };
          } else if (!passphrase && placed.ivPrefix) {
            spec.iv = { from: 'prefix', length: placed.ivPrefix };
          }
          if (placed.encoding) spec.outEncoding = placed.encoding; // ciphertext re-encoded on the wire (e.g. hex)
          if (!passphrase && r.iv && r.iv.value && !spec.iv) spec.iv = { value: r.iv.value, encoding: r.iv.encoding === 'base64' || r.iv.encoding === 'utf8' ? r.iv.encoding : 'hex' };
          cfg.ciphers[id] = spec;
        }
      }
      // apply rules from correlated transport locations (request and/or response side); `at` (the captured
      // request path) is kept aside and only becomes a pathRegex when the direction needs it (see below)
      if (r.applyWebSocket) {
        const w = r.applyWebSocket;
        wsNotes.add(`WebSocket ${w.url} ${w.path || w.name || w.in} -> ${id} (Burp does not rewrite WebSocket messages yet; no apply rule made)`);
      }
      // (encoding / ivPrefix placement details live in the cipher spec, not the rule)
      const rule = (a) => { const { at, encoding, ivPrefix, ...rest } = a; const out = { ...rest, cipher: id }; Object.defineProperty(out, '_at', { value: at, enumerable: false }); return out; };
      for (const [side, a] of [['request', r.apply], ['response', r.applyResponse]]) {
        if (!a) continue;
        const k = locKeyOf(a);
        if (!locs[side].has(k)) locs[side].set(k, []);
        const list = locs[side].get(k);
        if (list.some((e) => e.id === id)) { if (!list.some((e) => e.at === a.at)) list.push({ id, at: a.at, keyVal: now, rule: null }); continue; }
        const ru = rule(a);
        cfg.apply[side].push(ru);
        list.push({ id, at: a.at, keyVal: now, rule: ru });
      }
      // selftest vector when we have both plaintext and ciphertext
      if (otherKey) continue; // a vector made with another key would fail this cipher's selftest
      // RSA encryption is randomized: a vector can only be checked by decrypting, which needs the private key.
      if (cfg.ciphers[id].alg === 'rsa' && !cfg.ciphers[id].privateKey) continue;
      const plain = plainOf(r, cfg.ciphers[id]);
      const ct = r.op === 'decrypt' ? r.input : r.output;
      if (plain != null && ct && ct.value != null) {
        const c = cfg.ciphers[id];
        const vec = { cipher: id, plain, ciphertext: wireCiphertext(c, ct, r.iv, r.tag) };
        if (c.iv && c.iv.from === 'field') {
          const ivb = recBytes(r.iv);
          if (!ivb) continue; // no IV to check this vector with
          vec.iv = encodeBytes(ivb, c.iv.encoding || 'base64');
        }
        cfg.selftest.push(vec);
      }
    }

    for (const n of wsNotes) cfg._notes.push(n);

    // Draft integrity rules from captured hash/HMAC calls whose output landed in a request field
    // (a token/signature). The analyst must set the "input" template to match the page; the captured
    // one-shot input is recorded in _note as a starting point.
    const normAlg = (a) => String((a && a.name) || 'SHA256').toLowerCase().replace(/^sha-?/, 'sha');
    // The input template: find the request that carried this signature, then the value(s) in it whose text
    // equals what was signed -- one field, or 2-3 joined by a separator. The server recomputes the token over
    // the FINAL (re-encrypted) message, so a field that is itself encrypted is signed with its new ciphertext.
    const tokenOf = (loc) => (loc.in === 'json' ? `{json:${loc.path}}` : loc.in === 'body' ? '{body}' : `{${loc.in}:${loc.name}}`);
    const slotsOfT = (t) => {
      const out = [];
      const b = t.body || {};
      if (b.kind === 'json') for (const f of b.fields || []) out.push({ tok: tokenOf({ in: 'json', path: f.path }), value: f.value });
      else if (b.kind === 'form' || b.kind === 'multipart') for (const f of b.fields || []) out.push({ tok: tokenOf({ in: b.kind, name: f.name }), value: f.value });
      else if (b.kind === 'text' && b.sample) out.push({ tok: '{body}', value: b.sample });
      for (const [name, value] of t.headers || []) out.push({ tok: tokenOf({ in: 'header', name }), value });
      for (const [name, value] of t.query || []) out.push({ tok: tokenOf({ in: 'query', name }), value });
      return out;
    };
    function inferTemplate(r) {
      const input = String((r.input && r.input.value) || '');
      const sig = String((r.output && r.output.value) || '');
      if (!input || !sig) return null;
      for (const t of records) {
        if (t.lib !== 'transport' || t.op === 'response') continue;
        const slots = slotsOfT(t);
        if (!slots.some((s) => s.value === sig)) continue;
        const cand = slots.filter((s) => s.value && s.value !== sig);
        const one = cand.find((s) => s.value === input);
        if (one) return one.tok;
        for (const sep of ['', '|', '&', ':', '.', ',', '_', '\n']) {
          for (const a of cand) {
            if (!input.startsWith(a.value + sep)) continue;
            for (const b of cand) {
              if (b === a) continue;
              if (a.value + sep + b.value === input) return a.tok + sep + b.tok;
              for (const c of cand) if (c !== a && c !== b && a.value + sep + b.value + sep + c.value === input) return a.tok + sep + b.tok + sep + c.tok;
            }
          }
        }
      }
      return null;
    }
    for (const r of records) {
      if ((r.op !== 'hash' && r.op !== 'hmac') || !r.apply) continue;
      const target = r.apply.in === 'json' ? { in: 'json', path: r.apply.path }
        : r.apply.in === 'header' ? { in: 'header', name: r.apply.name }
        : r.apply.in === 'query' ? { in: 'query', name: r.apply.name }
        : r.apply.in === 'form' || r.apply.in === 'multipart' ? { in: r.apply.in, name: r.apply.name } : { in: 'body' };
      if (cfg.integrity.some((x) => JSON.stringify(x.target) === JSON.stringify(target))) continue;
      const rule = { type: r.op === 'hmac' ? 'hmac' : 'hash', alg: normAlg(r.alg), input: '{body}', outEncoding: 'hex', target };
      if (r.op === 'hmac' && r.key && r.key.value != null) {
        const v = String(r.key.value);
        rule.key = keyNameFor({ source: 'static', value: v, encoding: /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0 ? 'hex' : 'utf8' });
      }
      const tpl = inferTemplate(r);
      if (tpl) {
        rule.input = tpl;
        rule._note = 'input inferred from the captured call (signed value found in the same request)';
      } else {
        rule._note = 'DRAFT: set "input" to the real template. Captured input was: ' + JSON.stringify(String((r.input && r.input.value) || '').slice(0, 120));
      }
      cfg.integrity.push(rule);
    }

    // One location used by different ciphers at different endpoints: pin each of those rules to its endpoint.
    for (const side of ['request', 'response']) {
      for (const list of locs[side].values()) {
        if (new Set(list.map((e) => e.id)).size < 2) continue;
        for (const e of list) if (e.rule && e.at) e.rule.pathRegex = pathRegexFor(e.at);
      }
    }

    // A whole-body rule and JSON/form-field rules in one direction rewrite the same body. When they came from
    // different endpoints, pin each rule to its captured path so the server applies only the right one.
    for (const side of ['request', 'response']) {
      const rules = cfg.apply[side];
      const mixed = rules.some((x) => x.in === 'body') && rules.some((x) => x.in === 'json' || x.in === 'form');
      if (!mixed) continue;
      let pinned = 0;
      for (const x of rules) if (x._at) { x.pathRegex = pathRegexFor(x._at); pinned++; }
      if (pinned) cfg._notes.push(`apply.${side}: whole-body and field rules came from different endpoints -- each rule is pinned to its captured path (pathRegex); widen it if more endpoints share the scheme`);
    }

    cfg.scope = [...hosts].filter(Boolean).map((s) => {
      const { host, port } = JSON.parse(s);
      const rule = { host, pathRegex: '.*' };
      if (port) rule.port = port;
      return rule;
    });
    if (!cfg.scope.length) cfg.scope.push({ host: '', pathRegex: '.*' });
    return cfg;
  };

  /** For Send to Burp (0.3.0): the server rejects a whole profile when one cipher can't load, so drop the
   * ciphers the capture couldn't complete -- no key (per-request / wrapped key), RSA without key material,
   * custom-module placeholders -- with their apply rules and selftests. Export keeps the full draft. */
  window.loadableConfig = function loadableConfig(cfg) {
    const out = JSON.parse(JSON.stringify(cfg));
    const skipped = [];
    const why = {};
    for (const [id, c] of Object.entries(out.ciphers)) {
      let reason = null;
      if (c._perRequestKey) reason = 'key changes per request (not a fixed key)';
      else if (c.custom) reason = 'custom module not provided';
      else if (c.alg === 'rsa' && !c.publicKey && !c.privateKey) reason = 'RSA key not captured';
      else if (c.alg !== 'rsa' && !c.key && !c.custom && !c.identify) reason = 'key not captured (per-request or wrapped key)';
      if (reason) { why[id] = reason; delete out.ciphers[id]; }
    }
    const where = (r) => (r.path || r.name || r.in);
    for (const side of ['request', 'response']) {
      out.apply[side] = out.apply[side].filter((r) => {
        if (!why[r.cipher]) return true;
        skipped.push(`${side} ${where(r)}: ${why[r.cipher]}`);
        return false;
      });
    }
    out.selftest = out.selftest.filter((t) => !why[t.cipher]);
    if (skipped.length) {
      out._notes = [...(out._notes || []), 'Skipped on Send to Burp (finish them from Export by hand):', ...skipped.map((x) => '- ' + x)];
    }
    return { cfg: out, skipped };
  };
})();
