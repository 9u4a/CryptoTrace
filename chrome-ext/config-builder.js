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
    const padding = (rec.padding || 'Pkcs7').toLowerCase().includes('pkcs') ? 'pkcs7' : 'none';
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
  function asText(v) {
    if (!v) return null;
    if (v.encoding === 'utf8') return String(v.value);
    if (v.encoding !== 'base64') return null;
    const bytes = b64Bytes(v.value);
    return bytes ? utf8Text(bytes) : null;
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
    const ruleByLoc = new Map(); // request "in|path|name" -> cipher id
    const ruleByLocResp = new Map(); // response "in|path|name" -> cipher id
    const keyValOf = new Map(); // cipher id -> the key value of the capture that defined it
    const locKeyOf = (a) => (a ? `${a.in}|${a.path || ''}|${a.name || ''}` : null);
    const keyNameFor = (entry) => {
      const sig = JSON.stringify(entry);
      for (const [n, e] of Object.entries(cfg.keys)) if (JSON.stringify(e) === sig) return n;
      const name = 'k' + (Object.keys(cfg.keys).length + 1);
      cfg.keys[name] = entry;
      return name;
    };

    for (const r of records) {
      if (r.lib === 'transport' || (r.op !== 'encrypt' && r.op !== 'decrypt')) continue;
      if (r.frame) hosts.add(hostFromFrame(r.frame));
      let spec = null;
      const keyBytes = keyByteLen(r.key);
      if (r.lib === 'webcrypto') spec = webcryptoAlg(r.alg, keyBytes);
      else if (r.lib === 'cryptojs') spec = cryptojsAlg(r, keyBytes);
      else if (r.lib === 'jsencrypt') spec = { alg: 'rsa', padding: 'pkcs1' };
      if (!spec) continue;

      // Reuse the cipher already chosen for this apply location (request or response) instead of
      // stacking a new one per capture. The first capture at a location defines the cipher.
      const locKey = locKeyOf(r.apply);
      const locKeyResp = locKeyOf(r.applyResponse);
      let id;
      let otherKey = false; // this capture used a different key than the one the location's cipher holds
      if ((locKey && ruleByLoc.has(locKey)) || (locKeyResp && ruleByLocResp.has(locKeyResp))) {
        id = locKey && ruleByLoc.has(locKey) ? ruleByLoc.get(locKey) : ruleByLocResp.get(locKeyResp);
        const seen = keyValOf.get(id);
        const now = r.key && r.key.value != null ? String(r.key.value) : null;
        if (seen != null && now != null && seen !== now && cfg.ciphers[id].alg !== 'rsa') {
          otherKey = true;
          if (!cfg.ciphers[id]._perRequestKey) {
            cfg.ciphers[id]._perRequestKey = true;
            cfg.ciphers[id]._note = 'key differs between captures at this location (per-request / session key)';
          }
        }
      } else {
        id = 'c' + ++ci;
        if (r.key && r.key.value != null) keyValOf.set(id, String(r.key.value));
        if (spec.alg === 'rsa') {
          cfg.ciphers[id] = spec;
          // WebCrypto hands over the key it encrypts/decrypts with (spki/pkcs8 base64, or a JWK): an encrypt
          // capture carries the public half, a decrypt capture the private half.
          if (r.lib === 'webcrypto' && r.key && r.key.value) {
            const entry = r.key.encoding === 'jwk'
              ? { source: 'static', value: String(r.key.value), encoding: 'utf8' }
              : { source: 'static', value: String(r.key.value), encoding: 'base64' };
            spec[r.op === 'decrypt' ? 'privateKey' : 'publicKey'] = keyNameFor(entry);
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
          if (!passphrase && r.iv && r.iv.value && !spec.iv) spec.iv = { value: r.iv.value, encoding: r.iv.encoding === 'base64' ? 'base64' : 'hex' };
          cfg.ciphers[id] = spec;
        }
      }
      // apply rules from correlated transport locations (request and/or response side); `at` (the captured
      // request path) is kept aside and only becomes a pathRegex when the direction needs it (see below)
      const rule = (a) => { const { at, ...rest } = a; const out = { ...rest, cipher: id }; Object.defineProperty(out, '_at', { value: at, enumerable: false }); return out; };
      if (locKey && !ruleByLoc.has(locKey)) { cfg.apply.request.push(rule(r.apply)); ruleByLoc.set(locKey, id); }
      if (locKeyResp && !ruleByLocResp.has(locKeyResp)) { cfg.apply.response.push(rule(r.applyResponse)); ruleByLocResp.set(locKeyResp, id); }
      // selftest vector when we have both plaintext and ciphertext
      if (otherKey) continue; // a vector made with another key would fail this cipher's selftest
      // RSA encryption is randomized: a vector can only be checked by decrypting, which needs the private key.
      if (cfg.ciphers[id].alg === 'rsa' && !cfg.ciphers[id].privateKey) continue;
      const plain = asText(r.op === 'encrypt' ? r.input : r.output);
      const ct = r.op === 'encrypt' ? r.output : r.input;
      if (plain != null && ct && ct.value != null) cfg.selftest.push({ cipher: id, plain, ciphertext: ct.value });
    }

    // Draft integrity rules from captured hash/HMAC calls whose output landed in a request field
    // (a token/signature). The analyst must set the "input" template to match the page; the captured
    // one-shot input is recorded in _note as a starting point.
    const normAlg = (a) => String((a && a.name) || 'SHA256').toLowerCase().replace(/^sha-?/, 'sha');
    for (const r of records) {
      if ((r.op !== 'hash' && r.op !== 'hmac') || !r.apply) continue;
      const target = r.apply.in === 'json' ? { in: 'json', path: r.apply.path }
        : r.apply.in === 'header' ? { in: 'header', name: r.apply.name }
        : r.apply.in === 'query' ? { in: 'query', name: r.apply.name } : { in: 'body' };
      if (cfg.integrity.some((x) => JSON.stringify(x.target) === JSON.stringify(target))) continue;
      const rule = { type: r.op === 'hmac' ? 'hmac' : 'hash', alg: normAlg(r.alg), input: '{body}', outEncoding: 'hex', target };
      if (r.op === 'hmac' && r.key && r.key.value != null) {
        const v = String(r.key.value);
        rule.key = keyNameFor({ source: 'static', value: v, encoding: /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0 ? 'hex' : 'utf8' });
      }
      rule._note = 'DRAFT: set "input" to the real template. Captured input was: ' + JSON.stringify(String((r.input && r.input.value) || '').slice(0, 120));
      cfg.integrity.push(rule);
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
      else if (c.alg !== 'rsa' && !c.key && !c.custom) reason = 'key not captured (per-request or wrapped key)';
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
