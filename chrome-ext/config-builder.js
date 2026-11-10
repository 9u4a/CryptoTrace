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
      if (locKey && ruleByLoc.has(locKey)) {
        id = ruleByLoc.get(locKey);
      } else if (locKeyResp && ruleByLocResp.has(locKeyResp)) {
        id = ruleByLocResp.get(locKeyResp);
      } else {
        id = 'c' + ++ci;
        if (spec.alg === 'rsa') {
          cfg.ciphers[id] = spec; // keys (public/private) must be filled in by the analyst
          spec._note = 'RSA: add publicKey/privateKey (DER base64 or PEM) manually';
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
      // apply rules from correlated transport locations (request and/or response side)
      if (locKey && !ruleByLoc.has(locKey)) { cfg.apply.request.push({ ...r.apply, cipher: id }); ruleByLoc.set(locKey, id); }
      if (locKeyResp && !ruleByLocResp.has(locKeyResp)) { cfg.apply.response.push({ ...r.applyResponse, cipher: id }); ruleByLocResp.set(locKeyResp, id); }
      // selftest vector when we have both plaintext and ciphertext
      if (r.op === 'encrypt' && r.input && r.output && r.input.encoding === 'utf8') {
        cfg.selftest.push({ cipher: id, plain: r.input.value, ciphertext: r.output.value });
      } else if (r.op === 'decrypt' && r.input && r.output && r.output.encoding === 'utf8') {
        cfg.selftest.push({ cipher: id, plain: r.output.value, ciphertext: r.input.value });
      }
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

    cfg.scope = [...hosts].filter(Boolean).map((s) => {
      const { host, port } = JSON.parse(s);
      const rule = { host, pathRegex: '.*' };
      if (port) rule.port = port;
      return rule;
    });
    if (!cfg.scope.length) cfg.scope.push({ host: '', pathRegex: '.*' });
    return cfg;
  };
})();
