'use strict';

/* Turn recorded crypto calls into a draft config.json for the CryptoTrace server.
 * Heuristic: the analyst reviews keys, encodings and scope before use. Produces
 * schemaVersion 1 (see server/src/profile.mjs). Exposed as window.buildConfig. */
(function () {
  // WebCrypto algorithm object -> server cipher spec (alg + hints). Returns null if unknown.
  function webcryptoAlg(alg) {
    if (!alg || !alg.name) return null;
    const name = alg.name.toUpperCase();
    if (name === 'AES-GCM') return { alg: 'aes-256-gcm', iv: { from: 'prefix', length: 12 }, tag: { length: 16 } };
    if (name === 'AES-CBC') return { alg: 'aes-256-cbc', padding: 'pkcs7' };
    if (name === 'AES-CTR') return { alg: 'aes-256-ctr' };
    if (name === 'RSA-OAEP') return { alg: 'rsa', padding: 'oaep', oaepHash: (alg.hash && (alg.hash.name || alg.hash)) ? String(alg.hash.name || alg.hash).replace('SHA-', 'sha').toLowerCase() : 'sha1' };
    return null;
  }

  function cryptojsAlg(rec) {
    const name = (rec.alg && rec.alg.name) || 'AES';
    const map = { AES: 'aes-256-cbc', DES: 'des-cbc', TripleDES: 'des-ede3-cbc' };
    const spec = { alg: map[name] || 'aes-256-cbc', padding: (rec.padding || 'Pkcs7').toLowerCase().includes('pkcs') ? 'pkcs7' : 'none' };
    // CryptoJS default output is an OpenSSL "Salted__" base64 blob unless key/iv are WordArrays.
    spec.inEncoding = 'utf8';
    spec.outEncoding = 'base64';
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
      if (r.lib === 'webcrypto') spec = webcryptoAlg(r.alg);
      else if (r.lib === 'cryptojs') spec = cryptojsAlg(r);
      else if (r.lib === 'jsencrypt') spec = { alg: 'rsa', padding: 'pkcs1' };
      if (!spec) continue;

      const id = 'c' + ++ci;
      if (spec.alg === 'rsa') {
        cfg.ciphers[id] = spec; // keys (public/private) must be filled in by the analyst
        spec._note = 'RSA: add publicKey/privateKey (DER base64 or PEM) manually';
      } else {
        const ke = keyEntry(r.key);
        if (ke) spec.key = keyNameFor(ke);
        if (r.iv && r.iv.value && !spec.iv) spec.iv = { value: r.iv.value, encoding: r.iv.encoding === 'base64' ? 'base64' : 'hex' };
        cfg.ciphers[id] = spec;
      }

      // apply rule from correlated transport location (request side)
      if (r.apply) {
        const rule = { ...r.apply, cipher: id };
        if (!cfg.apply.request.some((x) => JSON.stringify(x) === JSON.stringify(rule))) cfg.apply.request.push(rule);
      }
      // selftest vector when we have both plaintext and ciphertext
      if (r.op === 'encrypt' && r.input && r.output && r.input.encoding === 'utf8') {
        cfg.selftest.push({ cipher: id, plain: r.input.value, ciphertext: r.output.value });
      } else if (r.op === 'decrypt' && r.input && r.output && r.output.encoding === 'utf8') {
        cfg.selftest.push({ cipher: id, plain: r.output.value, ciphertext: r.input.value });
      }
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
