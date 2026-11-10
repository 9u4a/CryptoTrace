// One config file = one profile: scope + keys + ciphers + apply rules + selftest vectors.
import fs from 'node:fs';
import path from 'node:path';
import { toBytes } from './encoding.mjs';
import { symmetricCipher, rsaCipher, opensslPassphraseCipher } from './cipher.mjs';
import { deriveKey } from './kdf.mjs';
import { loadCustomCipher, loadCustomSign } from './custom.mjs';
import { parsePath } from './jsonpath.mjs';
import { INTEGRITY_TYPES } from './integrity.mjs';

export const SCHEMA_VERSION = 1;
const LOCATIONS = ['json', 'body', 'header', 'query', 'form'];

function fail(file, msg) {
  throw new Error(`${path.basename(file)}: ${msg}`);
}

// Static keys resolve to bytes now; session keys stay empty until captured at runtime
// (op "key") and carry a capture rule so Burp knows which response holds the value.
function resolveKeys(file, keySpecs = {}) {
  const store = {}; // name -> Buffer (session keys appear here only once captured)
  const captures = [];
  for (const [name, k] of Object.entries(keySpecs)) {
    if (k.source === 'session') {
      const cap = k.capture || {};
      captures.push({
        keyName: name,
        urlRegex: cap.urlRegex || null,
        jsonPath: cap.jsonPath || null,
        regex: cap.regex || null,
        header: cap.header || null,
        encoding: k.encoding || 'utf8',
      });
      continue;
    }
    if (k.source && k.source !== 'static') fail(file, `key "${name}": unknown source "${k.source}"`);
    if (typeof k.value !== 'string') fail(file, `key "${name}": missing value`);
    store[name] = toBytes(k.value, k.encoding || 'utf8');
  }
  return { store, captures };
}

// A cipher whose session key hasn't arrived yet: valid to load and reference, but any
// transform through it reports a clear "not captured yet" error instead of crashing.
function pendingCipher(name, pendingKeys, keySpecs) {
  const waits = pendingKeys
    .map((k) => {
      const cap = (keySpecs[k] && keySpecs[k].capture) || {};
      return cap.urlRegex ? `${k} (from response ${cap.urlRegex})` : k;
    })
    .join(', ');
  const err = () => {
    throw new Error(`session key not captured yet: ${waits}`);
  };
  return { deterministic: false, pending: true, encrypt: err, decrypt: err };
}

function buildCipher(file, name, spec, store, keySpecs) {
  const pendingKeys = [];
  const keyOf = (ref) => {
    if (!ref) return null;
    if (ref in store) return store[ref];
    if (keySpecs[ref] && keySpecs[ref].source === 'session') {
      pendingKeys.push(ref);
      return null;
    }
    fail(file, `cipher "${name}": unknown key "${ref}"`);
  };
  if (spec.custom) {
    const modPath = path.resolve(path.dirname(file), spec.custom);
    return loadCustomCipher(modPath, spec, store);
  }
  if (!spec.alg) fail(file, `cipher "${name}": needs "alg" or "custom"`);
  if (spec.alg.toLowerCase() === 'rsa') {
    const pub = keyOf(spec.publicKey);
    const priv = keyOf(spec.privateKey);
    if (pendingKeys.length) return pendingCipher(name, pendingKeys, keySpecs);
    return rsaCipher(spec, pub, priv);
  }
  const key = keyOf(spec.key);
  if (pendingKeys.length) return pendingCipher(name, pendingKeys, keySpecs);
  if (!key) fail(file, `cipher "${name}": needs "key"`);
  if (spec.kdf === 'openssl-md5') return opensslPassphraseCipher(spec, key); // CryptoJS passphrase mode
  if (spec.kdf) return symmetricCipher(spec, deriveKey(spec, key)); // pbkdf2 / scrypt / hkdf
  return symmetricCipher(spec, key);
}

function validateRules(file, rules = [], ciphers) {
  return rules.map((r, i) => {
    if (!LOCATIONS.includes(r.in)) fail(file, `apply rule #${i}: "in" must be one of ${LOCATIONS.join('/')}`);
    if (!(r.cipher in ciphers)) fail(file, `apply rule #${i}: unknown cipher "${r.cipher}"`);
    if ((r.in === 'header' || r.in === 'query' || r.in === 'form') && !r.name) fail(file, `apply rule #${i}: needs "name"`);
    return { ...r, parts: r.in === 'json' ? parsePath(r.path) : null };
  });
}

// Integrity rules recompute a token/signature over the final message (see integrity.mjs).
// `target` is where the computed value is written; custom signers are preloaded here.
function validateIntegrity(file, rules = [], store, keySpecs) {
  return rules.map((r, i) => {
    if (!INTEGRITY_TYPES.has(r.type)) fail(file, `integrity #${i}: unknown type "${r.type}"`);
    const t = r.target || {};
    if (!LOCATIONS.includes(t.in)) fail(file, `integrity #${i}: target.in must be one of ${LOCATIONS.join('/')}`);
    if ((t.in === 'header' || t.in === 'query' || t.in === 'form') && !t.name) fail(file, `integrity #${i}: target needs "name"`);
    if (t.in === 'json' && !t.path) fail(file, `integrity #${i}: target needs "path"`);
    if ((r.type === 'hmac' || r.type === 'sign') && !(r.key in keySpecs)) fail(file, `integrity #${i}: unknown key "${r.key}"`);
    const out = { ...r, target: t.in === 'json' ? { ...t, parts: parsePath(t.path) } : { ...t } };
    if (r.type === 'custom') {
      if (!r.custom) fail(file, `integrity #${i}: custom needs "custom" module path`);
      out.__sign = loadCustomSign(path.resolve(path.dirname(file), r.custom), r, store);
    }
    return out;
  });
}

export function loadProfile(file) {
  let cfg;
  try {
    cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    fail(file, `cannot read config: ${e.message}`);
  }
  if (cfg.schemaVersion !== SCHEMA_VERSION) {
    fail(file, `schemaVersion ${cfg.schemaVersion} not supported (server expects ${SCHEMA_VERSION})`);
  }
  if (!cfg.profile) fail(file, 'missing "profile"');

  const keySpecs = cfg.keys || {};
  const cipherSpecs = cfg.ciphers || {};
  const { store, captures } = resolveKeys(file, keySpecs);
  const scope = (cfg.scope || []).map((s) => ({
    host: String(s.host || '').toLowerCase(),
    port: s.port ?? null,
    pathRe: new RegExp(s.pathRegex || '.*'),
  }));

  const profile = {
    name: cfg.profile,
    file,
    scope,
    keyStore: store,
    keySpecs,
    captures,
    ciphers: {},
    request: [],
    response: [],
    selftestVectors: cfg.selftest || [],
  };

  // (Re)build every cipher from its spec against the current key store. Called once at
  // load and again each time a session key is captured, so pending ciphers come alive.
  const rebuild = () => {
    const ciphers = {};
    for (const [name, spec] of Object.entries(cipherSpecs)) {
      try {
        ciphers[name] = buildCipher(file, name, spec, store, keySpecs);
      } catch (e) {
        fail(file, `cipher "${name}": ${e.message}`);
      }
    }
    profile.ciphers = ciphers;
  };
  rebuild();

  profile.request = validateRules(file, cfg.apply?.request, profile.ciphers);
  profile.response = validateRules(file, cfg.apply?.response, profile.ciphers);
  profile.integrity = validateIntegrity(file, cfg.integrity, store, keySpecs);
  profile.integrityResponse = validateIntegrity(file, cfg.integrityResponse, store, keySpecs);

  // Runtime key capture: store the bytes and rebuild so dependent ciphers become usable.
  profile.setKey = (keyName, value, encoding) => {
    const spec = keySpecs[keyName];
    if (!spec || spec.source !== 'session') throw new Error(`"${keyName}" is not a session key`);
    store[keyName] = toBytes(value, encoding || spec.encoding || 'utf8');
    rebuild();
    return { keyName, pending: Object.values(profile.ciphers).some((c) => c.pending) };
  };

  return profile;
}

export function inScope(profile, host, port, pathname) {
  const h = String(host || '').toLowerCase();
  return profile.scope.some((s) => s.host === h && (s.port == null || s.port === port) && s.pathRe.test(pathname));
}

/** Check exported plaintext/ciphertext pairs against the config. Returns [{cipher, ok, error?}]. */
export function selftest(profile) {
  return profile.selftestVectors.map((v) => {
    const c = profile.ciphers[v.cipher];
    if (!c) return { cipher: v.cipher, ok: false, error: 'unknown cipher' };
    if (c.pending) return { cipher: v.cipher, ok: false, error: 'session key not captured yet' };
    try {
      if (c.decrypt(v.ciphertext) !== v.plain) return { cipher: v.cipher, ok: false, error: 'decrypt(ciphertext) != plain' };
      if (c.deterministic && c.encrypt(v.plain) !== v.ciphertext.trim()) {
        return { cipher: v.cipher, ok: false, error: 'encrypt(plain) != ciphertext' };
      }
      if (c.decrypt(c.encrypt(v.plain)) !== v.plain) return { cipher: v.cipher, ok: false, error: 'round-trip failed' };
      return { cipher: v.cipher, ok: true };
    } catch (e) {
      return { cipher: v.cipher, ok: false, error: e.message };
    }
  });
}
