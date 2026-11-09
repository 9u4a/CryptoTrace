// One config file = one profile: scope + keys + ciphers + apply rules + selftest vectors.
import fs from 'node:fs';
import path from 'node:path';
import { toBytes } from './encoding.mjs';
import { symmetricCipher, rsaCipher } from './cipher.mjs';
import { loadCustomCipher } from './custom.mjs';
import { parsePath } from './jsonpath.mjs';

export const SCHEMA_VERSION = 1;
const LOCATIONS = ['json', 'body', 'header', 'query'];

function fail(file, msg) {
  throw new Error(`${path.basename(file)}: ${msg}`);
}

function resolveKeys(file, keys = {}) {
  const out = {};
  for (const [name, k] of Object.entries(keys)) {
    if (k.source === 'session') continue; // filled at runtime (phase 2)
    if (k.source && k.source !== 'static') fail(file, `key "${name}": unknown source "${k.source}"`);
    if (typeof k.value !== 'string') fail(file, `key "${name}": missing value`);
    out[name] = toBytes(k.value, k.encoding || 'utf8');
  }
  return out;
}

function buildCipher(file, name, spec, keys) {
  if (spec.custom) {
    const modPath = path.resolve(path.dirname(file), spec.custom);
    return loadCustomCipher(modPath, spec, keys);
  }
  if (!spec.alg) fail(file, `cipher "${name}": needs "alg" or "custom"`);
  const keyOf = (ref) => {
    if (!ref) return null;
    if (!(ref in keys)) fail(file, `cipher "${name}": unknown key "${ref}"`);
    return keys[ref];
  };
  if (spec.alg.toLowerCase() === 'rsa') return rsaCipher(spec, keyOf(spec.publicKey), keyOf(spec.privateKey));
  const key = keyOf(spec.key);
  if (!key) fail(file, `cipher "${name}": needs "key"`);
  return symmetricCipher(spec, key);
}

function validateRules(file, rules = [], ciphers) {
  return rules.map((r, i) => {
    if (!LOCATIONS.includes(r.in)) fail(file, `apply rule #${i}: "in" must be one of ${LOCATIONS.join('/')}`);
    if (!(r.cipher in ciphers)) fail(file, `apply rule #${i}: unknown cipher "${r.cipher}"`);
    if ((r.in === 'header' || r.in === 'query') && !r.name) fail(file, `apply rule #${i}: needs "name"`);
    return { ...r, parts: r.in === 'json' ? parsePath(r.path) : null };
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
  const keys = resolveKeys(file, cfg.keys);
  const ciphers = {};
  for (const [name, spec] of Object.entries(cfg.ciphers || {})) {
    try {
      ciphers[name] = buildCipher(file, name, spec, keys);
    } catch (e) {
      fail(file, `cipher "${name}": ${e.message}`);
    }
  }
  const scope = (cfg.scope || []).map((s) => ({
    host: String(s.host || '').toLowerCase(),
    port: s.port ?? null,
    pathRe: new RegExp(s.pathRegex || '.*'),
  }));
  return {
    name: cfg.profile,
    file,
    scope,
    ciphers,
    request: validateRules(file, cfg.apply?.request, ciphers),
    response: validateRules(file, cfg.apply?.response, ciphers),
    selftestVectors: cfg.selftest || [],
  };
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
