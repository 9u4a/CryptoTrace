// Operations exposed to Burp. Pure request -> result; transport lives in main.mjs.
import { loadProfile, inScope, selftest } from './profile.mjs';
import { transform, PLAIN_MARKER } from './message.mjs';

export const VERSION = '0.2.0';

export function createEngine() {
  let profiles = [];
  const env = { session: null }; // per-request oracle session (handleAsync), see profile.mjs oracleCipher

  const pick = (host, port, path = '') => {
    const pathname = path.split('?')[0];
    return profiles.find((p) => inScope(p, host, port, pathname)) || null;
  };
  const byName = (name) => {
    const p = profiles.find((x) => x.name === name);
    if (!p) throw new Error(`unknown profile "${name}"`);
    return p;
  };
  const noMatch = (key, msg) => ({ matched: null, [key]: msg, applied: [] });

  const ops = {
    health: () => ({ version: VERSION, profiles: profiles.map((p) => p.name) }),

    // Replaces all loaded profiles. A bad file is reported, the rest still load.
    load({ files = [] }) {
      const loaded = [];
      const results = files.map((file) => {
        try {
          const p = loadProfile(file, env);
          loaded.push(p);
          const scope = p.scope.map((s) => ({ host: s.host, port: s.port, pathRegex: s.pathRegex }));
          return { file, profile: p.name, selftest: selftest(p), captures: p.captures, scope, warnings: p.warnings, identified: p.identified, oracles: p.oracles };
        } catch (e) {
          return { file, error: e.message };
        }
      });
      profiles = loaded;
      return { results };
    },

    // Runtime session-key capture: Burp extracts a value from a matching response and
    // sends it here; dependent ciphers are rebuilt so later requests use the fresh key.
    key({ profile, keyName, value, encoding }) {
      const p = byName(profile);
      if (typeof p.setKey !== 'function') throw new Error(`profile "${profile}" has no session keys`);
      return p.setKey(keyName, value, encoding);
    },

    decryptRequest({ host, port, request }) {
      const p = pick(host, port, request.path);
      if (!p) return noMatch('request', request);
      const { message, applied } = transform(p, p.request, request, 'decrypt');
      return { matched: p.name, request: message, applied };
    },

    encryptRequest({ host, port, request }) {
      const headers = request.headers.filter(([n]) => n.toLowerCase() !== PLAIN_MARKER);
      const req = { ...request, headers };
      const p = pick(host, port, req.path);
      if (!p) return noMatch('request', req);
      const { message, applied } = transform(p, p.request, req, 'encrypt', p.integrity);
      return { matched: p.name, request: message, applied };
    },

    decryptResponse({ host, port, path, response }) {
      const p = pick(host, port, path);
      if (!p) return noMatch('response', response);
      const { message, applied } = transform(p, p.response, response, 'decrypt', [], path);
      return { matched: p.name, response: message, applied };
    },

    encryptResponse({ host, port, path, response }) {
      const p = pick(host, port, path);
      if (!p) return noMatch('response', response);
      const { message, applied } = transform(p, p.response, response, 'encrypt', p.integrityResponse, path);
      return { matched: p.name, response: message, applied };
    },

    // Raw ops. A cipher that keeps its IV in another field takes it as `iv` (decrypt) and returns the fresh
    // one it used as `iv` (encrypt).
    decrypt: ({ profile, cipher, value, iv }) => ({ value: cipherOf(byName(profile), cipher).decrypt(value, { getIv: () => iv }) }),
    encrypt: ({ profile, cipher, value }) => {
      let iv;
      const out = cipherOf(byName(profile), cipher).encrypt(value, { setIv: (x) => { iv = x; } });
      return iv === undefined ? { value: out } : { value: out, iv };
    },
  };

  function cipherOf(p, name) {
    const c = p.ciphers[name];
    if (!c) throw new Error(`profile "${p.name}": unknown cipher "${name}"`);
    return c;
  }

  const handle = (req) => {
    const fn = ops[req.op];
    if (!fn) throw new Error(`unknown op "${req.op}"`);
    return fn(req);
  };

  return {
    handle,
    /** Like handle, for requests that may need the browser oracle: run, fetch what the oracle ciphers asked for
     * via oracleCall(job) -> Promise<string> (job = {cipher, fn, frame, dir, value}), run again with the answers.
     * A failed answer becomes that field's error (the request is then blocked, never sent in plaintext). */
    async handleAsync(req, oracleCall) {
      const session = { cache: new Map(), need: new Map() };
      for (let round = 0; ; round++) {
        session.need.clear();
        env.session = session;
        let result;
        try { result = handle(req); } finally { env.session = null; }
        if (!session.need.size || !oracleCall || round >= 3) return result;
        await Promise.all([...session.need.entries()].map(async ([key, job]) => {
          try { session.cache.set(key, { value: String(await oracleCall(job)) }); } catch (e) { session.cache.set(key, { error: e.message }); }
        }));
      }
    },
  };
}
