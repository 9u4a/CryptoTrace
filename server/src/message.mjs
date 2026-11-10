// Apply a profile's rules to an HTTP message.
// Message shape (what Burp sends): { headers: [[name, value], ...], body: string, path?: string }
// `path` (with query string) is only present for requests.
import { getAt, setAt, parsePath } from './jsonpath.mjs';
import { computeRule } from './integrity.mjs';

export const PLAIN_MARKER = 'x-ct-plain';

const findHeader = (headers, name) => headers.findIndex(([n]) => n.toLowerCase() === name.toLowerCase());

function splitPath(p = '') {
  const i = p.indexOf('?');
  return i < 0 ? [p, ''] : [p.slice(0, i), p.slice(i + 1)];
}

function queryGet(qs, name) {
  for (const pair of qs.split('&')) {
    const eq = pair.indexOf('=');
    if (eq > 0 && decodeURIComponent(pair.slice(0, eq)) === name) return decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
  }
  return undefined;
}

function querySet(qs, name, value) {
  return qs
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      return eq > 0 && decodeURIComponent(pair.slice(0, eq)) === name ? `${pair.slice(0, eq)}=${encodeURIComponent(value)}` : pair;
    })
    .join('&');
}

// Plaintext that is itself JSON is shown as a nested object so it can be edited in place,
// and serialized back (compact) before encryption.
const embed = (plain) => {
  try {
    const v = JSON.parse(plain);
    return v !== null && typeof v === 'object' ? v : plain;
  } catch {
    return plain;
  }
};
const unembed = (v) => (typeof v === 'string' ? v : JSON.stringify(v));

/**
 * direction: 'decrypt' | 'encrypt'. Returns { message, applied: [{in, where, ok, error?}] }.
 * Never throws for a single location; failures are reported per rule and the value is left as-is.
 */
export function transform(profile, rules, msg, direction, integrity = []) {
  const headers = msg.headers.map(([n, v]) => [n, v]);
  let body = msg.body ?? '';
  let [pathname, qs] = splitPath(msg.path);
  const applied = [];
  let json; // parsed lazily, shared by all json rules
  const run = (cipher, v) => (direction === 'decrypt' ? cipher.decrypt(v) : cipher.encrypt(v));

  for (const r of rules) {
    const cipher = profile.ciphers[r.cipher];
    const where = r.in === 'json' ? r.path : r.name || 'body';
    try {
      if (r.in === 'body') {
        if (!body) continue;
        body = run(cipher, body);
      } else if (r.in === 'header') {
        const i = findHeader(headers, r.name);
        if (i < 0) continue;
        headers[i][1] = run(cipher, headers[i][1]);
      } else if (r.in === 'query') {
        const v = queryGet(qs, r.name);
        if (v === undefined) continue;
        qs = querySet(qs, r.name, run(cipher, v));
      } else if (r.in === 'json') {
        json ??= JSON.parse(body);
        const v = getAt(json, r.parts);
        if (v === undefined) continue;
        json = setAt(json, r.parts, direction === 'decrypt' ? embed(cipher.decrypt(v)) : cipher.encrypt(unembed(v)));
      }
      applied.push({ in: r.in, where, ok: true });
    } catch (e) {
      applied.push({ in: r.in, where, ok: false, error: e.message });
    }
  }
  if (json !== undefined) body = direction === 'decrypt' ? JSON.stringify(json, null, 2) : JSON.stringify(json);

  // Integrity: recompute tokens/signatures over the FINAL (re-encrypted) message, encrypt-only.
  // Rules run in config order so a timestamp/nonce can feed a later hmac's {ts}/{nonce}.
  if (direction === 'encrypt' && integrity.length) {
    const state = {};
    const read = (kind, key) => {
      if (kind === 'body') return body;
      if (kind === 'header') { const i = findHeader(headers, key); return i < 0 ? '' : headers[i][1]; }
      if (kind === 'query') { const v = queryGet(qs, key); return v === undefined ? '' : v; }
      if (kind === 'json') { try { return String(getAt(JSON.parse(body), parsePath(key)) ?? ''); } catch { return ''; } }
      return '';
    };
    const loadCustom = (rule) => rule.__sign;
    for (const r of integrity) {
      const t = r.target;
      const where = t.in === 'json' ? t.path : t.name || 'body';
      try {
        const value = computeRule(r, { read, keyStore: profile.keyStore || {}, state, loadCustom });
        if (t.in === 'header') { const i = findHeader(headers, t.name); if (i < 0) headers.push([t.name, value]); else headers[i][1] = value; }
        else if (t.in === 'query') qs = queryGet(qs, t.name) === undefined ? (qs ? `${qs}&${encodeURIComponent(t.name)}=${encodeURIComponent(value)}` : `${encodeURIComponent(t.name)}=${encodeURIComponent(value)}`) : querySet(qs, t.name, value);
        else if (t.in === 'body') body = value;
        else if (t.in === 'json') { const j = JSON.parse(body); setAt(j, t.parts, value); body = JSON.stringify(j); }
        applied.push({ in: t.in, where, integrity: r.type, ok: true });
      } catch (e) {
        applied.push({ in: t.in, where, integrity: r.type, ok: false, error: e.message });
      }
    }
  }

  const out = { headers, body };
  if (msg.path !== undefined) out.path = qs ? `${pathname}?${qs}` : pathname;
  return { message: out, applied };
}
