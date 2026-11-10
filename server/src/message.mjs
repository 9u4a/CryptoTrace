// Apply a profile's rules to an HTTP message.
// Message shape (what Burp sends): { headers: [[name, value], ...], body: string, path?: string }
// `path` (with query string) is only present for requests.
import { getAt, setAt, parsePath, expand } from './jsonpath.mjs';
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

// Update the field if present, else append it (used when an integrity target field is new).
function querySetOrAdd(qs, name, value) {
  if (queryGet(qs, name) !== undefined) return querySet(qs, name, value);
  const pair = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
  return qs ? `${qs}&${pair}` : pair;
}

// ---- multipart/form-data: operate on one named text field's value, structure preserved ----
// Only text fields (UTF-8 bodies); binary file parts travel base64 (bodyEncoding) and are out of scope.
function boundaryOf(headers) {
  const i = findHeader(headers, 'content-type');
  if (i < 0) return null;
  const m = /boundary=("?)([^";]+)\1/i.exec(headers[i][1]);
  return m ? m[2] : null;
}
function partValue(part) {
  const h = part.indexOf('\r\n\r\n');
  if (h < 0) return null;
  const nm = /name="([^"]*)"/i.exec(part.slice(0, h));
  if (!nm) return null;
  let val = part.slice(h + 4);
  if (val.endsWith('\r\n')) val = val.slice(0, -2);
  return { name: nm[1], headEnd: h + 4, value: val };
}
function multipartGet(body, boundary, name) {
  for (const part of body.split('--' + boundary)) {
    const p = partValue(part);
    if (p && p.name === name) return p.value;
  }
  return undefined;
}
function multipartSet(body, boundary, name, value) {
  const delim = '--' + boundary;
  const parts = body.split(delim);
  for (let k = 0; k < parts.length; k++) {
    const p = partValue(parts[k]);
    if (p && p.name === name) {
      const trail = parts[k].endsWith('\r\n') ? '\r\n' : '';
      parts[k] = parts[k].slice(0, p.headEnd) + value + trail;
      return parts.join(delim);
    }
  }
  return body;
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
      } else if (r.in === 'form') {
        const v = queryGet(body, r.name); // x-www-form-urlencoded body: same shape as a query string
        if (v === undefined) continue;
        body = querySet(body, r.name, run(cipher, v));
      } else if (r.in === 'multipart') {
        const boundary = boundaryOf(headers);
        if (!boundary) continue;
        const v = multipartGet(body, boundary, r.name);
        if (v === undefined) continue;
        body = multipartSet(body, boundary, r.name, run(cipher, v));
      } else if (r.in === 'json') {
        json ??= JSON.parse(body);
        const paths = expand(json, r.parts); // [*]/..key fan out; a plain path stays single
        let any = false;
        for (const parts of paths) {
          const v = getAt(json, parts);
          if (v === undefined) continue;
          setAt(json, parts, direction === 'decrypt' ? embed(cipher.decrypt(v)) : cipher.encrypt(unembed(v)));
          any = true;
        }
        if (!any) continue;
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
      if (kind === 'form') { const v = queryGet(body, key); return v === undefined ? '' : v; }
      if (kind === 'multipart') { const bd = boundaryOf(headers); const v = bd ? multipartGet(body, bd, key) : undefined; return v === undefined ? '' : v; }
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
        else if (t.in === 'query') qs = querySetOrAdd(qs, t.name, value);
        else if (t.in === 'form') body = querySetOrAdd(body, t.name, value);
        else if (t.in === 'multipart') { const bd = boundaryOf(headers); if (bd) body = multipartSet(body, bd, t.name, value); }
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
  // Binary bodies travel to/from Burp as base64 (bodyEncoding). On encrypt the produced body is the
  // re-encrypted bytes (the in:body cipher's outEncoding should match), so Burp base64-decodes it back
  // to the wire. On decrypt the body is plaintext text for the editor, so the flag is dropped.
  if (direction === 'encrypt' && msg.bodyEncoding) out.bodyEncoding = msg.bodyEncoding;
  return { message: out, applied };
}
