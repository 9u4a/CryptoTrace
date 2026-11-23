'use strict';

/* Correlate captured crypto calls with where their ciphertext travels (fetch/XHR transport records), to
 * learn each cipher's apply location. Pure (no DOM): exposed as window.correlate(transportRecord, records),
 * which sets `apply` / `applyResponse` on the matching cipher records. Used by panel.js. */
(function () {
  // Match a ciphertext even when the field re-encodes it: URL-encoded, or base64 padding stripped.
  // JSON field values arrive already unescaped. Ciphertexts shorter than MIN_CT are too ambiguous to
  // correlate by substring (they would spuriously match unrelated fields), so they are ignored.
  const MIN_CT = 8;
  const _urldec = (s) => { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (_) { return String(s); } };
  function cipherMatch(value, target) {
    if (!value || !target || target.length < MIN_CT) return false;
    const hay = [String(value), _urldec(value)];
    const needles = [target, target.replace(/=+$/, '')];
    return hay.some((h) => needles.some((n) => n && n.length >= MIN_CT && h.includes(n)));
  }

  // ---- byte-level matching ------------------------------------------------
  // Many pages re-encode the cipher's bytes before sending (base64 -> hex, base64url) or glue the IV in
  // front, which plain substring matching can't see (a 16-byte prefix shifts base64 alignment). So a value
  // that didn't match as text is decoded as hex/base64/base64url and compared as bytes.
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; // leakcheck:allow
  function b64Decode(s) {
    const out = [];
    let acc = 0, bits = 0;
    for (const ch of s.replace(/=+$/, '')) {
      const v = B64.indexOf(ch);
      if (v < 0) return null;
      acc = ((acc << 6) | v) & 0xffffff; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    return out;
  }
  // Byte readings of a text value: [{encoding, bytes}].
  function readings(text) {
    const s = String(text || '').trim();
    const out = [];
    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
      const b = [];
      for (let i = 0; i < s.length; i += 2) b.push(parseInt(s.slice(i, i + 2), 16));
      out.push({ encoding: 'hex', bytes: b });
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s)) { const b = b64Decode(s); if (b) out.push({ encoding: 'base64', bytes: b }); }
    if (/^[A-Za-z0-9_-]+={0,2}$/.test(s) && /[-_]/.test(s)) {
      const b = b64Decode(s.replace(/-/g, '+').replace(/_/g, '/'));
      if (b) out.push({ encoding: 'base64url', bytes: b });
    }
    return out;
  }
  // Bytes of a recorded value (what the hook captured), if it is binary-encoded.
  function recordedBytes(v) {
    if (!v || v.value == null) return null;
    const r = readings(v.value).find((x) => x.encoding === v.encoding);
    return r ? r.bytes : null;
  }
  const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const endsWith = (a, b) => a.length >= b.length && b.every((x, i) => x === a[a.length - b.length + i]);

  // Where a recorded ciphertext sits in one transport value: text match, else byte match (re-encoded,
  // or IV-prefixed). Returns extra placement fields, or null.
  function placeIn(value, rec, key) {
    const target = rec[key] && rec[key].value;
    if (cipherMatch(value, target)) return {};
    const ct = recordedBytes(rec[key]);
    if (!ct || ct.length < MIN_CT) return null;
    for (const { encoding, bytes } of readings(value)) {
      const extra = encoding === rec[key].encoding ? {} : { encoding };
      if (sameBytes(bytes, ct)) return extra;
      if (bytes.length > ct.length && endsWith(bytes, ct)) {
        const prefix = bytes.slice(0, bytes.length - ct.length);
        const iv = recordedBytes(rec.iv);
        if (!iv || sameBytes(prefix, iv)) return { ...extra, ivPrefix: prefix.length };
      }
    }
    return null;
  }

  // The values a transport record carries, each with its location.
  function slotsOf(t) {
    const out = [];
    const b = t.body || {};
    if (b.kind === 'json' && Array.isArray(b.fields)) for (const f of b.fields) out.push({ loc: { in: 'json', path: f.path }, value: f.value });
    else if ((b.kind === 'form' || b.kind === 'multipart') && Array.isArray(b.fields)) for (const f of b.fields) out.push({ loc: { in: b.kind, name: f.name }, value: f.value });
    else if (b.kind === 'text' && b.sample) out.push({ loc: { in: 'body' }, value: b.sample });
    for (const [name, value] of t.headers || []) out.push({ loc: { in: 'header', name }, value });
    for (const [name, value] of t.query || []) out.push({ loc: { in: 'query', name }, value });
    return out;
  }

  // An IV the page sends in its own field (e.g. {iv, ct} JSON or an X-IV header), for the server's
  // iv {from:"field"}. Only locations the server can read an IV from.
  const IV_LOCS = new Set(['json', 'header', 'query', 'form']);
  function ivFieldOf(rec, slots, used) {
    const iv = recordedBytes(rec.iv);
    if (!iv || iv.length < 8) return null;
    for (const s of slots) {
      if (s === used || !IV_LOCS.has(s.loc.in)) continue;
      const hit = readings(s.value).find((r) => sameBytes(r.bytes, iv));
      if (hit) return { ...s.loc, encoding: hit.encoding };
    }
    return null;
  }

  // A request transport record: find where recent cipher OUTPUTS (ciphertext) are placed -> apply.
  // A response transport record: find where recent DECRYPT INPUTS (ciphertext) sit -> applyResponse.
  // `at` = the request path, used to pin rules per endpoint.
  function pathOf(url) {
    try { return new URL(url, 'http://x').pathname; } catch (_) { return ''; }
  }

  function place(t, candidates, key, prop, extra) {
    const at = pathOf(t.url);
    const slots = slotsOf(t);
    for (const slot of slots) {
      // the LONGEST matching ciphertext wins: the most specific placement, so a short output can't shadow the real one
      let best = null, bestExtra = null;
      for (const r of candidates) {
        const extra = placeIn(slot.value, r, key);
        if (extra && (!best || r[key].value.length >= best[key].value.length)) { best = r; bestExtra = extra; }
      }
      if (!best) continue;
      best[prop] = { ...slot.loc, at, ...bestExtra, ...extra };
      const ivf = ivFieldOf(best, slots, slot);
      if (ivf) best.ivApply = ivf;
    }
  }

  function correlate(t, records) {
    if (t.op === 'response') {
      const decs = records.filter((r) => r.op === 'decrypt' && r.input && r.input.value).slice(-80);
      return place(t, decs, 'input', 'applyResponse');
    }
    // a pure encoding step (a traced base64 helper: output text == input text) explains nothing -- skip it
    const outs = records.filter((r) => r.output && r.output.value && r.lib !== 'transport' && !(r.input && r.input.value === r.output.value)).slice(-80);
    // A WebSocket message is not an HTTP request: keep its placement apart so it never becomes an apply rule.
    if (t.op === 'websocket') return place(t, outs, 'output', 'applyWebSocket', { url: t.url });
    place(t, outs, 'output', 'apply');
  }

  // Does a captured crypto call already account for this traced value (same location, same endpoint)?
  // `origin` = hook-transport.js origin record {url, loc}. Unexplained ones are the "unknown" rows.
  function isExplained(origin, records) {
    const at = pathOf(origin.url);
    const l = origin.loc || {};
    const same = (a) => !!a && a.in === l.in && (a.path || '') === (l.path || '') && (a.name || '') === (l.name || '') && a.at === at;
    // ...including the field a captured call sends its IV in (a random IV looks like ciphertext, too)
    const ivAt = (r) => (r.ivApply ? { ...r.ivApply, at: (r.apply || r.applyResponse || {}).at } : null);
    return records.some((r) => same(r.apply) || same(r.applyWebSocket) || same(ivAt(r)));
  }

  window.correlate = correlate;
  window.isExplained = isExplained;
})();
