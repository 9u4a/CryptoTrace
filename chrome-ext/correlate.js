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

  // Pick the candidate with the LONGEST matching ciphertext — the most specific placement, so a short
  // output can't shadow the real one.
  function bestMatch(value, candidates, key) {
    let best = null;
    for (const r of candidates) {
      const t = r[key] && r[key].value;
      if (cipherMatch(value, t) && (!best || t.length > best[key].value.length)) best = r;
    }
    return best;
  }

  // A request transport record: find where recent cipher OUTPUTS (ciphertext) are placed -> apply.request.
  // A response transport record: find where recent DECRYPT INPUTS (ciphertext) sit -> apply.response.
  // Request path of a transport record (relative or absolute URL), used to pin rules per endpoint.
  function pathOf(url) {
    try { return new URL(url, 'http://x').pathname; } catch (_) { return ''; }
  }

  function correlate(t, records) {
    if (t.op === 'response') return correlateResponse(t, records);
    const outs = records.filter((r) => r.output && r.output.value && r.lib !== 'transport').slice(-80);
    const find = (value) => bestMatch(value, outs, 'output');
    const at = pathOf(t.url);
    const b = t.body || {};
    if (b.kind === 'json' && Array.isArray(b.fields)) {
      for (const f of b.fields) { const hit = find(f.value); if (hit) hit.apply = { in: 'json', path: f.path, at }; }
    } else if ((b.kind === 'form' || b.kind === 'multipart') && Array.isArray(b.fields)) {
      for (const f of b.fields) { const hit = find(f.value); if (hit) hit.apply = { in: b.kind, name: f.name, at }; }
    } else if (b.kind === 'text' && b.sample) {
      const hit = find(b.sample); if (hit) hit.apply = { in: 'body', at };
    }
    for (const [name, value] of t.headers || []) { const hit = find(value); if (hit) hit.apply = { in: 'header', name, at }; }
    for (const [name, value] of t.query || []) { const hit = find(value); if (hit) hit.apply = { in: 'query', name, at }; }
  }

  function correlateResponse(t, records) {
    const decs = records.filter((r) => r.op === 'decrypt' && r.input && r.input.value).slice(-80);
    const find = (value) => bestMatch(value, decs, 'input');
    const b = t.body || {};
    if (b.kind === 'json' && Array.isArray(b.fields)) {
      for (const f of b.fields) { const hit = find(f.value); if (hit) hit.applyResponse = { in: 'json', path: f.path, at: pathOf(t.url) }; }
    } else if (b.kind === 'text' && b.sample) {
      const hit = find(b.sample); if (hit) hit.applyResponse = { in: 'body', at: pathOf(t.url) };
    }
  }

  window.correlate = correlate;
})();
