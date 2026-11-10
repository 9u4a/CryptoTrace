// Injected alongside hook.js. Watches fetch / XMLHttpRequest and reports where each
// outgoing request puts its data (body, a JSON field, a header, or a query param).
// The panel correlates these against recent cipher outputs to learn the "apply" location.
(() => {
  'use strict';
  if (globalThis.__cryptotrace_transport) return;
  globalThis.__cryptotrace_transport = true;

  const CHANNEL = '__cryptotrace__';
  const send = (rec) => {
    try {
      rec.t = Date.now();
      const line = JSON.stringify(rec);
      if (typeof globalThis.__cryptotrace_emit === 'function') globalThis.__cryptotrace_emit(line);
      else if (typeof postMessage === 'function') postMessage({ [CHANNEL]: line }, '*');
    } catch (_) { /* unserializable; skip */ }
  };

  // Describe a request body: scalar string, or the JSON leaf paths it contains.
  const describeBody = (body) => {
    if (typeof body !== 'string' || !body) return { kind: typeof body === 'string' ? 'text' : 'none', sample: '' };
    try {
      const j = JSON.parse(body);
      if (j && typeof j === 'object') {
        const fields = [];
        const walk = (v, path) => {
          if (v && typeof v === 'object') {
            for (const k of Object.keys(v)) walk(v[k], Array.isArray(v) ? `${path}[${k}]` : `${path}.${k}`);
          } else if (typeof v === 'string') {
            fields.push({ path, value: v });
          }
        };
        walk(j, '$');
        return { kind: 'json', fields };
      }
    } catch (_) { /* not json */ }
    return { kind: 'text', sample: body };
  };

  const parseHeaders = (headers) => {
    const out = [];
    if (!headers) return out;
    if (headers instanceof Headers) { headers.forEach((v, k) => out.push([k, v])); return out; }
    if (Array.isArray(headers)) return headers.map(([k, v]) => [String(k), String(v)]);
    for (const k of Object.keys(headers)) out.push([k, String(headers[k])]);
    return out;
  };

  const queryOf = (url) => {
    try {
      const u = new URL(url, globalThis.location && globalThis.location.href);
      return [...u.searchParams.entries()];
    } catch (_) { return []; }
  };

  // ---- fetch -------------------------------------------------------------
  if (typeof globalThis.fetch === 'function') {
    const orig = globalThis.fetch;
    globalThis.fetch = function (input, init) {
      try {
        const url = typeof input === 'string' ? input : input && input.url;
        const method = (init && init.method) || (input && input.method) || 'GET';
        const body = init && typeof init.body === 'string' ? init.body : null;
        send({ lib: 'transport', op: 'fetch', url, method, query: queryOf(url),
          headers: parseHeaders(init && init.headers), body: describeBody(body) });
      } catch (_) { /* never break the page's fetch */ }
      const p = orig.apply(this, arguments);
      try {
        const url = typeof input === 'string' ? input : input && input.url;
        p.then((res) => { try { res.clone().text().then((text) => send({ lib: 'transport', op: 'response', url, body: describeBody(text) })).catch(() => {}); } catch (_) {} }, () => {});
      } catch (_) { /* observation only; never alter the page's promise */ }
      return p;
    };
  }

  // ---- XMLHttpRequest ----------------------------------------------------
  const XHR = globalThis.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const open = XHR.prototype.open;
    const setH = XHR.prototype.setRequestHeader;
    const send_ = XHR.prototype.send;
    XHR.prototype.open = function (method, url) {
      this.__ct = { method, url, headers: [] };
      return open.apply(this, arguments);
    };
    XHR.prototype.setRequestHeader = function (k, v) {
      if (this.__ct) this.__ct.headers.push([String(k), String(v)]);
      return setH.apply(this, arguments);
    };
    XHR.prototype.send = function (body) {
      try {
        const c = this.__ct || {};
        send({ lib: 'transport', op: 'xhr', url: c.url, method: c.method, query: queryOf(c.url),
          headers: c.headers || [], body: describeBody(typeof body === 'string' ? body : null) });
        this.addEventListener('load', function () {
          try {
            const text = this.responseType === '' || this.responseType === 'text' ? this.responseText : null;
            if (text) send({ lib: 'transport', op: 'response', url: c.url, body: describeBody(text) });
          } catch (_) { /* responseText not accessible for this responseType */ }
        });
      } catch (_) { /* skip */ }
      return send_.apply(this, arguments);
    };
  }
})();
