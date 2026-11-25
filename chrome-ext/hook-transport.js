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

  // Describe a request body for correlation: JSON leaf paths, form / multipart fields, or a scalar string.
  const formFields = (params) => { const out = []; params.forEach((value, name) => out.push({ name, value })); return out; };
  // key=value pairs. A lone `x=...` is too ambiguous (base64 padding looks like one), so without a form
  // Content-Type at least two pairs are required.
  const FORM_RE = /^[\w.\-[\]%]+=[^&]*(&[\w.\-[\]%]+=[^&]*)+$/;
  const MAX_TEXT_SAMPLE = 256 * 1024;
  const describeBody = (body, contentType) => {
    try {
      if (typeof URLSearchParams === 'function' && body instanceof URLSearchParams) return { kind: 'form', fields: formFields(body) };
      if (typeof FormData === 'function' && body instanceof FormData) {
        const fields = [];
        body.forEach((value, name) => { if (typeof value === 'string') fields.push({ name, value }); }); // files skipped
        return { kind: 'multipart', fields };
      }
    } catch (_) { /* fall through */ }
    if (typeof body === 'string' && body && (/x-www-form-urlencoded/i.test(contentType || '') || FORM_RE.test(body))) {
      try { return { kind: 'form', fields: formFields(new URLSearchParams(body)) }; } catch (_) { /* not a form after all */ }
    }
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
    // A long session would otherwise keep every large page/response body in the panel. A whole-body ciphertext
    // is far shorter than this; a longer text body can't be matched as one anyway.
    if (typeof body === 'string' && body.length > MAX_TEXT_SAMPLE) return { kind: 'text', sample: body.slice(0, MAX_TEXT_SAMPLE), truncated: body.length };
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

  // ---- outgoing data -> origin of values that look like ciphertext ----------
  // Every value a request carries that looks like ciphertext (16+ base64/hex chars, varied) is looked up in
  // hook.js's encoding-sink buffer; a hit is reported as an `origin` record with the page call stack that
  // built it. The panel shows it only when no captured crypto call already explains that location.
  const looksCipher = (v) => typeof v === 'string' && v.length >= 16 && /^[A-Za-z0-9+/=_%-]+$/.test(v) && new Set(v).size >= 8;
  const slotsOf = (rec) => {
    const out = [];
    const b = rec.body || {};
    if (b.kind === 'json') for (const f of b.fields || []) out.push([{ in: 'json', path: f.path }, f.value]);
    else if (b.kind === 'form' || b.kind === 'multipart') for (const f of b.fields || []) out.push([{ in: b.kind, name: f.name }, f.value]);
    else if (b.kind === 'text' && b.sample) out.push([{ in: 'body' }, b.sample]);
    for (const [name, value] of rec.headers || []) out.push([{ in: 'header', name }, value]);
    for (const [name, value] of rec.query || []) out.push([{ in: 'query', name }, value]);
    for (const [name, value] of rec.cookies || []) {
      let v = value;
      try { v = decodeURIComponent(value); } catch (_) {}
      out.push([{ in: 'cookie', name }, v]);
    }
    return out;
  };
  // Cookies the page itself can see (document.cookie) go out with same-origin requests: a ciphertext the page
  // stores in a cookie is placed there. Workers have no document.
  const cookiesOf = () => {
    try {
      const c = typeof document !== 'undefined' && document ? String(document.cookie || '') : '';
      return c.split(/;\s*/).filter(Boolean).map((p) => { const i = p.indexOf('='); return i < 0 ? [p, ''] : [p.slice(0, i), p.slice(i + 1)]; });
    } catch (_) { return []; }
  };
  const sent = (rec) => {
    rec.cookies = cookiesOf();
    send(rec);
    try {
      const lookup = globalThis.__ct_sinkLookup;
      if (typeof lookup !== 'function') return;
      for (const [loc, value] of slotsOf(rec)) {
        if (!looksCipher(value)) continue;
        const hit = lookup(value);
        if (hit) send({ lib: 'origin', op: 'origin', via: rec.op, url: rec.url, loc, value: value.slice(0, 120), sink: hit.sink, frames: hit.frames });
      }
    } catch (_) { /* observation only */ }
  };

  // ---- fetch -------------------------------------------------------------
  if (typeof globalThis.fetch === 'function') {
    const orig = globalThis.fetch;
    globalThis.fetch = function (input, init) {
      try {
        const url = typeof input === 'string' ? input : input && input.url;
        const method = (init && init.method) || (input && input.method) || 'GET';
        const isRequest = typeof Request === 'function' && input instanceof Request;
        const headers = parseHeaders((init && init.headers) || (isRequest ? input.headers : null));
        const ctype = (headers.find(([k]) => /^content-type$/i.test(k)) || [])[1];
        const record = (body) => sent({ lib: 'transport', op: 'fetch', url, method, query: queryOf(url), headers, body });
        if (isRequest && !(init && 'body' in init) && input.body) {
          // fetch(new Request(url, {body})): the body is a stream -- read a clone (before fetch consumes it)
          input.clone().text().then((text) => record(describeBody(text, ctype)), () => record(describeBody(null)));
        } else {
          record(describeBody(init ? init.body : null, ctype));
        }
      } catch (_) { /* never break the page's fetch */ }
      const p = orig.apply(this, arguments);
      try {
        const url = typeof input === 'string' ? input : input && input.url;
        p.then((res) => { try { res.clone().text().then((text) => send({ lib: 'transport', op: 'response', url, body: describeBody(text) })).catch(() => {}); } catch (_) {} }, () => {});
      } catch (_) { /* observation only; never alter the page's promise */ }
      return p;
    };
  }

  // ---- navigator.sendBeacon (a POST that outlives the page) ---------------
  const nav = globalThis.navigator;
  if (nav && typeof nav.sendBeacon === 'function') {
    const owner = Object.prototype.hasOwnProperty.call(nav, 'sendBeacon') ? nav : Object.getPrototypeOf(nav);
    const orig = owner.sendBeacon;
    owner.sendBeacon = function (url, data) {
      try { sent({ lib: 'transport', op: 'beacon', url: String(url), method: 'POST', query: queryOf(url), headers: [], body: describeBody(data) }); } catch (_) {}
      return orig.apply(this, arguments);
    };
  }

  // ---- WebSocket messages (shown in the panel; Burp does not rewrite WebSocket frames yet) ----
  const WS = globalThis.WebSocket;
  if (WS && WS.prototype && typeof WS.prototype.send === 'function') {
    const orig = WS.prototype.send;
    WS.prototype.send = function (data) {
      try { sent({ lib: 'transport', op: 'websocket', url: String(this.url || ''), headers: [], body: describeBody(data) }); } catch (_) {}
      return orig.apply(this, arguments);
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
        const ctype = ((c.headers || []).find(([k]) => /^content-type$/i.test(k)) || [])[1];
        sent({ lib: 'transport', op: 'xhr', url: c.url, method: c.method, query: queryOf(c.url),
          headers: c.headers || [], body: describeBody(body, ctype) });
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
