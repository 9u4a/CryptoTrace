'use strict';
/* Send to Burp (0.3.0): posts the built config to the CryptoTrace Burp extension's local bridge
 * (127.0.0.1 only, pairing token from Burp's CryptoTrace tab). Exposed as window.CryptoTraceBridge.
 * Pure apart from the injected fetch, so it is unit-tested under node. */
(function () {
  const DEFAULT_PORT = 17777;

  function endpoint(port, path) {
    const p = Number(port) || DEFAULT_PORT;
    return 'http://127.0.0.1:' + p + path;
  }

  /** One-line result for the panel status from the bridge's JSON reply. */
  function summarize(reply) {
    if (!reply || typeof reply !== 'object') return { ok: false, text: 'Burp: unexpected reply' };
    if (reply.error) return { ok: false, text: 'Burp: ' + reply.error };
    const log = Array.isArray(reply.log) ? reply.log : [];
    let pass = 0;
    let fail = 0;
    for (const line of log) {
      pass += (String(line).match(/=OK\b/g) || []).length;
      fail += (String(line).match(/=FAIL\(/g) || []).length;
    }
    const errors = log.filter((l) => /^ERROR /.test(l));
    const tests = pass + fail ? ` · selftest ${pass}/${pass + fail}` : '';
    if (reply.ok) return { ok: true, text: 'Burp: loaded' + tests + (reply.status ? ` · ${reply.status}` : '') };
    const why = errors.length ? errors[errors.length - 1].replace(/^ERROR /, '') : reply.status || 'load failed';
    return { ok: false, text: 'Burp: ' + why + tests };
  }

  async function call(fetchFn, { port, token }, path, init) {
    if (!token) return { ok: false, text: 'Burp token not set -- paste it from Burp > CryptoTrace tab' };
    let res;
    try {
      res = await fetchFn(endpoint(port, path), {
        ...init,
        headers: { ...(init && init.headers), Authorization: 'Bearer ' + token },
      });
    } catch (_) {
      return { ok: false, text: `Burp not reachable on 127.0.0.1:${Number(port) || DEFAULT_PORT} -- is Burp running with CryptoTrace loaded?` };
    }
    let body = null;
    try { body = await res.json(); } catch (_) { /* non-JSON */ }
    if (res.status === 401) return { ok: false, text: 'Burp rejected the token -- copy it again from Burp > CryptoTrace tab' };
    return summarize(body || { error: 'HTTP ' + res.status });
  }

  function send(fetchFn, opts, cfg) {
    return call(fetchFn, opts, '/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    });
  }

  async function ping(fetchFn, opts) {
    const r = await call(fetchFn, opts, '/ping', { method: 'GET' });
    return r.ok ? { ok: true, text: `Burp: connected (127.0.0.1:${Number(opts.port) || DEFAULT_PORT})` } : r;
  }

  window.CryptoTraceBridge = { DEFAULT_PORT, endpoint, summarize, send, ping };
})();
