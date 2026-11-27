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
    // ciphers the server picked from a traced function's candidates (Burp log: "  IDENTIFIED c1 = seed-cbc ...")
    const ids = log.map((l) => String(l).match(/IDENTIFIED (\S+) = (\S+)/)).filter(Boolean).map((m) => `${m[1]}=${m[2]}`);
    const idText = ids.length ? ` · identified ${ids.join(', ')}` : '';
    if (reply.ok) return { ok: true, text: 'Burp: loaded' + tests + idText + (reply.status ? ` · ${reply.status}` : '') };
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

  // ---- L4 browser oracle: Burp hands out jobs ({oid, fn, value}) the page's own function must compute ----
  /** Long-poll Burp for the next job. -> {enabled, job?} or {error}. */
  // `origin`: the inspected page's origin, so Burp hands this panel only jobs for functions traced on that origin
  // (with several tabs open, each panel gets its own).
  // `graceMs`: how long past `waitMs` to wait for Burp. A poll in flight when the extension is reloaded (or Burp
  // restarts) can stay unanswered forever; without a limit the panel loop would hang showing "waiting".
  async function oracleNext(fetchFn, { port, token }, waitMs, origin, graceMs = 5000) {
    if (!token) return { error: 'Burp token not set' };
    const wait = Math.max(0, Number(waitMs) || 0);
    const ctl = typeof AbortController === 'function' ? new AbortController() : null;
    let timer = null;
    const expired = new Promise((_, reject) => {
      if (typeof setTimeout === 'function') timer = setTimeout(() => { if (ctl) ctl.abort(); reject(new Error('poll timeout')); }, wait + graceMs);
    });
    try {
      const q = '/oracle/next?wait=' + wait + (origin ? '&origin=' + encodeURIComponent(origin) : '');
      const init = { method: 'GET', headers: { Authorization: 'Bearer ' + token } };
      if (ctl) init.signal = ctl.signal;
      const res = await Promise.race([fetchFn(endpoint(port, q), init), expired]);
      if (res.status === 401) return { error: 'Burp rejected the token' };
      const body = await Promise.race([res.json(), expired]).catch(() => null);
      if (!body) return { error: 'HTTP ' + res.status };
      return { enabled: !!body.enabled, job: body.job || null };
    } catch (_) {
      return { error: `Burp not reachable on 127.0.0.1:${Number(port) || DEFAULT_PORT}` };
    } finally {
      if (timer !== null) clearTimeout(timer);
    }
  }

  /** Post one job's answer: {oid, ok, value} | {oid, ok: false, error}. */
  async function oracleResult(fetchFn, { port, token }, answer) {
    try {
      await fetchFn(endpoint(port, '/oracle/result'), {
        method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify(answer),
      });
      return true;
    } catch (_) {
      return false;
    }
  }

  window.CryptoTraceBridge = { DEFAULT_PORT, endpoint, summarize, send, ping, oracleNext, oracleResult };
})();
