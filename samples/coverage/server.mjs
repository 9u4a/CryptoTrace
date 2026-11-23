#!/usr/bin/env node
// Coverage-lab target (127.0.0.1 only, fake keys): one page + one API endpoint per case in cases.mjs.
//   node samples/coverage/server.mjs  -> http://127.0.0.1:8089/cov
// Each /cov/<id>/api request is decrypted the way the case's target would (400 if it rejects it) and kept as
// the raw request Burp would see (GET /cov/<id>/last), so the runner can replay it through the crypto server.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CASES } from './cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VENDOR = path.resolve(HERE, '../public/vendor');
const vendor = (f) => fs.readFileSync(path.join(VENDOR, f), 'utf8');

// Bundler shapes. A webpack 5 runtime (same order as the real one: queued chunks are read BEFORE `push` is
// replaced) and a chunk carrying crypto-js as module 101; an ES-module wrapper the way Vite/Rollup inline a
// CommonJS dependency (no global, no webpack registry).
const WP_RUNTIME = `(() => {
  var __webpack_modules__ = {}, __webpack_module_cache__ = {};
  function __webpack_require__(id) {
    var c = __webpack_module_cache__[id]; if (c !== undefined) return c.exports;
    var module = __webpack_module_cache__[id] = { exports: {} };
    __webpack_modules__[id].call(module.exports, module, module.exports, __webpack_require__);
    return module.exports;
  }
  var webpackJsonpCallback = (parent, data) => { var more = data[1]; for (var id in more) __webpack_modules__[id] = more[id]; if (parent) parent(data); };
  var chunkLoadingGlobal = self["webpackChunkcov_app"] = self["webpackChunkcov_app"] || [];
  chunkLoadingGlobal.forEach(webpackJsonpCallback.bind(null, 0));
  chunkLoadingGlobal.push = webpackJsonpCallback.bind(null, chunkLoadingGlobal.push.bind(chunkLoadingGlobal));
  window.__wpRequire = __webpack_require__;
})();`;
const wpChunk = () => `(self["webpackChunkcov_app"] = self["webpackChunkcov_app"] || []).push([[7], { 101: function (module, exports) {\n${vendor('crypto-js-4.2.0.js')}\n} }]);`;
const esModule = (file) => `const module = { exports: {} }; let exports = module.exports; const define = undefined;\n${vendor(file)}\n;export default module.exports;\n`;
const seedShim = () => `(function () { var exports = {};\n${vendor('kisa-seed-1.1.0.js')}\n;(typeof window !== 'undefined' ? window : self).KISA_SEED_CBC = exports.KISA_SEED_CBC; })();\n`;

function page(c) {
  const libs = (c.libs || []).map((s) => `<script src="${s}"></script>`).join('\n');
  const client = `(function ${c.client.toString()})();`;
  const main = c.module ? `<script type="module">\n${c.prelude || ''}\n${client}\nwindow.__ready = true;\n</script>` : `<script>\n${client}\nwindow.__ready = true;\n</script>`;
  // Manual use: an input + button that calls the case's __run, then shows what the target decrypted.
  // (The runner calls window.__run directly; the button only adds a GET of /cov/<id>/last.)
  const ui = `<p><input id="plain" size="50" value='{"t":"manual-test"}'> <button id="go">실행</button>
<a href="/cov">← 목록</a></p><p>기대 수준: <b>${c.expect}</b>${c.note ? ' — ' + c.note : ''}</p>
<pre id="out" style="background:#f4f4f4;padding:8px;white-space:pre-wrap"></pre>
<script>
document.getElementById('go').onclick = async () => {
  const out = document.getElementById('out');
  out.textContent = '전송 중...';
  try {
    await window.__run(document.getElementById('plain').value);
    const last = await (await fetch('/cov/${c.id}/last')).json();
    out.textContent = '대상 서버가 받은 요청: ' + (last.accepted ? '복호화 성공' : '거부 (' + last.error + ')') + '\\n평문: ' + (last.plain || '') +
      '\\n\\n원문 요청: ' + last.method + ' ' + last.path + '\\n' + last.headers.filter(([k]) => /^(content-type|cookie|x-)/i.test(k)).map(([k, v]) => k + ': ' + v).join('\\n') + '\\n\\n' + last.body;
  } catch (e) { out.textContent = '오류: ' + e.message; }
};
</script>`;
  return `<!doctype html><html><head><meta charset="utf-8"><title>cov ${c.id}</title></head><body style="font-family:sans-serif">
<h1>${c.id}</h1><p>${c.title}</p>
${ui}
${libs}
${main}
</body></html>`;
}

export function createCoverageServer() {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const pub = crypto.createPublicKey(privateKey);
  const key = {
    spki: pub.export({ type: 'spki', format: 'der' }).toString('base64'),
    pem: pub.export({ type: 'spki', format: 'pem' }),
    n: Buffer.from(jwk.n, 'base64url').toString('hex'),
    e: Buffer.from(jwk.e, 'base64url').toString('hex').replace(/^0+/, ''),
  };
  const ctx = { rsa: privateKey, session: { k: crypto.randomBytes(16), iv: crypto.randomBytes(16) } };
  const last = new Map();
  const byId = new Map(CASES.map((c) => [c.id, c]));

  const send = (res, status, body, type = 'application/json') => {
    res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  return http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const url = new URL(req.url, 'http://x');
      const p = url.pathname;
      try {
        if (p === '/cov' || p === '/cov/') {
          const rows = CASES.map((c) => `<tr><td><a href="/cov/${c.id}">${c.id}</a></td><td>${c.group}</td><td><b>${c.expect}</b></td><td>${c.title}</td></tr>`).join('');
          return send(res, 200, `<!doctype html><meta charset="utf-8"><title>CryptoTrace coverage lab</title><body style="font-family:sans-serif">
<h1>CryptoTrace coverage lab</h1><p>케이스를 열고 DevTools CryptoTrace 패널에서 Hook ON → 실행. 기대 수준: auto &gt; trace &gt; encrypt-only &gt; skip &gt; locate &gt; none</p>
<table border="1" cellpadding="4" style="border-collapse:collapse"><tr><th>case</th><th>group</th><th>expect</th><th>what</th></tr>${rows}</table></body>`, 'text/html');
        }
        if (p === '/cov/key') return send(res, 200, key);
        if (p === '/cov/agent') { // a stand-in for a native security agent: encrypts outside the page
          const c = crypto.createCipheriv('aes-128-cbc', Buffer.from('cov-agent-key-16'), Buffer.from('cov-agent-iv--16'));
          return send(res, 200, { ct: Buffer.concat([c.update(body), c.final()]).toString('base64') });
        }
        if (p === '/cov/session-handshake/key') return send(res, 200, { k: ctx.session.k.toString('base64'), iv: ctx.session.iv.toString('base64') });
        if (p.startsWith('/vendor/')) return send(res, 200, vendor(path.basename(p)), 'text/javascript');
        if (p === '/shim/kisa-seed.js') return send(res, 200, seedShim(), 'text/javascript');
        if (p === '/mod/crypto-js.mjs') return send(res, 200, esModule('crypto-js-4.2.0.js'), 'text/javascript');
        if (p === '/mod/aes-js.mjs') return send(res, 200, esModule('aes-js-3.1.2.js'), 'text/javascript');
        if (p === '/wp/runtime.js') return send(res, 200, WP_RUNTIME, 'text/javascript');
        if (p === '/wp/crypto-js-chunk.js') return send(res, 200, wpChunk(), 'text/javascript');
        const m = p.match(/^\/cov\/([\w-]+)(\/api|\/last|\/worker\.js)?$/);
        const c = m && byId.get(m[1]);
        if (!c) return send(res, 404, { error: 'not found' });
        if (!m[2]) return send(res, 200, page(c), 'text/html');
        if (m[2] === '/last') return send(res, 200, last.get(c.id) || null);
        if (m[2] === '/worker.js' && c.worker) return send(res, 200, `(function ${c.worker.toString()})();`, 'text/javascript');
        // the case's API endpoint: keep the raw request, then decrypt it like the target would
        const raw = { method: req.method, path: req.url, headers: Object.entries(req.headers), body, accepted: false };
        last.set(c.id, raw);
        const r = { method: req.method, headers: req.headers, body, query: url.searchParams,
          json: () => JSON.parse(body), form: () => new URLSearchParams(body) };
        try {
          const plain = c.decrypt(r, ctx);
          raw.accepted = true;
          raw.plain = plain;
          if (c.respond) { // an encrypted response the page decrypts; kept for the runner like the request
            const r = c.respond(plain, ctx);
            raw.response = { status: 200, headers: [['content-type', r.type]], body: r.body };
            return send(res, 200, r.body, r.type);
          }
          return send(res, 200, { ok: true, plain });
        } catch (e) {
          raw.error = e.message;
          return send(res, 400, { ok: false, error: e.message });
        }
      } catch (e) {
        return send(res, 400, { ok: false, error: e.message });
      }
    });
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT) || 8089;
  createCoverageServer().listen(port, '127.0.0.1', () => console.log(`CryptoTrace coverage lab: http://127.0.0.1:${port}/cov`));
}
