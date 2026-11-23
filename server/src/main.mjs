#!/usr/bin/env node
// CryptoTrace local crypto server — stdio transport (Burp launches this as a child process).
//
//   node server/src/main.mjs [--config a.json --config b.json ...]
//
// Protocol: one JSON object per line.
//   in : {"id": 1, "op": "decryptRequest", ...}
//   out: {"id": 1, "ok": true, ...result} | {"id": 1, "ok": false, "error": "..."}
// Diagnostics go to stderr only; stdout carries protocol lines exclusively.
import readline from 'node:readline';
import { createEngine, VERSION } from './engine.mjs';

const engine = createEngine();
const write = (obj) => process.stdout.write(JSON.stringify(obj) + '\n');

const files = [];
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === '--config' && process.argv[i + 1]) files.push(process.argv[++i]);
}
if (files.length) {
  for (const r of engine.handle({ op: 'load', files }).results) {
    const st = r.error ? `ERROR ${r.error}` : r.selftest.map((t) => `${t.cipher}:${t.ok ? 'ok' : t.error}`).join(' ') || 'no selftest vectors';
    process.stderr.write(`[cryptotrace] ${r.file}: ${st}\n`);
  }
}
process.stderr.write(`[cryptotrace] server ${VERSION} ready (stdio)\n`);

// Browser oracle (L4): when a request needs a page-computed value, the server asks Burp with a line
//   out: {"oracle": {"oid": 7, "cipher", "fn", "frame", "dir": "encrypt", "value"}}
// and Burp answers (after asking the browser) with
//   in : {"oracleResult": 7, "ok": true, "value": "..."} | {"oracleResult": 7, "ok": false, "error": "..."}
// Requests are handled concurrently; responses carry their id, so order doesn't matter.
const ORACLE_TIMEOUT_MS = Number(process.env.CT_ORACLE_TIMEOUT_MS) || 8000; // < Burp's 12 s call timeout
let oseq = 0;
const asked = new Map();
const oracleCall = (job) => new Promise((resolve, reject) => {
  const oid = ++oseq;
  const timer = setTimeout(() => { asked.delete(oid); reject(new Error('the browser did not answer in time (oracle on in Burp, tab open?)')); }, ORACLE_TIMEOUT_MS);
  asked.set(oid, { resolve, reject, timer });
  write({ oracle: { oid, ...job } });
});

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    return write({ id: null, ok: false, error: 'invalid JSON line' });
  }
  if (req.oracleResult != null) {
    const w = asked.get(req.oracleResult);
    if (!w) return;
    asked.delete(req.oracleResult);
    clearTimeout(w.timer);
    if (req.ok) w.resolve(req.value);
    else w.reject(new Error(req.error || 'oracle call failed'));
    return;
  }
  engine.handleAsync(req, oracleCall).then(
    (res) => write({ id: req.id ?? null, ok: true, ...res }),
    (e) => write({ id: req.id ?? null, ok: false, error: e.message }),
  );
});
rl.on('close', () => process.exit(0));
