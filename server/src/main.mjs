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

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    return write({ id: null, ok: false, error: 'invalid JSON line' });
  }
  try {
    write({ id: req.id ?? null, ok: true, ...engine.handle(req) });
  } catch (e) {
    write({ id: req.id ?? null, ok: false, error: e.message });
  }
});
rl.on('close', () => process.exit(0));
