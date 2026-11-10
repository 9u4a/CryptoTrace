// The SEA bundle must be functionally identical to server/src. Build it with the real bundler,
// run it over stdio, and check health + a loaded profile's selftest + an encrypt/decrypt round-trip.
// Guards against a future import/export form the line-oriented bundler doesn't handle.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import readline from 'node:readline';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const BUNDLE = path.join(ROOT, 'dist', 'server-bundle.cjs');
const SCENARIO_A = path.join(ROOT, 'samples/configs/scenario-a.json');
const PROFILE = JSON.parse(fs.readFileSync(SCENARIO_A, 'utf8')).profile;
let proc, rl, seq = 0;
const waiting = new Map();
const call = (op, args = {}) =>
  new Promise((resolve) => { const id = ++seq; waiting.set(id, resolve); proc.stdin.write(JSON.stringify({ id, op, ...args }) + '\n'); });

before(() => {
  execFileSync(process.execPath, ['scripts/bundle-server.mjs'], { cwd: ROOT, stdio: 'ignore' });
  proc = spawn(process.execPath, [BUNDLE]);
  rl = readline.createInterface({ input: proc.stdout });
  rl.on('line', (l) => { const m = JSON.parse(l); waiting.get(m.id)?.(m); waiting.delete(m.id); });
});

after(() => { rl?.close(); proc?.kill(); });

test('bundled server answers health and loads a profile with passing selftest', async () => {
  const h = await call('health');
  assert.equal(h.ok, true);
  assert.equal(h.version, '0.1.0');

  const l = await call('load', { files: [SCENARIO_A] });
  const r = l.results[0];
  assert.equal(r.error, undefined, r.error);
  assert.ok(r.selftest.length > 0 && r.selftest.every((t) => t.ok), JSON.stringify(r.selftest));
});

test('bundled server encrypt/decrypt round-trips a value', async () => {
  await call('load', { files: [SCENARIO_A] });
  const plain = '{"hello":"world"}';
  const enc = await call('encrypt', { profile: PROFILE, cipher: 'c1', value: plain });
  assert.equal(enc.ok, true, enc.error);
  const dec = await call('decrypt', { profile: PROFILE, cipher: 'c1', value: enc.value });
  assert.equal(dec.value, plain);
});
