// End-to-end over the real stdio protocol against the sample target:
// plaintext request (as Burp would hold it) -> server encrypts -> sample target accepts -> server decrypts reply.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSampleServer } from '../../samples/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
let target, port, proc, rl, keyDir;
let seq = 0;
const waiting = new Map();

const call = (op, args = {}) =>
  new Promise((resolve) => {
    const id = ++seq;
    waiting.set(id, resolve);
    proc.stdin.write(JSON.stringify({ id, op, ...args }) + '\n');
  });

before(async () => {
  keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-e2e-'));
  target = createSampleServer({ keyDir });
  await new Promise((r) => target.listen(0, '127.0.0.1', r));
  port = target.address().port;

  // Sample configs pin port 8088; rewrite scope to the ephemeral port.
  const files = ['scenario-a.json', 'scenario-c.json'].map((f) => {
    const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'samples/configs', f), 'utf8'));
    cfg.scope.forEach((s) => (s.port = port));
    const out = path.join(keyDir, f);
    fs.writeFileSync(out, JSON.stringify(cfg));
    return out;
  });
  proc = spawn(process.execPath, [path.join(ROOT, 'server/src/main.mjs'), ...files.flatMap((f) => ['--config', f])]);
  rl = readline.createInterface({ input: proc.stdout });
  rl.on('line', (l) => {
    const m = JSON.parse(l);
    waiting.get(m.id)?.(m);
    waiting.delete(m.id);
  });
});

after(() => {
  proc.stdin.end();
  target.close();
  fs.rmSync(keyDir, { recursive: true, force: true });
});

async function send(request) {
  const headers = Object.fromEntries(request.headers);
  const res = await fetch(`http://127.0.0.1:${port}${request.path}`, { method: 'POST', headers, body: request.body });
  return { status: res.status, headers: [...res.headers.entries()], body: await res.text() };
}

test('health lists both sample profiles', async () => {
  const h = await call('health');
  assert.equal(h.ok, true);
  assert.deepEqual(h.profiles, ['sample-a-login', 'sample-c-profile']);
});

test('scenario A: edited plaintext JSON field is re-encrypted and accepted', async () => {
  const plain = {
    path: '/api/login',
    headers: [['Content-Type', 'application/json'], ['X-CT-Plain', '1']],
    body: JSON.stringify({ data: { id: '<script>bob</script>', pw: 'x' } }, null, 2),
  };
  const enc = await call('encryptRequest', { host: '127.0.0.1', port, request: plain });
  assert.equal(enc.ok, true);
  assert.equal(typeof JSON.parse(enc.request.body).data, 'string');

  const res = await send(enc.request);
  assert.equal(res.status, 200);
  const dec = await call('decryptResponse', { host: '127.0.0.1', port, path: '/api/login', response: res });
  assert.equal(JSON.parse(dec.response.body).msg, 'welcome <script>bob</script>');
});

test('scenario C: whole-body AES-GCM with IV prefix', async () => {
  const plain = {
    path: '/api/profile',
    headers: [['Content-Type', 'text/plain'], ['X-CT-Plain', '1']],
    body: JSON.stringify({ name: "Eve' OR 1=1--", email: 'e@shop.test' }),
  };
  const enc = await call('encryptRequest', { host: '127.0.0.1', port, request: plain });
  const res = await send(enc.request);
  assert.equal(res.status, 200);
  const dec = await call('decryptResponse', { host: '127.0.0.1', port, path: '/api/profile', response: res });
  assert.equal(JSON.parse(dec.response.body).msg, "profile saved for Eve' OR 1=1--");
});

test('protocol errors are reported, not fatal', async () => {
  const r = await call('nope');
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown op/);
  assert.equal((await call('health')).ok, true);
});
