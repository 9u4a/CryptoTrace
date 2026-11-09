// Round-trips every scenario with a Node client that mirrors public/app.js + worker.js.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { createSampleServer, aesCbcEncrypt, aesCbcDecrypt, gcmEncrypt, gcmDecrypt, C_KEY } from '../server.mjs';

let server, base, keyDir;

before(async () => {
  keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-samples-'));
  server = createSampleServer({ keyDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  fs.rmSync(keyDir, { recursive: true, force: true });
});

const post = (p, body, type = 'application/json') =>
  fetch(base + p, { method: 'POST', headers: { 'Content-Type': type }, body });

test('A: CryptoJS-compatible AES-CBC JSON field, encrypted response echoes input', async () => {
  const data = aesCbcEncrypt(JSON.stringify({ id: 'alice<x>', pw: 'p' }));
  const res = await post('/api/login', JSON.stringify({ data }));
  assert.equal(res.status, 200);
  const reply = JSON.parse(aesCbcDecrypt(await res.text()));
  assert.equal(reply.ok, true);
  assert.equal(reply.msg, 'welcome alice<x>');
});

test('A: tampered ciphertext is rejected', async () => {
  const res = await post('/api/login', JSON.stringify({ data: 'AAAA' + aesCbcEncrypt('{}').slice(4) }));
  assert.equal(res.status, 400);
});

test('B: RSA-OAEP envelope with per-request AES-GCM key', async () => {
  const { spki } = await (await fetch(base + '/api/pubkey')).json();
  const pub = crypto.createPublicKey({ key: Buffer.from(spki, 'base64'), format: 'der', type: 'spki' });
  const aesKey = crypto.randomBytes(32);
  const ek = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aesKey);
  const { iv, ct } = gcmEncrypt(aesKey, JSON.stringify({ to: '110', amount: 5 }));
  const res = await post('/api/transfer', JSON.stringify({ ek: ek.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') }));
  assert.equal(res.status, 200);
  const out = await res.json();
  const reply = JSON.parse(gcmDecrypt(aesKey, Buffer.from(out.iv, 'base64'), Buffer.from(out.ct, 'base64')));
  assert.equal(reply.msg, 'sent 5 to 110');
});

test('C: AES-GCM whole body with IV prefix', async () => {
  const { iv, ct } = gcmEncrypt(C_KEY, JSON.stringify({ name: 'Bob', email: 'b@shop.test' }));
  const res = await post('/api/profile', Buffer.concat([iv, ct]).toString('base64'), 'text/plain');
  assert.equal(res.status, 200);
  const raw = Buffer.from(await res.text(), 'base64');
  assert.equal(JSON.parse(gcmDecrypt(C_KEY, raw.subarray(0, 12), raw.subarray(12))).msg, 'profile saved for Bob');
});

test('static files served, traversal blocked', async () => {
  assert.equal((await fetch(base + '/')).status, 200);
  assert.equal((await fetch(base + '/worker.js')).status, 200);
  assert.equal((await fetch(base + '/..%2Fkeys.mjs')).status, 404);
});

test('RSA key persists across restarts in keyDir', () => {
  const a = createSampleServer({ keyDir });
  const b = createSampleServer({ keyDir });
  a.close();
  b.close();
  assert.ok(fs.existsSync(path.join(keyDir, 'rsa-private.pem')));
});
