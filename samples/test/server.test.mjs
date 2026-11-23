// Round-trips every scenario with a Node client that mirrors public/app.js + worker.js.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { createSampleServer, aesCbcEncrypt, aesCbcDecrypt, gcmEncrypt, gcmDecrypt, C_KEY } from '../server.mjs';
import { E_KEY } from '../keys.mjs';

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

test('D: jsbn-style RSA PKCS#1 v1.5 (hex) in a urlencoded form field', async () => {
  const { modulus, exponent } = await (await fetch(base + '/api/rsakey')).json();
  assert.match(modulus, /^[0-9a-f]+$/);
  assert.equal(exponent, '10001');
  const pub = crypto.createPublicKey({ key: { kty: 'RSA', n: Buffer.from(modulus, 'hex').toString('base64url'), e: 'AQAB' }, format: 'jwk' });
  const enc = (s) => crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(s)).toString('hex');
  const ok = await post('/api/pin', `userId=minjun.kim&encPin=${enc('135790')}`, 'application/x-www-form-urlencoded');
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { ok: true, code: '0000', msg: 'pin verified for minjun.kim', data: { pinLength: 6 } });
  const bad = await post('/api/pin', `userId=minjun.kim&encPin=${enc('12ab')}`, 'application/x-www-form-urlencoded');
  assert.equal((await bad.json()).code, 'E403', 'a non-6-digit PIN is refused (reflected for payload tests)');
  // OpenSSL's implicit rejection (Marvin mitigation): bad PKCS#1 v1.5 ciphertext decrypts to random bytes
  // instead of throwing, so garbage is refused as a wrong PIN rather than with a 400.
  const garbage = await post('/api/pin', 'userId=x&encPin=00ff', 'application/x-www-form-urlencoded');
  assert.equal((await garbage.json()).code, 'E403');
});

test('E: AES-256-CBC static key, fresh IV per request in the X-Enc-IV header (hex); response {iv, data}', async () => {
  const key = Buffer.from(E_KEY, 'utf8');
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  const payload = Buffer.concat([c.update(JSON.stringify({ title: 'hi<b>', body: '문의' })), c.final()]).toString('base64');
  const res = await fetch(base + '/api/inquiry', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Enc-IV': iv.toString('hex') }, body: JSON.stringify({ payload, channel: 'WEB' }) });
  assert.equal(res.status, 200);
  const out = await res.json();
  const d = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(out.iv, 'base64'));
  const reply = JSON.parse(Buffer.concat([d.update(Buffer.from(out.data, 'base64')), d.final()]).toString());
  assert.equal(reply.msg, 'inquiry received: hi<b>');
  const bad = await fetch(base + '/api/inquiry', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Enc-IV': crypto.randomBytes(16).toString('hex') }, body: JSON.stringify({ payload }) });
  assert.equal(bad.status, 400, 'wrong IV -> the target rejects it');
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
