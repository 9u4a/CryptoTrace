#!/usr/bin/env node
// Self-made sample target for CryptoTrace E2E. Offline, zero deps, binds 127.0.0.1 only.
//   node samples/server.mjs          → http://127.0.0.1:8088
//
// Scenarios (each request is decrypted + validated here; bad ciphertext → 400):
//   A  POST /api/login     CryptoJS AES-256-CBC, static key/IV. JSON field $.data encrypted; response body encrypted.
//   B  POST /api/transfer  WebCrypto RSA-OAEP(SHA-256) envelope: per-request random AES-256-GCM key.
//                          Body {ek, iv, ct}; response {iv, ct} under the same AES key.  (GET /api/pubkey → SPKI)
//   C  POST /api/profile   WebCrypto AES-256-GCM inside a Web Worker, static key.
//                          Body = base64(iv[12] || ciphertext+tag); response same format.
//   D  POST /api/pin       jsbn RSAKey (Tom Wu rsa.js) PKCS#1 v1.5, hex output, in a urlencoded form field
//                          `encPin`. Key from GET /api/rsakey {modulus, exponent} (hex), the usual Korean shape.
//   E  POST /api/inquiry   WebCrypto AES-256-CBC, static key, fresh IV per request in the X-Enc-IV header (hex).
//                          Body {payload: base64(ct), channel}; response {iv: base64, data: base64(ct)}.
//   GET  /api/accounts   plain JSON (fake demo accounts), mixed in like a real app.
// Responses echo user input so reflected-payload detection can be tested through Burp.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { A_KEY, A_IV, C_KEY_HEX, C_IV_LEN, E_KEY } from './keys.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(DIR, 'public');
const KEY_DIR = path.join(DIR, '.keys'); // gitignored; generated on first run
const MAX_BODY = 1024 * 1024;
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.md': 'text/plain' };

// ---- crypto helpers (shared with tests) ----
export function aesCbcEncrypt(plain) {
  const c = crypto.createCipheriv('aes-256-cbc', Buffer.from(A_KEY, 'utf8'), Buffer.from(A_IV, 'utf8'));
  return Buffer.concat([c.update(plain, 'utf8'), c.final()]).toString('base64');
}
export function aesCbcDecrypt(b64) {
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(A_KEY, 'utf8'), Buffer.from(A_IV, 'utf8'));
  return Buffer.concat([d.update(Buffer.from(b64, 'base64')), d.final()]).toString('utf8');
}
export function gcmEncrypt(key, plain, iv = crypto.randomBytes(C_IV_LEN)) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final(), c.getAuthTag()]);
  return { iv, ct };
}
export function gcmDecrypt(key, iv, ctWithTag) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(ctWithTag.subarray(-16));
  return Buffer.concat([d.update(ctWithTag.subarray(0, -16)), d.final()]).toString('utf8');
}
export const C_KEY = Buffer.from(C_KEY_HEX, 'hex');

export function loadRsaKeys(dir = KEY_DIR) {
  const priv = path.join(dir, 'rsa-private.pem');
  if (!fs.existsSync(priv)) {
    fs.mkdirSync(dir, { recursive: true });
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    fs.writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(priv));
  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64');
  return { privateKey, spki };
}

// ---- HTTP ----
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) reject(new Error('body too large'));
      else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function send(res, status, body, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function serveStatic(req, res) {
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = path.normalize(path.join(PUBLIC, rel === '/' ? 'index.html' : rel));
  if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    return send(res, 404, { error: 'not found' });
  }
  send(res, 200, fs.readFileSync(file, 'utf8'), TYPES[path.extname(file)] || 'application/octet-stream');
}

export function createSampleServer({ keyDir = KEY_DIR } = {}) {
  const rsa = loadRsaKeys(keyDir);

  // Fake in-memory demo data so responses look like a real banking API (all values fictional).
  const accounts = [
    { acctNo: '1002-845-112233', nick: '데모 입출금통장', type: 'DEPOSIT', balance: 3482150 },
    { acctNo: '1002-845-445566', nick: '데모 비상금통장', type: 'SAVING', balance: 12000000 },
  ];
  const banks = { '004': '가나은행', '011': '다라은행', '020': '마바은행', '088': '사아은행', '090': '자차뱅크' };
  const mask = (s, keep = 4) => (s.length <= keep ? s : '*'.repeat(s.length - keep) + s.slice(-keep));
  const now = () => new Date().toISOString().replace('Z', '+00:00');
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const fakeJwt = (sub) =>
    `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub, iss: 'auth.demobank.test', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 1800 })}.${crypto.randomBytes(32).toString('base64url')}`;

  const routes = {
    'GET /api/pubkey': async () => [200, { spki: rsa.spki }],

    'GET /api/rsakey': async () => {
      const jwk = rsa.privateKey.export({ format: 'jwk' });
      return [200, { modulus: Buffer.from(jwk.n, 'base64url').toString('hex'), exponent: Buffer.from(jwk.e, 'base64url').toString('hex').replace(/^0+/, '') }];
    },

    'POST /api/pin': async (body) => {
      const form = new URLSearchParams(body);
      const userId = form.get('userId') ?? '';
      const pin = crypto.privateDecrypt({ key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(form.get('encPin') ?? '', 'hex')).toString('utf8');
      if (!/^\d{6}$/.test(pin)) return [200, { ok: false, code: 'E403', msg: `invalid pin for ${userId}` }];
      return [200, { ok: true, code: '0000', msg: `pin verified for ${userId}`, data: { pinLength: pin.length } }];
    },

    'POST /api/inquiry': async (body, req) => {
      const key = Buffer.from(E_KEY, 'utf8');
      const iv = Buffer.from(String(req.headers['x-enc-iv'] || ''), 'hex');
      const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
      const q = JSON.parse(Buffer.concat([d.update(Buffer.from(JSON.parse(body).payload, 'base64')), d.final()]).toString('utf8'));
      const reply = JSON.stringify({ ok: true, code: '0000', msg: `inquiry received: ${q.title}`,
        data: { ticketNo: 'Q' + Date.now(), category: q.category ?? null, receivedAt: now() } });
      const riv = crypto.randomBytes(16);
      const c = crypto.createCipheriv('aes-256-cbc', key, riv);
      return [200, { iv: riv.toString('base64'), data: Buffer.concat([c.update(reply), c.final()]).toString('base64') }];
    },

    'GET /api/accounts': async () => [200, { code: '0000', data: accounts.map((a) => ({ ...a })) }],

    'POST /api/login': async (body) => {
      const { data } = JSON.parse(body);
      const { id, pw, deviceId } = JSON.parse(aesCbcDecrypt(data));
      const ok = typeof id === 'string' && typeof pw === 'string';
      const reply = JSON.stringify({
        ok,
        code: ok ? '0000' : 'E401',
        msg: `welcome ${id}`,
        token: crypto.randomUUID(),
        data: {
          custNo: 'C2025' + String(100000 + (id.length * 7919) % 900000),
          custName: '김*준',
          loginId: id,
          grade: 'GOLD',
          deviceId: deviceId ?? null,
          lastLoginAt: '2026-11-18T21:04:33+09:00',
          lastLoginIp: '127.0.0.1',
          accessToken: fakeJwt(id),
          refreshToken: crypto.randomBytes(24).toString('hex'),
          expiresIn: 1800,
        },
      });
      return [200, aesCbcEncrypt(reply), 'text/plain'];
    },

    'POST /api/transfer': async (body) => {
      const { ek, iv, ct } = JSON.parse(body);
      const aesKey = crypto.privateDecrypt(
        { key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(ek, 'base64'),
      );
      const req = JSON.parse(gcmDecrypt(aesKey, Buffer.from(iv, 'base64'), Buffer.from(ct, 'base64')));
      const from = accounts.find((a) => a.acctNo === req.fromAcct) ?? accounts[0];
      const amount = Number(req.amount) || 0;
      from.balance -= amount;
      const reply = JSON.stringify({
        ok: true,
        code: '0000',
        msg: `sent ${req.amount} to ${req.to}`,
        data: {
          txId: 'TX' + Date.now() + crypto.randomInt(100, 999),
          txDt: now(),
          fromAcct: from.acctNo,
          toBankNm: banks[req.toBankCd] ?? req.toBankCd ?? null,
          toAcct: mask(String(req.to ?? '')),
          toName: req.toName ?? null,
          amount,
          fee: 0,
          memo: req.memo ?? '',
          balanceAfter: from.balance,
        },
      });
      const out = gcmEncrypt(aesKey, reply);
      return [200, { iv: out.iv.toString('base64'), ct: out.ct.toString('base64') }];
    },

    'POST /api/profile': async (body) => {
      const raw = Buffer.from(body.trim(), 'base64');
      const req = JSON.parse(gcmDecrypt(C_KEY, raw.subarray(0, C_IV_LEN), raw.subarray(C_IV_LEN)));
      const reply = JSON.stringify({
        ok: true,
        code: '0000',
        msg: `profile saved for ${req.name}`,
        data: { ...req, custNo: 'C2025104729', updatedAt: now() },
      });
      const out = gcmEncrypt(C_KEY, reply);
      return [200, Buffer.concat([out.iv, out.ct]).toString('base64'), 'text/plain'];
    },
  };

  return http.createServer(async (req, res) => {
    const route = routes[`${req.method} ${new URL(req.url, 'http://x').pathname}`];
    if (!route) return req.method === 'GET' ? serveStatic(req, res) : send(res, 404, { error: 'not found' });
    try {
      const [status, body, type] = await route(await readBody(req), req);
      send(res, status, body, type);
    } catch (e) {
      send(res, 400, { error: 'decrypt/validate failed', detail: e.message });
    }
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT) || 8088;
  createSampleServer().listen(port, '127.0.0.1', () => {
    console.log(`CryptoTrace sample target: http://127.0.0.1:${port}`);
  });
}
