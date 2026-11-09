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
// Responses echo user input so reflected-payload detection can be tested through Burp.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { A_KEY, A_IV, C_KEY_HEX, C_IV_LEN } from './keys.mjs';

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

  const routes = {
    'GET /api/pubkey': async () => [200, { spki: rsa.spki }],

    'POST /api/login': async (body) => {
      const { data } = JSON.parse(body);
      const { id, pw } = JSON.parse(aesCbcDecrypt(data));
      const ok = typeof id === 'string' && typeof pw === 'string';
      const reply = JSON.stringify({ ok, msg: `welcome ${id}`, token: crypto.randomUUID() });
      return [200, aesCbcEncrypt(reply), 'text/plain'];
    },

    'POST /api/transfer': async (body) => {
      const { ek, iv, ct } = JSON.parse(body);
      const aesKey = crypto.privateDecrypt(
        { key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(ek, 'base64'),
      );
      const req = JSON.parse(gcmDecrypt(aesKey, Buffer.from(iv, 'base64'), Buffer.from(ct, 'base64')));
      const reply = JSON.stringify({ ok: true, msg: `sent ${req.amount} to ${req.to}` });
      const out = gcmEncrypt(aesKey, reply);
      return [200, { iv: out.iv.toString('base64'), ct: out.ct.toString('base64') }];
    },

    'POST /api/profile': async (body) => {
      const raw = Buffer.from(body.trim(), 'base64');
      const req = JSON.parse(gcmDecrypt(C_KEY, raw.subarray(0, C_IV_LEN), raw.subarray(C_IV_LEN)));
      const reply = JSON.stringify({ ok: true, msg: `profile saved for ${req.name}` });
      const out = gcmEncrypt(C_KEY, reply);
      return [200, Buffer.concat([out.iv, out.ct]).toString('base64'), 'text/plain'];
    },
  };

  return http.createServer(async (req, res) => {
    const route = routes[`${req.method} ${new URL(req.url, 'http://x').pathname}`];
    if (!route) return req.method === 'GET' ? serveStatic(req, res) : send(res, 404, { error: 'not found' });
    try {
      const [status, body, type] = await route(await readBody(req));
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
