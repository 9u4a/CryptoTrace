// Sample target client code. Keys are FAKE and hard-coded on purpose — this is what CryptoTrace must extract.
'use strict';

const $ = (id) => document.getElementById(id);
const log = (label, obj) => {
  $('log').textContent = `[${new Date().toLocaleTimeString()}] ${label}\n${JSON.stringify(obj, null, 2)}\n\n` + $('log').textContent;
};
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ---- A. CryptoJS AES-256-CBC, static key/IV ----
const A_KEY = CryptoJS.enc.Utf8.parse('ct-sample-aes-key-0123456789abcd');
const A_IV = CryptoJS.enc.Utf8.parse('ct-sample-iv-016');
const aOpts = { iv: A_IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 };

$('a-go').onclick = async () => {
  const plain = JSON.stringify({ id: $('a-id').value, pw: $('a-pw').value });
  const data = CryptoJS.AES.encrypt(plain, A_KEY, aOpts).toString();
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data }),
  });
  const text = await res.text();
  if (!res.ok) return log('A error', text);
  log('A login response', JSON.parse(CryptoJS.AES.decrypt(text, A_KEY, aOpts).toString(CryptoJS.enc.Utf8)));
};

// ---- B. RSA-OAEP envelope with a fresh AES-GCM key per request ----
let serverKey;
async function getServerKey() {
  if (serverKey) return serverKey;
  const { spki } = await (await fetch('/api/pubkey')).json();
  serverKey = await crypto.subtle.importKey('spki', unb64(spki), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  return serverKey;
}

$('b-go').onclick = async () => {
  const rsa = await getServerKey();
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify({ to: $('b-to').value, amount: Number($('b-amount').value) }));
  const body = {
    ek: b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsa, rawKey)),
    iv: b64(iv),
    ct: b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plain)),
  };
  const res = await fetch('/api/transfer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) return log('B error', await res.text());
  const out = await res.json();
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(out.iv) }, aesKey, unb64(out.ct));
  log('B transfer response', JSON.parse(new TextDecoder().decode(dec)));
};

// ---- C. Web Worker does the crypto, page only sends ----
const worker = new Worker('worker.js');
const pending = new Map();
let seq = 0;
worker.onmessage = ({ data }) => {
  pending.get(data.id)?.(data);
  pending.delete(data.id);
};
const callWorker = (op, payload) =>
  new Promise((resolve) => {
    const id = ++seq;
    pending.set(id, resolve);
    worker.postMessage({ id, op, payload });
  });

$('c-go').onclick = async () => {
  const plain = JSON.stringify({ name: $('c-name').value, email: $('c-email').value });
  const { result: body } = await callWorker('encrypt', plain);
  const res = await fetch('/api/profile', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body });
  const text = await res.text();
  if (!res.ok) return log('C error', text);
  const { result } = await callWorker('decrypt', text);
  log('C profile response', JSON.parse(result));
};
