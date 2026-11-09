// Scenario C: crypto runs inside a Web Worker (page-world hooks can't see it; CDP auto-attach must).
// FAKE static AES-256-GCM key. Wire format: base64(iv[12] || ciphertext+tag).
'use strict';

const KEY_HEX = '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f';
const hex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const keyP = crypto.subtle.importKey('raw', hex(KEY_HEX), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

async function encrypt(plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await keyP, new TextEncoder().encode(plain)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return b64(out);
}

async function decrypt(text) {
  const raw = unb64(text.trim());
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, await keyP, raw.subarray(12));
  return new TextDecoder().decode(pt);
}

self.onmessage = async ({ data }) => {
  const result = data.op === 'encrypt' ? await encrypt(data.payload) : await decrypt(data.payload);
  self.postMessage({ id: data.id, result });
};
