// Built-in ciphers: any OpenSSL block cipher Node exposes (AES/ARIA: cbc, ecb, ctr, gcm, ...) and RSA.
// A cipher turns a plaintext string into an encoded ciphertext string and back.
import crypto from 'node:crypto';
import { toBytes, fromBytes } from './encoding.mjs';

const OPENSSL = new Set(crypto.getCiphers());
const BLOCK = 16;

function pad(buf, padding) {
  if (padding === 'zero') {
    const n = (BLOCK - (buf.length % BLOCK)) % BLOCK;
    return Buffer.concat([buf, Buffer.alloc(n)]);
  }
  return buf;
}

function unpad(buf, padding) {
  if (padding !== 'zero') return buf;
  let end = buf.length;
  while (end > 0 && buf[end - 1] === 0) end--;
  return buf.subarray(0, end);
}

/**
 * Build a symmetric cipher.
 * spec: { alg, iv?: {value, encoding} | {from:"prefix", length}, padding?: pkcs7|none|zero,
 *         tag?: {length}, aad?: {value, encoding}, inEncoding?, outEncoding? }
 * keyBytes: Buffer
 */
export function symmetricCipher(spec, keyBytes) {
  const alg = spec.alg.toLowerCase();
  if (!OPENSSL.has(alg)) throw new Error(`cipher "${alg}" not available in this Node/OpenSSL build`);
  const isGcm = alg.endsWith('-gcm');
  const isEcb = alg.endsWith('-ecb');
  const padding = spec.padding || 'pkcs7';
  if (!['pkcs7', 'none', 'zero'].includes(padding)) throw new Error(`unknown padding "${padding}"`);
  const inEnc = spec.inEncoding || 'utf8';
  const outEnc = spec.outEncoding || 'base64';
  const tagLen = spec.tag?.length ?? 16;
  const ivPrefix = spec.iv?.from === 'prefix';
  const ivLen = ivPrefix ? spec.iv.length ?? (isGcm ? 12 : 16) : 0;
  const staticIv = !isEcb && !ivPrefix ? (spec.iv ? toBytes(spec.iv.value, spec.iv.encoding) : null) : null;
  if (!isEcb && !ivPrefix && !staticIv) throw new Error(`${alg} needs "iv"`);
  const aad = spec.aad ? toBytes(spec.aad.value, spec.aad.encoding) : null;
  const usePadding = !isGcm && !alg.includes('-ctr') && padding === 'pkcs7';

  return {
    deterministic: !ivPrefix,
    encrypt(plain) {
      const iv = ivPrefix ? crypto.randomBytes(ivLen) : staticIv;
      const c = crypto.createCipheriv(alg, keyBytes, isEcb ? null : iv, isGcm ? { authTagLength: tagLen } : undefined);
      c.setAutoPadding(usePadding);
      if (aad) c.setAAD(aad);
      const body = Buffer.concat([c.update(pad(toBytes(plain, inEnc), isGcm ? 'none' : padding)), c.final()]);
      const parts = [ivPrefix ? iv : null, body, isGcm ? c.getAuthTag() : null].filter(Boolean);
      return fromBytes(Buffer.concat(parts), outEnc);
    },
    decrypt(text) {
      let raw = toBytes(text.trim(), outEnc);
      let iv = staticIv;
      if (ivPrefix) {
        iv = raw.subarray(0, ivLen);
        raw = raw.subarray(ivLen);
      }
      const d = crypto.createDecipheriv(alg, keyBytes, isEcb ? null : iv, isGcm ? { authTagLength: tagLen } : undefined);
      d.setAutoPadding(usePadding);
      if (aad) d.setAAD(aad);
      if (isGcm) {
        d.setAuthTag(raw.subarray(raw.length - tagLen));
        raw = raw.subarray(0, raw.length - tagLen);
      }
      const out = Buffer.concat([d.update(raw), d.final()]);
      return fromBytes(unpad(out, isGcm ? 'none' : padding), inEnc);
    },
  };
}

function asKeyObject(bytesOrPem, kind) {
  const s = bytesOrPem.toString('utf8');
  if (s.includes('-----BEGIN')) return kind === 'public' ? crypto.createPublicKey(s) : crypto.createPrivateKey(s);
  return kind === 'public'
    ? crypto.createPublicKey({ key: bytesOrPem, format: 'der', type: 'spki' })
    : crypto.createPrivateKey({ key: bytesOrPem, format: 'der', type: 'pkcs8' });
}

/**
 * RSA cipher. spec: { alg:"rsa", padding: oaep|pkcs1, oaepHash?: sha1|sha256, inEncoding?, outEncoding? }
 * publicKey/privateKey: Buffer (DER spki/pkcs8) or PEM text bytes; privateKey optional.
 */
export function rsaCipher(spec, publicKey, privateKey) {
  const padding = spec.padding === 'pkcs1' ? crypto.constants.RSA_PKCS1_PADDING : crypto.constants.RSA_PKCS1_OAEP_PADDING;
  const oaepHash = spec.oaepHash || 'sha1';
  const inEnc = spec.inEncoding || 'utf8';
  const outEnc = spec.outEncoding || 'base64';
  const pub = publicKey ? asKeyObject(publicKey, 'public') : null;
  const priv = privateKey ? asKeyObject(privateKey, 'private') : null;
  return {
    deterministic: false,
    encrypt(plain) {
      if (!pub) throw new Error('RSA encrypt needs a public key');
      return fromBytes(crypto.publicEncrypt({ key: pub, padding, oaepHash }, toBytes(plain, inEnc)), outEnc);
    },
    decrypt(text) {
      if (!priv) throw new Error('RSA decrypt needs a private key (usually only the server has it)');
      return fromBytes(crypto.privateDecrypt({ key: priv, padding, oaepHash }, toBytes(text.trim(), outEnc)), inEnc);
    },
  };
}
