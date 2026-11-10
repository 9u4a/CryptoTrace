// Key derivation: turn a password / input-keying-material into the cipher key when the target
// doesn't use the key bytes directly. `spec.kdf` names the function; `spec.kdfParams` carries the
// salt/iterations/etc. The derived key length defaults to the cipher's AES bit size.
import crypto from 'node:crypto';
import { toBytes } from './encoding.mjs';

function keyLenFromAlg(alg) {
  const m = String(alg || '').match(/-(\d+)-/);
  return m ? Number(m[1]) / 8 : 32;
}

export function deriveKey(spec, ikm) {
  const p = spec.kdfParams || {};
  const keyLen = p.keyLen || keyLenFromAlg(spec.alg);
  const salt = p.salt ? toBytes(p.salt.value, p.salt.encoding || 'hex') : Buffer.alloc(0);
  const hash = (p.hash || 'sha256').toLowerCase();
  switch (spec.kdf) {
    case 'pbkdf2':
      return crypto.pbkdf2Sync(ikm, salt, p.iterations || 10000, keyLen, hash);
    case 'scrypt':
      return crypto.scryptSync(ikm, salt, keyLen, { N: p.N || 16384, r: p.r || 8, p: p.p || 1, maxmem: 64 * 1024 * 1024 });
    case 'hkdf': {
      const info = p.info ? toBytes(p.info.value, p.info.encoding || 'utf8') : Buffer.alloc(0);
      return Buffer.from(crypto.hkdfSync(hash, ikm, salt, info, keyLen));
    }
    default:
      throw new Error(`unknown kdf "${spec.kdf}"`);
  }
}
