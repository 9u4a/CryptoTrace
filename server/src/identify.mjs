// Cipher identification: a traced page function gave us plaintext/ciphertext pairs (selftest vectors) and
// key/IV candidates from its scopes, but not the algorithm. A cipher spec { identify: grid } lists the
// candidates; the first combination that reproduces every vector becomes the cipher.
//   grid: { algs: [...], keys: [keyRef...], ivs: [ {value,encoding} | {from:"prefix",...} | {from:"field",...} ],
//           paddings: ["pkcs7", "zero", "none"], inEncoding?, outEncoding? }
import { symmetricCipher } from './cipher.mjs';

const MAX_TRIES = 5000;

export function identifyCipher(grid, store, vectors) {
  let tried = 0;
  if (!vectors.length) return { cipher: null, tried, reason: 'no captured plaintext/ciphertext pair to identify it with' };
  const ivs = grid.ivs && grid.ivs.length ? grid.ivs : [null];
  for (const alg of grid.algs || []) {
    const isEcb = /-ecb$/i.test(alg);
    for (const keyRef of grid.keys || []) {
      const key = store[keyRef];
      if (!key) continue;
      for (const iv of isEcb ? [null] : ivs) {
        if (!isEcb && !iv) continue;
        for (const padding of grid.paddings || ['pkcs7']) {
          if (++tried > MAX_TRIES) return { cipher: null, tried, reason: `stopped after ${MAX_TRIES} candidates` };
          const spec = { alg, padding, inEncoding: grid.inEncoding || 'utf8', outEncoding: grid.outEncoding || 'base64', ...(iv ? { iv } : {}) };
          let c;
          try { c = symmetricCipher(spec, key); } catch (_) { continue; } // e.g. key length doesn't fit this algorithm
          const reproduces = (v) => {
            try { return c.decrypt(v.ciphertext, { getIv: () => v.iv }) === v.plain; } catch (_) { return false; }
          };
          if (vectors.every(reproduces)) return { cipher: c, tried, chosen: { alg, key: keyRef, ...(iv ? { iv } : {}), padding } };
        }
      }
    }
  }
  return { cipher: null, tried, reason: `none of ${tried} candidates reproduced the captured calls` };
}
