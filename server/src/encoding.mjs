// Byte <-> string encodings used in configs. `encoding` may be a single name or an array of
// layers (innermost first): e.g. ["base64","hex"] means hex(ascii(base64(bytes))) on the wire.
const NODE_ENC = { utf8: 'utf8', hex: 'hex', base64: 'base64', base64url: 'base64url', latin1: 'latin1' };

export const ENCODINGS = [...Object.keys(NODE_ENC), 'base32', 'base58'];

// ---- base32 (RFC 4648, '=' padding) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += '=';
  return out;
}
function base32Decode(str) {
  const s = str.replace(/=+$/, '').toUpperCase().replace(/\s+/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of s) { const idx = B32.indexOf(ch); if (idx < 0) throw new Error('invalid base32'); value = (value << 5) | idx; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
  return Buffer.from(out);
}

// ---- base58 (Bitcoin alphabet) ----
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; // leakcheck:allow (public Bitcoin base58 alphabet, not a key)
function base58Encode(buf) {
  let zeros = 0; while (zeros < buf.length && buf[zeros] === 0) zeros++;
  const digits = [0];
  for (let i = zeros; i < buf.length; i++) {
    let carry = buf[i];
    for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}
function base58Decode(str) {
  let zeros = 0; while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes = [0];
  for (let i = zeros; i < str.length; i++) {
    const val = B58.indexOf(str[i]); if (val < 0) throw new Error('invalid base58');
    let carry = val;
    for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  const out = Buffer.alloc(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}

function toBytesOne(str, encoding) {
  if (encoding === 'base32') return base32Decode(str.trim());
  if (encoding === 'base58') return base58Decode(str.trim());
  const enc = NODE_ENC[encoding];
  if (!enc) throw new Error(`unknown encoding "${encoding}"`);
  if (typeof str !== 'string') throw new Error('expected a string value');
  return Buffer.from(encoding === 'hex' ? str.trim() : str, enc);
}

function fromBytesOne(buf, encoding) {
  if (encoding === 'base32') return base32Encode(Buffer.from(buf));
  if (encoding === 'base58') return base58Encode(Buffer.from(buf));
  const enc = NODE_ENC[encoding];
  if (!enc) throw new Error(`unknown encoding "${encoding}"`);
  return Buffer.from(buf).toString(enc);
}

export function toBytes(str, encoding = 'utf8') {
  if (!Array.isArray(encoding)) return toBytesOne(str, encoding);
  // Decode outermost layer first (last in the array), feeding each inner layer as a utf8 string.
  let cur = str;
  for (let i = encoding.length - 1; i >= 0; i--) {
    const bytes = toBytesOne(cur, encoding[i]);
    if (i === 0) return bytes;
    cur = bytes.toString('utf8');
  }
  return toBytesOne(str, 'utf8');
}

export function fromBytes(buf, encoding = 'utf8') {
  if (!Array.isArray(encoding)) return fromBytesOne(buf, encoding);
  let cur = Buffer.from(buf);
  for (let i = 0; i < encoding.length; i++) {
    const s = fromBytesOne(cur, encoding[i]);
    if (i === encoding.length - 1) return s;
    cur = Buffer.from(s, 'utf8');
  }
  return fromBytesOne(buf, 'utf8');
}
