// Byte <-> string encodings used in configs.
const NODE_ENC = { utf8: 'utf8', hex: 'hex', base64: 'base64', base64url: 'base64url', latin1: 'latin1' };

export const ENCODINGS = Object.keys(NODE_ENC);

export function toBytes(str, encoding = 'utf8') {
  const enc = NODE_ENC[encoding];
  if (!enc) throw new Error(`unknown encoding "${encoding}"`);
  if (typeof str !== 'string') throw new Error('expected a string value');
  return Buffer.from(encoding === 'hex' ? str.trim() : str, enc);
}

export function fromBytes(buf, encoding = 'utf8') {
  const enc = NODE_ENC[encoding];
  if (!enc) throw new Error(`unknown encoding "${encoding}"`);
  return Buffer.from(buf).toString(enc);
}
