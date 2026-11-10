// Integrity recompute: an edited + re-encrypted request must still pass the target's own
// integrity check (an HMAC/hash token, a timestamp, a nonce, or a custom signature). Each rule
// computes a value over the FINAL message and writes it to a target field; message.mjs runs these
// on the encrypt direction only, after ciphers + body reserialization, in config order so a
// timestamp/nonce rule can feed a later hmac's {ts}/{nonce}.
import crypto from 'node:crypto';
import { fromBytes } from './encoding.mjs';

export const INTEGRITY_TYPES = new Set(['hmac', 'hash', 'timestamp', 'nonce', 'custom']);

// Replace {token} references against the current message via read(kind, key) and prior state.
export function resolveTemplate(tpl, read, state) {
  return String(tpl).replace(/\{([^}]+)\}/g, (_, token) => {
    const i = token.indexOf(':');
    const kind = i < 0 ? token.trim() : token.slice(0, i).trim();
    const key = i < 0 ? null : token.slice(i + 1).trim();
    if (kind === 'ts') return state.ts ?? '';
    if (kind === 'nonce') return state.nonce ?? '';
    return read(kind, key);
  });
}

function timestamp(format) {
  const now = Date.now();
  if (format === 's') return String(Math.floor(now / 1000));
  if (format === 'iso') return new Date(now).toISOString();
  return String(now); // ms (default)
}

// Compute one rule's value and update state. ctx = { read, keyStore, state, loadCustom }.
export function computeRule(rule, ctx) {
  const { read, keyStore, state } = ctx;
  switch (rule.type) {
    case 'timestamp': {
      state.ts = timestamp(rule.format);
      return state.ts;
    }
    case 'nonce': {
      state.nonce = fromBytes(crypto.randomBytes(rule.bytes || 16), rule.encoding || 'hex');
      return state.nonce;
    }
    case 'hash': {
      const input = resolveTemplate(rule.input ?? '{body}', read, state);
      return fromBytes(crypto.createHash((rule.alg || 'sha256').toLowerCase()).update(input, 'utf8').digest(), rule.outEncoding || 'hex');
    }
    case 'hmac': {
      const key = keyStore[rule.key];
      if (!key) throw new Error(`hmac integrity: unknown key "${rule.key}"`);
      const input = resolveTemplate(rule.input ?? '{body}', read, state);
      return fromBytes(crypto.createHmac((rule.alg || 'sha256').toLowerCase(), key).update(input, 'utf8').digest(), rule.outEncoding || 'hex');
    }
    case 'custom': {
      const sign = ctx.loadCustom(rule);
      const input = resolveTemplate(rule.input ?? '{body}', read, state);
      return String(sign({ input }));
    }
    default:
      throw new Error(`unknown integrity type "${rule.type}"`);
  }
}
