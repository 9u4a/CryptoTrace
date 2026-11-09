// Custom cipher modules ported from the target's JS, run in node:vm.
//
// NOT A SECURITY BOUNDARY. node:vm only separates globals; hostile code can escape it.
// Only load code you have read and reviewed. What this does give you: no require/process/fetch
// in scope by default, and a per-call timeout so a runaway loop can't hang Burp.
//
// Module shape (CommonJS style):
//   module.exports = { encrypt(plain, ctx) -> string, decrypt(cipher, ctx) -> string }
// Both must be synchronous. ctx = { key: {<name>: Buffer}, params: <cipher spec> }.
import vm from 'node:vm';
import fs from 'node:fs';

const DEFAULT_TIMEOUT_MS = 1000;

export function loadCustomCipher(file, spec, keys) {
  const source = fs.readFileSync(file, 'utf8');
  const sandbox = {
    module: { exports: {} },
    Buffer,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    DataView,
    ArrayBuffer,
    console: { log: (...a) => process.stderr.write(`[custom ${file}] ${a.join(' ')}\n`) },
  };
  sandbox.exports = sandbox.module.exports;
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  const timeout = spec.timeoutMs || DEFAULT_TIMEOUT_MS;
  new vm.Script(source, { filename: file }).runInContext(context, { timeout });

  const mod = context.module.exports;
  for (const fn of ['encrypt', 'decrypt']) {
    if (typeof mod[fn] !== 'function') throw new Error(`${file}: module.exports.${fn} is not a function`);
  }
  const call = (fn, value) => {
    context.__arg = value;
    context.__ctx = { key: keys, params: spec };
    const out = vm.runInContext(`module.exports.${fn}(__arg, __ctx)`, context, { timeout });
    if (typeof out !== 'string') throw new Error(`${file}: ${fn}() must return a string synchronously`);
    return out;
  };
  return {
    deterministic: spec.deterministic !== false,
    encrypt: (plain) => call('encrypt', plain),
    decrypt: (text) => call('decrypt', text),
  };
}
