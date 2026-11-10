# Extending CryptoTrace

Where to add support for a new target shape. Each row is the one place (or few) to change; add a test
beside the existing ones and, for any `server/` change, rebuild the exe (`node scripts/build-sea.mjs`).

## Symmetric cipher / block mode
- **Server:** `server/src/cipher.mjs` — `symmetricCipher` runs any algorithm Node's OpenSSL exposes
  (`crypto.getCiphers()`), so AES/ARIA/SEED/Camellia/SM4 in cbc/ecb/ctr/gcm usually need no code. AEAD
  (tag + nonce) is gated by `isAead`; add new AEAD names there.
- **Capture → config:** `chrome-ext/config-builder.js` — `cryptojsAlg` / `webcryptoAlg` map a captured
  call to a cipher spec. Add the algorithm/mode name here so exports pick it up.

## Key derivation (KDF)
`server/src/kdf.mjs` — add a branch to `deriveKey` (pbkdf2/scrypt/hkdf today). `profile.mjs buildCipher`
already routes any `spec.kdf` through it. CryptoJS passphrase mode is the separate `openssl-md5` path.

## Integrity rule type (token / signature)
`server/src/integrity.mjs` — add a `case` to `computeRule` and the name to `INTEGRITY_TYPES`. If it needs
a key, extend the key check in `profile.mjs validateIntegrity`. Signing primitives live in
`cipher.mjs signData` (RSA-PSS/PKCS1, ECDSA, EdDSA). Rules run on **encrypt**, after ciphers, in order.

## Apply location (where ciphertext sits)
`server/src/message.mjs` — add a branch in `transform` (cipher side) and the integrity read/write, and add
the name to `LOCATIONS` in `profile.mjs`. Reuse `queryGet` / `querySetOrAdd` for key=value shapes. For
Scanner insertion points, add a `case` in `burp-ext/.../PlainInsertionPoints.java`.

## Byte encoding
`server/src/encoding.mjs` — add a case to `toBytesOne` / `fromBytesOne` and the name to `ENCODINGS`.
A spec's `inEncoding`/`outEncoding` may be an array to chain encodings (innermost first).

## JSON path feature
`server/src/jsonpath.mjs` — `parsePath` tokenizes; `expand` resolves `[*]`/`..key` against a document.
Mirror non-trivial additions in `burp-ext/.../JsonPaths.java` for insertion points.

## Browser crypto library
`chrome-ext/hook.js` — write an `installX(obj)` (wrap its encrypt/decrypt via `wrap()` so the toString
disguise applies), then append `{ name, detect, install }` to the `LIBS` array. That hooks it both as a
global and inside webpack bundles. Prototype-based libraries (e.g. JSEncrypt) use `trapGlobal` directly.
Transport/location capture for fetch/XHR lives in `chrome-ext/hook-transport.js`.

## Custom per-target code
When no built-in fits, port the target's routine into a reviewed module (`node:vm`, not a security
boundary): `module.exports = { encrypt, decrypt }` for a cipher (`custom.mjs loadCustomCipher`) or
`{ sign }` for an integrity signer (`loadCustomSign`). Reference it with `"custom": "path.js"`.

## Session keys captured at runtime
Keys with `source: "session"` + a `capture` rule are filled from live responses — server side in
`profile.mjs setKey` + `engine.mjs key` op; Burp side in `SessionKeys.java`.
