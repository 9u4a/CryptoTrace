# CryptoTrace coverage

Measured by `node scripts/coverage.mjs` against the self-made coverage lab (`samples/coverage/`, fake keys, 127.0.0.1).
Each case runs the panel pipeline in headless Chrome; "got" is what actually happened to the request the target received
(decrypted in Burp's view, edited, re-encrypted, accepted by the target).

ok 33 · better 0 · GAP 0 · ERROR 0 (of 33)

Levels: auto > trace > encrypt-only > skip > locate > scan-only > none.

| case | group | what | expect | got | verdict | notes |
|---|---|---|---|---|---|---|
| cjs-cbc-json | library | CryptoJS AES-256-CBC, WordArray key/IV, JSON field | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| cjs-passphrase | library | CryptoJS AES passphrase mode (OpenSSL Salted__), whole body | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| cjs-ecb-hex-form | library | CryptoJS AES-128-ECB, ciphertext sent as hex in a form field | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| cjs-webpack-lazy | bundler | CryptoJS in a webpack 5 chunk loaded after the runtime | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| cjs-webpack-vendor-first | bundler | CryptoJS in a webpack 5 vendor chunk loaded BEFORE the runtime (usual split) | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| cjs-esm | bundler | CryptoJS inlined in an ES module (Vite/Rollup style, no global, no webpack) | trace | trace | ok | traced: Object.stringify / WordArray.init.toString / Object.stringify / Object.toString / encryptPayload / window.__run<br>identified: aes-256-cbc/pkcs7<br>scan: SHA-1/SHA-256/Blowfish |
| wc-gcm-prefix | library | WebCrypto AES-256-GCM, static key, body = base64(iv || ct) | auto | auto | ok |  |
| wc-cbc-ivfield | library | WebCrypto AES-256-CBC, random IV in its own JSON field | auto | auto | ok |  |
| wc-ctr-query | library | WebCrypto AES-CTR (static counter), base64url ciphertext in a GET query | auto | auto | ok |  |
| wc-pbkdf2 | library | WebCrypto PBKDF2-derived non-extractable AES-CBC key | auto | auto | ok |  |
| wc-envelope | library | WebCrypto RSA-OAEP envelope + fresh AES-GCM key per request | skip | skip | ok | skipped: request $.ct: key changes per request (not a fixed key)<br>target rejected the re-encrypted request: error:02000079:rsa routines::oaep decoding error |
| jsbn-form | library | jsbn RSAKey PKCS#1 v1.5 hex in a form field (Korean login pattern) | encrypt-only | encrypt-only | ok | scan: RSA |
| jsencrypt | library | JSEncrypt (setPublicKey PEM) base64 in a JSON field | encrypt-only | encrypt-only | ok | scan: RSA/EC |
| forge-cbc | library | node-forge AES-CBC, base64 (forge.util.encode64) in a JSON field | auto | auto | ok | scan: SHA-1/DES/SHA-256 |
| aesjs-ctr-hex | library | aes-js CTR (Counter 7), hex in a JSON field | auto | auto | ok | scan: AES |
| xhr-header | transport | CryptoJS ciphertext sent by XMLHttpRequest in a header | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| hmac-sign | integrity | CryptoJS AES field + X-Sign = HmacSHA256(field) checked by the server | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| seed-site | no-api | KISA SEED-CBC behind a site function, key/IV in script variables | trace | trace | ok | traced: b64 / encSeed / window.__run<br>identified: seed-cbc/pkcs7<br>scan: SEED |
| seed-key-local | no-api | SEED with the key built inside the function on each call (local variable) | trace | trace | ok | traced: b64 / encryptField / window.__run<br>identified: seed-cbc/pkcs7<br>scan: SEED |
| seed-class-method | no-api | SEED in a class method, key/IV on `this` | trace | trace | ok | traced: CryptoService.encrypt / window.__run<br>identified: seed-cbc/pkcs7<br>scan: SEED |
| aes-module-site | no-api | aes-js inlined in an ES module (no global), CBC + PKCS#7, hex, key in module scope | trace | trace | ok | traced: Object.fromBytes / encryptBody / window.__run<br>identified: aes-256-cbc/pkcs7<br>scan: AES |
| cjs-esm-wordarray | no-api | Same as cjs-esm (traced): key/IV are CryptoJS WordArrays, not bytes/strings | trace | trace | ok | traced: Object.stringify / WordArray.init.toString / Object.stringify / Object.toString / seal / window.__run<br>identified: aes-256-cbc/pkcs7<br>scan: SHA-1/SHA-256/Blowfish |
| xor-custom | no-api | Home-made XOR + base64 "encryption" (no standard algorithm) | encrypt-only | encrypt-only | ok | traced: scramble / window.__run<br>re-encrypted by the page function (oracle) |
| double-layer | transport | CryptoJS ciphertext wrapped in JSON, the whole JSON base64-encoded again | locate | locate | ok | traced: window.__run<br>scan: SHA-1/SHA-256/Blowfish |
| resp-cjs-body | response | Response: whole body CryptoJS AES-CBC, decrypted by the page | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| resp-wc-json-iv | response | Response: WebCrypto AES-CBC {iv, data} JSON, decrypted by the page | auto | auto | ok |  |
| session-handshake | library | Key handed out by a handshake per page session, then CryptoJS AES | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| hmac-ts | integrity | X-Sign = HmacSHA256(data + "|" + X-Ts) with a timestamp header | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| multi-field | transport | Two fields in one request, different keys and libraries (CryptoJS CBC + aes-js CTR) | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish/AES |
| cookie-token | transport | Ciphertext set with document.cookie and sent as a cookie | auto | auto | ok | scan: SHA-1/SHA-256/Blowfish |
| worker-seed | no-api | SEED inside a Web Worker that also sends the request (no hookable API) | trace | trace | ok | traced: sealInWorker / self.onmessage<br>identified: seed-cbc/pkcs7<br>scan: SEED |
| eval-obfuscated | no-api | SEED site code run through new Function (eval script, no URL), names mangled | trace | trace | ok | traced: _0xe / window.__run<br>identified: seed-cbc/pkcs7<br>scan: SEED |
| native-agent | out-of-scope | Ciphertext produced outside page JS (security-module agent on localhost) | none | none | ok |  |

## Not measured by this lab

- Rewriting WebSocket frames in Burp (placements are only shown in the panel).
- Non-standard ciphers (custom XOR, nested encodings, per-request keys): located only -- they need a custom module or the planned L4 browser oracle.
- Identification covers AES/ARIA/SEED block modes (CBC/ECB/CTR/CFB/OFB, PKCS#7/zero/none); LEA, WASM crypto and stream ciphers outside OpenSSL are not identified.
- Code with no stable function boundaries (control-flow-flattened obfuscation) and cross-origin iframes are not exercised.
- Burp UI itself (Decrypted tab, Scanner insertion points) is covered by the Java tests and manual checks, not by this run.
