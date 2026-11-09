// FAKE keys for the self-made sample target. Not secrets — the client copies are
// hard-coded in public/app.js and public/worker.js on purpose (that's what CryptoTrace extracts).

// Scenario A — CryptoJS AES-256-CBC, static key/IV (utf8)
export const A_KEY = 'ct-sample-aes-key-0123456789abcd'; // 32 bytes
export const A_IV = 'ct-sample-iv-016'; // 16 bytes

// Scenario C — WebCrypto AES-256-GCM in a Web Worker, static raw key (hex), random IV prefixed to body
export const C_KEY_HEX = '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f';
export const C_IV_LEN = 12;
