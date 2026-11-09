import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, loadAllowlist } from './leak-check.mjs';

// Fixtures are assembled at runtime so this file does not trip the check itself.
const realHost = ['api', 'acme-bank', 'co', 'kr'].join('.');
const hexKey = '0123456789abcdef'.repeat(2);
const b64Key = ['q9Zx', 'Lm3P', 'vT8w', 'Rk2N', 'yH5b', 'Jc7D', 'fG1s', 'Ua4E', 'oI6t', 'Wn0Y'].join('');
const allow = loadAllowlist(['github.com', '# comment', 'example.com', ''].join('\n'));
const rules = (r) => r.map((x) => x.rule);

test('flags real hostname, allows *.test, allowlist and subdomains', () => {
  assert.deepEqual(rules(scanText('docs/a.md', `see https://${realHost}/api`, allow)), ['hostname']);
  assert.deepEqual(scanText('docs/a.md', 'https://api.shop.test/x', allow), []);
  assert.deepEqual(scanText('docs/a.md', 'https://raw.github.com/x', allow), []);
});

test('hostname rule also applies inside samples/', () => {
  assert.deepEqual(rules(scanText('samples/index.html', `fetch("https://${realHost}")`, allow)), ['hostname']);
});

test('ignores file names and Java packages', () => {
  assert.deepEqual(scanText('a.md', 'edit config.json and burp.api.montoya.MontoyaApi', allow), []);
});

test('public IP flagged, private/loopback/doc ranges allowed', () => {
  assert.deepEqual(rules(scanText('a.md', `host ${[8, 8, 4, 4].join('.')}`, allow)), ['public-ip']);
  assert.deepEqual(scanText('a.md', '127.0.0.1 10.1.2.3 192.168.0.1 172.20.0.1 203.0.113.9', allow), []);
});

test('key-like strings flagged outside samples/, allowed inside', () => {
  assert.deepEqual(rules(scanText('server/x.js', `const k = "${hexKey}"`, allow)), ['hex-key']);
  assert.deepEqual(rules(scanText('server/x.js', `const k = "${b64Key}"`, allow)), ['base64-key']);
  assert.deepEqual(scanText('samples/keys.js', `const k = "${hexKey}"; const b = "${b64Key}"`, allow), []);
});

test('long identifiers are not base64 keys', () => {
  assert.deepEqual(scanText('a.java', 'HttpRequestEditorProviderRegistrationHandlerImpl', allow), []);
});

test('exported config outside samples/ is blocked', () => {
  const cfg = JSON.stringify({ schemaVersion: 1, keys: {}, ciphers: {} });
  assert.deepEqual(rules(scanText('notes/cfg.json', cfg, allow)), ['exported-config']);
  assert.deepEqual(scanText('samples/config.json', cfg, allow), []);
});

test('inline allow marker suppresses a line', () => {
  assert.deepEqual(scanText('a.md', `https://${realHost} leakcheck:allow`, allow), []);
});
