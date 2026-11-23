// Unknown-ciphertext back-trace: a request field that looks like ciphertext is traced back to the encoding
// call (btoa / Array#join) that produced it, with the page's call stack -- crypto with no hookable API
// (hand-written XOR/SEED ports) still gets a location.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const records = [];
const origins = () => records.filter((r) => r.lib === 'origin');

before(() => {
  globalThis.__cryptotrace_emit = (line) => { try { records.push(JSON.parse(line)); } catch (_) {} };
  globalThis.fetch = async () => new Response('ok');
  const src = ['hook.js', 'hook-transport.js'].map((f) => fs.readFileSync(path.join(ROOT, 'chrome-ext', f), 'utf8')).join('\n;\n');
  vm.runInThisContext(src, { filename: 'hook.js' });
});

// A page's own "encryption" with no library behind it.
function encSecret(text) {
  const bytes = [...text].map((c) => c.charCodeAt(0) ^ 0x5a);
  return btoa(String.fromCharCode(...bytes));
}
function toHexCipher(text) {
  return [...text].map((c) => ((c.charCodeAt(0) * 7 + 13) & 0xff).toString(16).padStart(2, '0')).join('');
}

test('a base64 field made by btoa is traced to the page function that built it', async () => {
  records.length = 0;
  const enc = encSecret('card pin 135790 secret');
  await fetch('/api/x', { method: 'POST', body: JSON.stringify({ user: 'minjun', enc }) });
  const o = origins();
  assert.equal(o.length, 1, JSON.stringify(o));
  assert.deepEqual({ ...o[0].loc }, { in: 'json', path: '$.enc' });
  assert.equal(o[0].sink, 'btoa');
  assert.equal(o[0].url, '/api/x');
  const fns = o[0].frames.map((f) => f.fn);
  assert.ok(fns.includes('encSecret'), JSON.stringify(o[0].frames));
  const f = o[0].frames.find((x) => x.fn === 'encSecret');
  assert.match(f.url, /hook-origin\.test\.mjs$/);
  assert.ok(f.line > 0 && f.col > 0);
});

test('a hex field built with Array#join is traced too; plain values are not', async () => {
  records.length = 0;
  const hex = toHexCipher('another secret value');
  await fetch('/api/y', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `name=minjun&mode=normal&encData=${hex}` });
  const o = origins();
  assert.equal(o.length, 1, JSON.stringify(o.map((x) => x.loc)));
  assert.deepEqual({ ...o[0].loc }, { in: 'form', name: 'encData' });
  assert.equal(o[0].sink, 'join');
  assert.ok(o[0].frames.some((x) => x.fn === 'toHexCipher'));
});

test('join stays transparent for ordinary calls', () => {
  assert.equal([1, 2, 3].join('-'), '1-2-3');
  assert.equal(['a', 'b'].join(), 'a,b');
  assert.equal(Array.prototype.join.call({ length: 2, 0: 'x', 1: 'y' }, ''), 'xy');
});
