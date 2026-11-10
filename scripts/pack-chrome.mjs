// Package chrome-ext/ into a Web Store / release zip. Zero deps (Node zlib only), offline,
// reproducible (fixed timestamps). Output goes to output/ (gitignored); attach it to the
// GitHub Release on a version bump.
//   node scripts/pack-chrome.mjs
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const SRC = path.join(ROOT, 'chrome-ext');
const OUT_DIR = path.join(ROOT, 'output');

const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

// Everything under chrome-ext/ except the test tree and *.test.* files.
function walk(dir, base = '') {
  const out = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    if (fs.statSync(full).isDirectory()) {
      if (name === 'test' || name === 'node_modules') continue;
      out.push(...walk(full, rel));
    } else if (!/\.test\./.test(name)) {
      out.push({ rel, full });
    }
  }
  return out;
}

const version = JSON.parse(fs.readFileSync(path.join(SRC, 'manifest.json'), 'utf8')).version;
const files = walk(SRC);
const DOS_TIME = 0;
const DOS_DATE = 0x21; // 1980-01-01, so the archive bytes are reproducible

const parts = [];
const central = [];
let offset = 0;

for (const f of files) {
  const data = fs.readFileSync(f.full);
  const crc = crc32(data);
  const comp = zlib.deflateRawSync(data, { level: 9 });
  const name = Buffer.from(f.rel, 'utf8');

  const lh = Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50, 0);
  lh.writeUInt16LE(20, 4);
  lh.writeUInt16LE(8, 8); // deflate
  lh.writeUInt16LE(DOS_TIME, 10);
  lh.writeUInt16LE(DOS_DATE, 12);
  lh.writeUInt32LE(crc, 14);
  lh.writeUInt32LE(comp.length, 18);
  lh.writeUInt32LE(data.length, 22);
  lh.writeUInt16LE(name.length, 26);
  parts.push(lh, name, comp);

  const ch = Buffer.alloc(46);
  ch.writeUInt32LE(0x02014b50, 0);
  ch.writeUInt16LE(20, 4);
  ch.writeUInt16LE(20, 6);
  ch.writeUInt16LE(8, 10);
  ch.writeUInt16LE(DOS_TIME, 12);
  ch.writeUInt16LE(DOS_DATE, 14);
  ch.writeUInt32LE(crc, 16);
  ch.writeUInt32LE(comp.length, 20);
  ch.writeUInt32LE(data.length, 24);
  ch.writeUInt16LE(name.length, 28);
  ch.writeUInt32LE(offset, 42);
  central.push(ch, name);

  offset += lh.length + name.length + comp.length;
}

const centralBuf = Buffer.concat(central);
const eocd = Buffer.alloc(22);
eocd.writeUInt32LE(0x06054b50, 0);
eocd.writeUInt16LE(files.length, 8);
eocd.writeUInt16LE(files.length, 10);
eocd.writeUInt32LE(centralBuf.length, 12);
eocd.writeUInt32LE(offset, 16);

fs.mkdirSync(OUT_DIR, { recursive: true });
const outPath = path.join(OUT_DIR, `cryptotrace-chrome-${version}.zip`);
fs.writeFileSync(outPath, Buffer.concat([...parts, centralBuf, eocd]));
console.log(`wrote ${path.relative(ROOT, outPath)} — ${files.length} files, ${(fs.statSync(outPath).size / 1024).toFixed(1)} KiB`);
for (const f of files) console.log('  ' + f.rel);
