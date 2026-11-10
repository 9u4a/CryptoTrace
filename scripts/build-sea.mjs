// Build a single-file server executable (Node SEA). Diagnosis PCs then run the .exe with no
// Node/npm install. Runtime stays zero-dep; the ONLY build-time external is `postject`, fetched
// once via npx to inject the blob into a copy of the Node binary (Node ships no built-in injector).
//
//   node scripts/build-sea.mjs
//
// Steps: bundle server -> generate SEA blob (built-in, offline) -> copy node binary -> postject inject.
import { execFileSync, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const DIST = path.join(ROOT, 'dist');
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'; // leakcheck:allow (public Node SEA sentinel, not a key)
const isWin = process.platform === 'win32';
const exe = path.join(DIST, isWin ? 'crypto-server.exe' : 'crypto-server');
const run = (cmd, args) => execFileSync(cmd, args, { cwd: ROOT, stdio: 'inherit' });

// 1. Inline server/src/*.mjs into one CJS file.
run(process.execPath, ['scripts/bundle-server.mjs']);

// 2. Generate the SEA preparation blob (built-in Node, no network).
run(process.execPath, ['--experimental-sea-config', 'sea-config.json']);

// 3. Copy the running Node binary; the blob is injected into this copy.
fs.mkdirSync(DIST, { recursive: true });
fs.copyFileSync(process.execPath, exe);

// 4. Inject the blob. postject is the Node-documented injector; `npx --yes` fetches it once.
// Run through a shell as a single quoted string: handles the Windows .cmd shim and paths with spaces
// without the deprecated shell+args form. Only fixed internal values are interpolated (no user input).
const q = (s) => `"${s}"`;
const cmd = ['npx', '--yes', 'postject', q(exe), 'NODE_SEA_BLOB', q(path.join(DIST, 'sea-prep.blob')), '--sentinel-fuse', FUSE]
  .concat(process.platform === 'darwin' ? ['--macho-segment-name', 'NODE_SEA'] : [])
  .join(' ');
try {
  execSync(cmd, { cwd: ROOT, stdio: 'inherit' });
} catch (e) {
  fs.rmSync(exe, { force: true }); // an un-injected node copy is not the server; don't leave it
  console.error('\npostject step failed (needs network the first time to fetch postject):');
  console.error('  ' + e.message);
  console.error('Run on a machine with network once; the produced .exe then needs nothing.');
  process.exit(1);
}

console.log(`\nBuilt ${path.relative(ROOT, exe)} — point Burp’s launcher at it (leave the script field blank).`);
