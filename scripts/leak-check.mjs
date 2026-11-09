#!/usr/bin/env node
// Pre-commit leak check for a public repo.
// Blocks target-derived data from being committed: real hostnames, public IPs,
// key-like hex/base64 strings outside samples/, and exported CryptoTrace configs.
//
// Usage:
//   node scripts/leak-check.mjs          # scan staged files (pre-commit)
//   node scripts/leak-check.mjs --all    # scan every tracked file
// Suppress a reviewed false positive by putting `leakcheck:allow` on that line.

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const TLDS = 'com|net|org|io|kr|co|dev|app|biz|info|me|xyz|cloud|ai|gov|edu|jp|cn|us|uk|de|site|online|shop|tech';
const DOMAIN_RE = new RegExp(
  String.raw`(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:${TLDS}|test|example|invalid|localhost))(?![\w-])`,
  'gi',
);
const SAFE_TLDS = ['test', 'example', 'invalid', 'localhost'];
const IPV4_RE = /(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/g;
const HEX_RE = /(?<![0-9a-zA-Z])[0-9a-fA-F]{32,}(?![0-9a-zA-Z])/g;
const B64_RE = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])/g;
const ALLOW_MARK = 'leakcheck:allow';

export function loadAllowlist(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.replace(/#.*/, '').trim().toLowerCase())
    .filter(Boolean);
}

function domainAllowed(domain, allow) {
  const d = domain.toLowerCase();
  if (SAFE_TLDS.includes(d.split('.').pop())) return true;
  return allow.some((a) => !a.startsWith('path:') && (d === a || d.endsWith('.' + a)));
}

function isPublicIp(ip) {
  const o = ip.split('.').map(Number);
  if (o.some((n) => n > 255)) return false;
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  // RFC 5737 documentation ranges
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function entropy(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeB64Key(s) {
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(s)).length;
  return classes === 3 && entropy(s) > 4.2;
}

function isExportedConfig(path, text) {
  if (!path.toLowerCase().endsWith('.json')) return false;
  try {
    const j = JSON.parse(text);
    return j && typeof j === 'object' && 'ciphers' in j && ('keys' in j || 'apply' in j);
  } catch {
    return false;
  }
}

const mask = (s) => (s.length > 10 ? s.slice(0, 6) + '…(' + s.length + ')' : s);

/** Scan one file's text. Returns [{path, line, rule, value}] */
export function scanText(path, text, allow) {
  const out = [];
  const p = path.replace(/\\/g, '/');
  // `path:<prefix>` entries skip unmodified third-party files (e.g. vendored libraries).
  if (allow.some((a) => a.startsWith('path:') && p.startsWith(a.slice(5)))) return out;
  const inSamples = p.startsWith('samples/');

  if (!inSamples && isExportedConfig(p, text)) {
    out.push({ path: p, line: 1, rule: 'exported-config', value: 'CryptoTrace config outside samples/' });
  }

  text.split(/\r?\n/).forEach((line, i) => {
    if (line.includes(ALLOW_MARK)) return;
    const hit = (rule, value) => out.push({ path: p, line: i + 1, rule, value: mask(value) });

    for (const m of line.matchAll(DOMAIN_RE)) {
      if (!domainAllowed(m[1], allow)) hit('hostname', m[1]);
    }
    for (const m of line.matchAll(IPV4_RE)) {
      if (isPublicIp(m[1])) hit('public-ip', m[1]);
    }
    if (!inSamples) {
      for (const m of line.matchAll(HEX_RE)) hit('hex-key', m[0]);
      for (const m of line.matchAll(B64_RE)) if (looksLikeB64Key(m[0])) hit('base64-key', m[0]);
    }
  });
  return out;
}

function git(args, opts = {}) {
  return execFileSync('git', args, { maxBuffer: 64 * 1024 * 1024, ...opts });
}

function main() {
  const all = process.argv.includes('--all');
  const root = git(['rev-parse', '--show-toplevel']).toString().trim();
  const allowPath = `${root}/.leakcheck-allow`;
  const allow = existsSync(allowPath) ? loadAllowlist(readFileSync(allowPath, 'utf8')) : [];

  const files = (all
    ? git(['ls-files', '-z'], { cwd: root })
    : git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'], { cwd: root }))
    .toString()
    .split('\0')
    .filter(Boolean);

  const findings = [];
  for (const f of files) {
    const buf = all ? readFileSync(`${root}/${f}`) : git(['show', `:${f}`], { cwd: root });
    if (buf.includes(0)) continue; // binary
    findings.push(...scanText(f, buf.toString('utf8'), allow));
  }

  if (findings.length === 0) {
    console.log(`leak-check: OK (${files.length} file(s))`);
    return;
  }
  console.error(`leak-check: ${findings.length} possible leak(s) — commit blocked\n`);
  for (const x of findings) console.error(`  ${x.path}:${x.line}  [${x.rule}]  ${x.value}`);
  console.error(
    `\nIf a hit is not target-derived: add the domain to .leakcheck-allow, or put "${ALLOW_MARK}" on that line.`,
  );
  process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
