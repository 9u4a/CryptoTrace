'use strict';

/* Constant-signature scan: find where a script implements a cipher/hash by the constants it has to contain
 * (S-boxes, round constants), however it is written -- hex or decimal, signed or unsigned, an array literal,
 * constants spread through the code, or one hex string. This finds crypto that has no library API to hook:
 * hand-written ports (KISA SEED/ARIA), inlined or minified copies, obfuscated bundles that keep their tables.
 * Pure (no DOM): window.CryptoTraceScan.scanSource(source, signatures) -> findings. The table lives in
 * signatures.json; panel.js runs this over every script the page loads. */
(function () {
  const WINDOW = 4000; // a "words" signature matches when all its constants occur within this many chars

  // Every numeric literal as an unsigned 32-bit value, with its position. `-680876936` and `0xd76aa478`
  // are the same constant (MD5 is usually written with signed decimals).
  const NUM_RE = /(-\s*)?\b(0[xX][0-9a-fA-F]+|\d+)\b/g;
  function tokens(src) {
    const out = [];
    let m;
    NUM_RE.lastIndex = 0;
    while ((m = NUM_RE.exec(src))) {
      const lit = m[2];
      let v = /^0[xX]/.test(lit) ? parseInt(lit, 16) : Number(lit);
      if (!Number.isFinite(v) || v > 0xffffffff) continue;
      if (m[1]) { if (v > 0x80000000) continue; v = v === 0 ? 0 : 0x100000000 - v; }
      out.push({ v, i: m.index });
    }
    return out;
  }
  const hex2 = (n) => (n < 16 ? '0' : '') + n.toString(16);
  const hex8 = (n) => ('0000000' + n.toString(16)).slice(-8);
  function allIndexes(hay, needle) {
    const out = [];
    for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + 1)) out.push(i);
    return out;
  }

  const STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; // + "+/" or "-_"  leakcheck:allow

  function scanSource(src, signatures) {
    src = String(src || '');
    const lower = src.toLowerCase();
    const toks = tokens(src);
    const vals = (s) => (s.values || []).map((x) => Number(x) >>> 0);
    // positions of the 32-bit constants that any "words" signature needs
    const wanted = new Set();
    for (const s of signatures) if (s.kind === 'words') for (const v of vals(s)) wanted.add(v);
    const pos = new Map();
    for (const t of toks) if (wanted.has(t.v)) { if (!pos.has(t.v)) pos.set(t.v, []); pos.get(t.v).push(t.i); }
    for (const v of wanted) for (const i of allIndexes(lower, hex8(v))) { if (!pos.has(v)) pos.set(v, []); pos.get(v).push(i); }

    const hits = []; // [signature, index]
    for (const s of signatures) {
      if (s.kind === 'bytes') {
        const want = vals(s);
        for (let t = 0; t + want.length <= toks.length; t++) {
          if (toks[t].v !== want[0]) continue;
          let k = 1;
          while (k < want.length && toks[t + k].v === want[k]) k++;
          if (k === want.length) hits.push([s, toks[t].i]);
        }
        for (const i of allIndexes(lower, want.slice(0, 8).map(hex2).join(''))) hits.push([s, i]); // one hex string
      } else if (s.kind === 'words') {
        const want = vals(s);
        for (const p of pos.get(want[0]) || []) {
          const near = (v) => (pos.get(v) || []).some((q) => Math.abs(q - p) <= WINDOW);
          if (want.slice(1).every(near)) hits.push([s, p]);
        }
      } else if (s.kind === 'text') {
        const idx = s.patterns.map((p) => src.indexOf(p));
        if (idx.every((i) => i >= 0)) hits.push([s, idx[0]]);
      } else if (s.kind === 'regex') {
        const re = new RegExp(s.pattern, 'g');
        let m;
        while ((m = re.exec(src))) { hits.push([s, m.index]); if (!m[0]) re.lastIndex++; }
      } else if (s.kind === 'alphabet') {
        const re = /(["'`])([A-Za-z0-9+/=_\-.$!*~]{64,65})\1/g;
        let m;
        while ((m = re.exec(src))) {
          const a = m[2].replace(/=$/, '');
          if (a.length !== 64 || new Set(a).size !== 64) continue;
          if (a === STD_B64 + '+/' || a === STD_B64 + '-_') continue; // standard / URL-safe
          hits.push([s, m.index + 1]);
        }
      }
    }

    // one finding per signature per WINDOW span, in source order
    hits.sort((a, b) => a[1] - b[1]);
    const lastAt = new Map();
    const lineStarts = [0];
    for (let i = src.indexOf('\n'); i >= 0; i = src.indexOf('\n', i + 1)) lineStarts.push(i + 1);
    const lineOf = (i) => { let lo = 0, hi = lineStarts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= i) lo = mid; else hi = mid - 1; } return lo; };
    const out = [];
    for (const [s, i] of hits) {
      if (lastAt.has(s.id) && i - lastAt.get(s.id) <= WINDOW) continue;
      lastAt.set(s.id, i);
      const line = lineOf(i);
      out.push({ id: s.id, name: s.name, algo: s.algo, strength: s.strength || 'strong', note: s.note || '',
        index: i, line, col: i - lineStarts[line], snippet: src.slice(Math.max(0, i - 30), i + 90).replace(/\s+/g, ' ') });
    }
    return out;
  }

  window.CryptoTraceScan = { scanSource };
})();
