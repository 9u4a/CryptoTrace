// JSON path: $.a.b[0].c, $['a-b'], plus [*] (every element) and $..key (recursive descent).
// Enough to locate ciphertext that sits at variable positions.
export function parsePath(path) {
  if (!path.startsWith('$')) throw new Error(`JSON path must start with $: ${path}`);
  const re = /\.\.([A-Za-z_$][\w$-]*)|\.([A-Za-z_$][\w$-]*)|\[(\d+)\]|\[\*\]|\['([^']*)'\]|\["([^"]*)"\]/gy;
  const parts = [];
  re.lastIndex = 1;
  while (re.lastIndex < path.length) {
    const m = re.exec(path);
    if (!m) throw new Error(`bad JSON path: ${path}`);
    if (m[1] !== undefined) parts.push({ recurse: m[1] });
    else if (m[2] !== undefined) parts.push(m[2]);
    else if (m[3] !== undefined) parts.push(Number(m[3]));
    else if (m[0] === '[*]') parts.push({ wild: true });
    else parts.push(m[4] ?? m[5]);
  }
  return parts;
}

// Expand wildcard/recursive parts against a concrete document into literal path lists.
// A plain path returns [itself]; [*]/..key fan out to every matching location.
export function expand(root, parts) {
  if (!parts.some((p) => p && (p.wild || p.recurse))) return [parts];
  const out = [];
  const rec = (node, i, acc) => {
    if (i === parts.length) { if (node !== undefined) out.push(acc); return; }
    const p = parts[i];
    if (p && p.wild) {
      if (Array.isArray(node)) node.forEach((el, idx) => rec(el, i + 1, [...acc, idx]));
      else if (node && typeof node === 'object') for (const k of Object.keys(node)) rec(node[k], i + 1, [...acc, k]);
    } else if (p && p.recurse) {
      const visit = (n, base) => {
        if (!n || typeof n !== 'object') return;
        if (!Array.isArray(n) && p.recurse in n) rec(n[p.recurse], i + 1, [...base, p.recurse]);
        if (Array.isArray(n)) n.forEach((el, idx) => visit(el, [...base, idx]));
        else for (const k of Object.keys(n)) visit(n[k], [...base, k]);
      };
      visit(node, acc);
    } else {
      const child = node == null || typeof node !== 'object' ? undefined : node[p];
      if (child !== undefined) rec(child, i + 1, [...acc, p]);
    }
  };
  rec(root, 0, []);
  return out;
}

export function getAt(root, parts) {
  let cur = root;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object' || !(p in cur)) return undefined;
    cur = cur[p];
  }
  return cur;
}

export function setAt(root, parts, value) {
  if (parts.length === 0) return value;
  const parent = getAt(root, parts.slice(0, -1));
  if (parent == null || typeof parent !== 'object') throw new Error('JSON path parent not found');
  parent[parts[parts.length - 1]] = value;
  return root;
}
