// Minimal JSON path: $.a.b[0].c and $['a-b']. Enough for "where is the ciphertext" in a body.
export function parsePath(path) {
  if (!path.startsWith('$')) throw new Error(`JSON path must start with $: ${path}`);
  const re = /\.([A-Za-z_$][\w$-]*)|\[(\d+)\]|\['([^']*)'\]|\["([^"]*)"\]/gy;
  const parts = [];
  re.lastIndex = 1;
  while (re.lastIndex < path.length) {
    const m = re.exec(path);
    if (!m) throw new Error(`bad JSON path: ${path}`);
    parts.push(m[2] !== undefined ? Number(m[2]) : (m[1] ?? m[3] ?? m[4]));
  }
  return parts;
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
