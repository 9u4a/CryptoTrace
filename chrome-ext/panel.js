'use strict';

/* ------------------------- state ------------------------- */
const tabId = chrome.devtools.inspectedWindow.tabId;
const DEBUGGEE = { tabId };
const CDP_VERSION = '1.3';
const BINDING = '__cryptotrace_emit';

let attached = false;
let hooked = false;
let hookSource = '';
const records = []; // every call record, in order
const childSessions = new Set();

const el = (id) => document.getElementById(id);
const hookBtn = el('hook');
const statusEl = el('status');
const rowsEl = el('rows');

/* ------------------------- theme ------------------------- */
function applyTheme() {
  const t = chrome.devtools.panels.themeName;
  document.body.classList.toggle('theme-dark', t === 'dark');
  document.body.classList.toggle('theme-light', t === 'default');
}
applyTheme();

function setStatus(msg, isErr) {
  statusEl.textContent = msg || '';
  statusEl.title = msg || '';
  statusEl.style.color = isErr ? '#d93025' : 'var(--muted)';
}

/* ------------------------- CDP helpers ------------------------- */
function cdp(method, params = {}, target = DEBUGGEE) {
  return new Promise((resolve, reject) => {
    chrome.debugger.sendCommand(target, method, params, (result) => {
      const err = chrome.runtime.lastError;
      if (err) reject(new Error(err.message));
      else resolve(result);
    });
  });
}

async function loadHookSource() {
  if (hookSource) return hookSource;
  const parts = await Promise.all(
    ['hook.js', 'hook-transport.js'].map((f) => fetch(chrome.runtime.getURL(f)).then((r) => r.text())),
  );
  hookSource = parts.join('\n;\n');
  return hookSource;
}

// Install binding + hook into a target (the tab, a frame, or a worker session).
// Workers have no Page domain: they auto-attach paused (waitForDebuggerOnStart), so a
// direct Runtime.evaluate installs the hook before the worker's own code runs.
async function installInto(target, isWorker) {
  await cdp('Runtime.enable', {}, target);
  await cdp('Runtime.addBinding', { name: BINDING }, target);
  if (isWorker) {
    await cdp('Runtime.evaluate', { expression: hookSource }, target).catch((e) =>
      setStatus('worker hook eval failed: ' + e.message, true),
    );
  } else {
    await cdp('Page.addScriptToEvaluateOnNewDocument', { source: hookSource }, target).catch(() => {});
  }
}

const WORKER_TYPES = new Set(['worker', 'service_worker', 'shared_worker']);

async function attach() {
  await loadHookSource();
  await new Promise((resolve, reject) => {
    chrome.debugger.attach(DEBUGGEE, CDP_VERSION, () => {
      const err = chrome.runtime.lastError;
      if (err) reject(new Error(err.message));
      else resolve();
    });
  });
  attached = true;
  await cdp('Page.enable');
  await installInto(DEBUGGEE);
  // Reach workers, iframes and popups: attach to child targets as they appear.
  await cdp('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }).catch((e) =>
    setStatus('child targets (workers/iframes) unavailable: ' + e.message, true),
  );
  await cdp('Page.reload', { ignoreCache: true });
}

async function detach() {
  if (!attached) return;
  attached = false;
  childSessions.clear();
  await new Promise((resolve) => chrome.debugger.detach(DEBUGGEE, () => { void chrome.runtime.lastError; resolve(); }));
}

/* ------------------------- events ------------------------- */
function onEvent(source, method, params) {
  if (!attached || source.tabId !== tabId) return;
  if (method === 'Runtime.bindingCalled' && params.name === BINDING) {
    try { addRecord(JSON.parse(params.payload)); } catch (_) {}
    return;
  }
  if (method === 'Target.attachedToTarget') {
    const sessionId = params.sessionId;
    const type = params.targetInfo && params.targetInfo.type;
    const isWorker = WORKER_TYPES.has(type);
    childSessions.add(sessionId);
    // chrome.debugger (unlike raw CDP) needs the tabId on every debuggee, even a child
    // session — sessionId rides alongside it, not on its own.
    const child = { tabId, sessionId };
    (async () => {
      try {
        await installInto(child, isWorker);
        // reach a worker's own nested workers / a frame's children too
        await cdp('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, child).catch(() => {});
        await cdp('Runtime.runIfWaitingForDebugger', {}, child).catch(() => {});
      } catch (e) {
        setStatus('worker/iframe hook failed: ' + e.message, true);
      }
    })();
  }
}

function onDetach(source, reason) {
  if (source.tabId !== tabId) return;
  attached = false;
  hooked = false;
  updateHookBtn();
  setStatus('debugger detached (' + reason + '). 다시 열려면 Hook ON.', true);
}

chrome.debugger.onEvent.addListener(onEvent);
chrome.debugger.onDetach.addListener(onDetach);
window.addEventListener('unload', () => { if (attached) chrome.debugger.detach(DEBUGGEE, () => void chrome.runtime.lastError); });

/* ------------------------- records + correlation ------------------------- */
function addRecord(rec) {
  rec.n = records.length + 1;
  if (rec.lib === 'transport') window.correlate(rec, records); // correlate.js
  records.push(rec);
  renderRow(rec);
  scheduleAutoSend();
  el('count').textContent = records.filter((r) => r.lib !== 'transport').length + ' calls';
}

/* ------------------------- rendering ------------------------- */
const CIPHER_OPS = new Set(['encrypt', 'decrypt']);
let selected = null; // record shown in the detail pane

function short(obj, max = 32) {
  if (!obj || obj.value == null) return '';
  const v = String(obj.value);
  return v.length > max ? v.slice(0, max - 1) + '…' : v;
}

function algText(rec) {
  return rec.alg ? (rec.alg.name || '') + (rec.mode ? '/' + rec.mode : '') : '';
}

function applyText(a) {
  return a ? a.in + (a.path || a.name ? ' ' + (a.path || a.name) : '') : '';
}

// Request + response placement in one short cell: "req json $.data · res body".
function applyCell(rec) {
  const parts = [];
  if (rec.apply) parts.push('req ' + applyText(rec.apply));
  if (rec.applyResponse) parts.push('res ' + applyText(rec.applyResponse));
  if (rec.applyWebSocket) parts.push('ws ' + applyText(rec.applyWebSocket));
  return parts.join(' · ');
}

function opBadge(op) {
  const b = document.createElement('span');
  b.className = op === 'encrypt' ? 'op-encrypt' : op === 'decrypt' ? 'op-decrypt' : '';
  b.textContent = op || '';
  return b;
}

function isHidden(rec) {
  return el('onlyCipher').checked && !CIPHER_OPS.has(rec.op);
}

function renderRow(rec) {
  if (rec.lib === 'transport') return; // transport rows only feed correlation
  el('table').hidden = false;
  el('empty').hidden = true;
  const tr = document.createElement('tr');
  if (!CIPHER_OPS.has(rec.op)) tr.classList.add('aux');
  const add = (content, cls) => {
    const td = document.createElement('td');
    if (cls) td.className = cls;
    if (content instanceof Node) td.appendChild(content);
    else td.textContent = content == null ? '' : String(content);
    if (!(content instanceof Node)) td.title = td.textContent;
    tr.appendChild(td);
    return td;
  };
  add(rec.n);
  add(rec.lib);
  add(opBadge(rec.op));
  add(algText(rec));
  add(short(rec.key, 24), 'val');
  add(short(rec.iv, 20), 'val');
  add(short(rec.input), 'val');
  add(short(rec.output), 'val');
  rec._applyTd = add(applyCell(rec), 'apply');

  const siteTd = document.createElement('td');
  if (rec.site && rec.site.url) {
    const a = document.createElement('span');
    a.className = 'loc link';
    const file = rec.site.url.split('/').pop();
    a.textContent = file + ':' + rec.site.line;
    a.title = rec.site.url + ':' + rec.site.line + ':' + rec.site.col;
    a.onclick = (e) => { e.stopPropagation(); openInSources(rec.site.url, rec.site.line - 1, rec.site.col - 1); };
    siteTd.appendChild(a);
  }
  tr.appendChild(siteTd);
  tr.hidden = isHidden(rec);
  tr.onclick = () => select(rec);
  rec._tr = tr;
  rowsEl.appendChild(tr);
  // Follow the latest encrypt/decrypt until the user picks a row themselves.
  if (CIPHER_OPS.has(rec.op) && (!selected || selected._auto)) select(rec, true);
}

// Re-paint apply cells (correlation may fill them after the row was drawn).
function refreshApply() {
  for (const r of records) if (r._applyTd) r._applyTd.textContent = applyCell(r);
  if (selected) renderDetail(selected);
}
setInterval(refreshApply, 1000);

el('onlyCipher').onchange = () => {
  for (const r of records) if (r._tr) r._tr.hidden = isHidden(r);
};

/* ------------------------- detail pane ------------------------- */
function select(rec, auto = false) {
  if (selected && selected._tr) selected._tr.classList.remove('sel');
  selected = rec;
  rec._auto = auto;
  if (rec._tr) rec._tr.classList.add('sel');
  el('detail').hidden = false;
  renderDetail(rec);
}

// Plaintext that is JSON is shown pretty-printed; everything else verbatim.
function pretty(v) {
  const s = String(v);
  if (!/^\s*[{[]/.test(s)) return s;
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch (_) { return s; }
}

let lastDetail = '';
function renderDetail(rec) {
  const isPlain = (side) => (rec.op === 'encrypt' && side === 'input') || (rec.op === 'decrypt' && side === 'output');
  const rows = [
    ['key', rec.key, ''],
    ['iv', rec.iv, ''],
    [rec.op === 'decrypt' ? 'input (암호문)' : rec.op === 'encrypt' ? 'input (평문)' : 'input', rec.input, isPlain('input') ? 'plain' : ''],
    [rec.op === 'encrypt' ? 'output (암호문)' : rec.op === 'decrypt' ? 'output (평문)' : 'output', rec.output, isPlain('output') ? 'plain' : ''],
    ['apply (req)', rec.apply ? { value: applyText(rec.apply) + (rec.apply.at ? '   @ ' + rec.apply.at : '') } : null, ''],
    ['apply (res)', rec.applyResponse ? { value: applyText(rec.applyResponse) + (rec.applyResponse.at ? '   @ ' + rec.applyResponse.at : '') } : null, ''],
    ['apply (ws)', rec.applyWebSocket ? { value: applyText(rec.applyWebSocket) + '   @ ' + rec.applyWebSocket.url + '  (Burp 미지원)' } : null, ''],
    ['site', rec.site && rec.site.url ? { value: rec.site.url + ':' + rec.site.line + ':' + rec.site.col } : null, ''],
  ];
  if (rec.format) rows.splice(1, 0, ['format', { value: rec.format }, '']);
  // Skip the DOM rebuild when nothing changed (refreshApply runs every second; keeps text selection alive).
  const sig = rec.n + JSON.stringify(rows.map((r) => r[1] && r[1].value));
  if (sig === lastDetail) return;
  lastDetail = sig;

  const head = el('dHead');
  head.textContent = '#' + rec.n + ' ';
  head.appendChild(opBadge(rec.op));
  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = [rec.lib, algText(rec)].filter(Boolean).join(' · ');
  head.appendChild(meta);

  const body = el('dBody');
  body.textContent = '';
  for (const [label, obj, cls] of rows) {
    if (!obj && (label === 'format' || label.startsWith('apply'))) continue;
    const k = document.createElement('div');
    k.className = 'k';
    k.textContent = label;
    if (obj && obj.encoding) {
      const sm = document.createElement('small');
      sm.textContent = obj.encoding;
      k.appendChild(sm);
    }
    const v = document.createElement('pre');
    const has = obj && obj.value != null && obj.value !== '';
    v.className = has ? 'v' : 'v empty';
    v.textContent = has ? (cls === 'plain' ? pretty(obj.value) : String(obj.value)) : '—';
    body.append(k, v);
  }
}

function openInSources(url, line0, col0) {
  try {
    chrome.devtools.panels.openResource(url, line0, col0, () => void chrome.runtime.lastError);
  } catch (e) {
    setStatus('Sources 열기 실패: ' + e.message, true);
  }
}

/* ------------------------- buttons ------------------------- */
function updateHookBtn() {
  hookBtn.textContent = hooked ? 'Hook ON' : 'Hook OFF';
  hookBtn.classList.toggle('on', hooked);
}

hookBtn.onclick = async () => {
  hookBtn.disabled = true;
  try {
    if (!hooked) {
      await attach();
      hooked = true;
      setStatus('hooking — 탭을 새로고침했습니다');
    } else {
      await detach();
      hooked = false;
      setStatus('stopped');
    }
  } catch (e) {
    setStatus(e.message, true);
  } finally {
    updateHookBtn();
    hookBtn.disabled = false;
  }
};

el('clear').onclick = () => {
  records.length = 0;
  rowsEl.innerHTML = '';
  selected = null;
  lastDetail = '';
  el('detail').hidden = true;
  el('table').hidden = true;
  el('empty').hidden = false;
  el('count').textContent = '0 calls';
};

el('export').onclick = () => {
  const cfg = buildConfig(records);
  const blob = new Blob([JSON.stringify(cfg, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'config.json';
  a.click();
  URL.revokeObjectURL(url);
  setStatus('exported config.json (검토 후 키/인코딩 확인 필요)');
};

/* ------------------------- Send to Burp (0.3.0) ------------------------- */
const burp = { port: CryptoTraceBridge.DEFAULT_PORT, token: '', autoSend: false };
let lastSent = '';
let autoTimer = null;

chrome.storage.local.get(['burpPort', 'burpToken', 'autoSend'], (v) => {
  burp.port = Number(v.burpPort) || CryptoTraceBridge.DEFAULT_PORT;
  burp.token = v.burpToken || '';
  burp.autoSend = !!v.autoSend;
  el('burpPort').value = burp.port;
  el('burpToken').value = burp.token;
  el('autoSend').checked = burp.autoSend;
  if (!burp.token) el('burpBar').hidden = false; // first run: show where to paste the token
});

el('burpToggle').onclick = () => { el('burpBar').hidden = !el('burpBar').hidden; };

el('burpSave').onclick = async () => {
  burp.port = Number(el('burpPort').value) || CryptoTraceBridge.DEFAULT_PORT;
  burp.token = el('burpToken').value.trim();
  burp.autoSend = el('autoSend').checked;
  chrome.storage.local.set({ burpPort: burp.port, burpToken: burp.token, autoSend: burp.autoSend });
  const r = await CryptoTraceBridge.ping(fetch, burp);
  setStatus(r.text, !r.ok);
  if (r.ok) el('burpBar').hidden = true;
};

el('autoSend').onchange = () => {
  burp.autoSend = el('autoSend').checked;
  chrome.storage.local.set({ autoSend: burp.autoSend });
};

async function sendToBurp(manual) {
  const { cfg, skipped } = loadableConfig(buildConfig(records));
  const note = skipped.length ? ` · ${skipped.length}개 위치 제외(키 미포착: ${skipped.map((x) => x.split(':')[0]).join(', ')})` : '';
  if (!Object.keys(cfg.ciphers || {}).length) {
    if (manual) setStatus(skipped.length ? '보낼 수 있는 설정이 없습니다' + note : '보낼 암호화 설정이 아직 없습니다 (Hook ON 후 암호화 동작을 실행하세요)', true);
    return;
  }
  const json = JSON.stringify(cfg);
  if (!manual && json === lastSent) return;
  const r = await CryptoTraceBridge.send(fetch, burp, cfg);
  if (r.ok) lastSent = json;
  setStatus(r.text + note, !r.ok);
}

el('sendBurp').onclick = () => sendToBurp(true);

// Auto-send: a few seconds after the last captured call, only when the config actually changed.
function scheduleAutoSend() {
  if (!burp.autoSend || !burp.token) return;
  clearTimeout(autoTimer);
  autoTimer = setTimeout(() => sendToBurp(false), 3000);
}
