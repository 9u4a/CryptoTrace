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

// Install binding + persistent script into a target (the tab, or a child session).
async function installInto(target) {
  await cdp('Runtime.enable', {}, target);
  await cdp('Runtime.addBinding', { name: BINDING }, target);
  await cdp('Page.addScriptToEvaluateOnNewDocument', { source: hookSource }, target).catch(() => {});
}

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
    childSessions.add(sessionId);
    const child = { sessionId };
    (async () => {
      try {
        await installInto(child);
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
  if (rec.lib === 'transport') correlate(rec);
  records.push(rec);
  renderRow(rec);
  el('count').textContent = records.filter((r) => r.lib !== 'transport').length + ' calls';
}

// Match a transport record's fields against recent cipher outputs to find where ciphertext is placed.
function correlate(t) {
  const recentOutputs = records
    .filter((r) => r.output && r.output.value && r.lib !== 'transport')
    .slice(-30);
  const find = (value) => recentOutputs.find((r) => value && value.includes(r.output.value));

  const b = t.body || {};
  if (b.kind === 'json' && Array.isArray(b.fields)) {
    for (const f of b.fields) {
      const hit = find(f.value);
      if (hit) hit.apply = { in: 'json', path: f.path };
    }
  } else if (b.kind === 'text' && b.sample) {
    const hit = find(b.sample);
    if (hit) hit.apply = { in: 'body' };
  }
  for (const [name, value] of t.headers || []) {
    const hit = find(value);
    if (hit) hit.apply = { in: 'header', name };
  }
  for (const [name, value] of t.query || []) {
    const hit = find(value);
    if (hit) hit.apply = { in: 'query', name };
  }
}

/* ------------------------- rendering ------------------------- */
function short(obj) {
  if (!obj || obj.value == null) return '';
  const v = String(obj.value);
  return v.length > 48 ? v.slice(0, 45) + '…' : v;
}

function renderRow(rec) {
  if (rec.lib === 'transport') return; // transport rows only feed correlation
  el('table').hidden = false;
  el('empty').hidden = true;
  const tr = document.createElement('tr');
  const alg = rec.alg ? (rec.alg.name || '') + (rec.mode ? '/' + rec.mode : '') : '';
  const cells = [
    rec.n, rec.lib, rec.op, alg, short(rec.key), short(rec.iv), short(rec.input), short(rec.output),
  ];
  for (const c of cells) {
    const td = document.createElement('td');
    td.className = 'val';
    td.textContent = c == null ? '' : String(c);
    td.title = td.textContent;
    tr.appendChild(td);
  }
  const applyTd = document.createElement('td');
  applyTd.className = 'apply';
  applyTd.textContent = rec.apply ? rec.apply.in + (rec.apply.path || rec.apply.name ? ' ' + (rec.apply.path || rec.apply.name) : '') : '';
  tr.appendChild(applyTd);
  rec._applyTd = applyTd;

  const siteTd = document.createElement('td');
  if (rec.site && rec.site.url) {
    const a = document.createElement('span');
    a.className = 'loc link';
    const file = rec.site.url.split('/').pop();
    a.textContent = file + ':' + rec.site.line;
    a.title = rec.site.url + ':' + rec.site.line + ':' + rec.site.col;
    a.onclick = () => openInSources(rec.site.url, rec.site.line - 1, rec.site.col - 1);
    siteTd.appendChild(a);
  }
  tr.appendChild(siteTd);
  rowsEl.appendChild(tr);
}

// Re-paint apply cells (correlation may fill them after the row was drawn).
function refreshApply() {
  for (const r of records) {
    if (r._applyTd) {
      r._applyTd.textContent = r.apply ? r.apply.in + (r.apply.path || r.apply.name ? ' ' + (r.apply.path || r.apply.name) : '') : '';
    }
  }
}
setInterval(refreshApply, 1000);

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
