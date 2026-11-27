'use strict';

/* ------------------------- state ------------------------- */
const tabId = chrome.devtools.inspectedWindow.tabId;
const DEBUGGEE = { tabId };
const CDP_VERSION = '1.3';
const BINDING = '__cryptotrace_emit';

let attached = false;
let hooked = false;
let hookSource = '';
let tracer = null; // tracer.js instance while attached
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

// The status bar shows the latest message; every message is kept (newest first) and the bar opens the log,
// so an error replaced by a later message can still be read. Errors not yet seen are counted on the bar.
const statusHistory = [];
let unseenErrors = 0;
function renderStatusLog() {
  const log = el('statusLog');
  log.textContent = '';
  for (const h of statusHistory) {
    const line = document.createElement('div');
    if (h.err) line.className = 'err';
    line.textContent = '[' + h.t + '] ' + h.msg;
    log.appendChild(line);
  }
}
function setStatus(msg, isErr) {
  statusEl.textContent = msg || '';
  statusEl.title = msg || '';
  statusEl.style.color = isErr ? '#d93025' : 'var(--muted)';
  if (!msg) return;
  statusHistory.unshift({ t: new Date().toLocaleTimeString(), msg, err: !!isErr });
  if (statusHistory.length > 50) statusHistory.pop();
  if (isErr && el('statusLog').hidden) unseenErrors++;
  el('statusCount').textContent = unseenErrors ? '오류 ' + unseenErrors + '건 ▾' : '';
  if (!el('statusLog').hidden) renderStatusLog();
}
el('statusbar').onclick = () => {
  const log = el('statusLog');
  log.hidden = !log.hidden;
  if (!log.hidden) { unseenErrors = 0; el('statusCount').textContent = ''; renderStatusLog(); }
};

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
  await enableScan(target);
  if (isWorker) {
    await cdp('Runtime.evaluate', { expression: hookSource }, target).catch((e) =>
      setStatus('worker hook eval failed: ' + e.message, true),
    );
  } else {
    // without this the page is never hooked and capture stays silently empty: say so
    await cdp('Page.addScriptToEvaluateOnNewDocument', { source: hookSource }, target).catch((e) =>
      setStatus('hook injection failed: ' + e.message, true),
    );
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
  // L3 function tracer (tracer.js): started per "unknown" row; its records go through addRecord like hooks'.
  tracer = window.CryptoTraceTracer.createTracer({ cdp, keyOf: (t) => t.sessionId || 'main',
    emit: (r, t) => { Object.defineProperty(r, '__target', { value: t, enumerable: false }); addRecord(r); },
    scriptsOf: (t) => scriptsBySession.get(t.sessionId || 'main') || [] });
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
  tracer = null; // its breakpoints go away with the debugger session
  childSessions.clear();
  await new Promise((resolve) => chrome.debugger.detach(DEBUGGEE, () => { void chrome.runtime.lastError; resolve(); }));
}

/* ------------------------- constant-signature scan ------------------------- */
// Every script the page (or a worker) parses is scanned for cipher/hash constants (signatures.json via
// signatures.js): this finds crypto with no library API to hook -- SEED/ARIA ports, inlined or obfuscated
// copies. Passive: reads script sources only. Our session never pauses (anti-debug `debugger;` traps).
let signatures = null;
const scannedScripts = new Set(); // script hash (or id): each source scanned once
const findingKeys = new Set();
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
let findingSeq = 0;

async function enableScan(target) {
  try {
    if (!signatures) signatures = await (await fetch(chrome.runtime.getURL('signatures.json'))).json();
    await cdp('Debugger.enable', {}, target);
    await cdp('Debugger.setSkipAllPauses', { skip: true }, target);
  } catch (e) {
    setStatus('script scan unavailable: ' + e.message, true);
  }
}

// Parsed scripts per session (page = 'main', workers/iframes by sessionId): the tracer resolves eval frames with it.
const scriptsBySession = new Map();

async function scanScript(target, p) {
  const sk = target.sessionId || 'main';
  if (!scriptsBySession.has(sk)) scriptsBySession.set(sk, []);
  scriptsBySession.get(sk).push({ scriptId: p.scriptId, url: p.url || '' });
  if (!signatures || !window.CryptoTraceScan) return;
  if (/^(chrome-extension|devtools|chrome):/.test(p.url || '') || (p.length || 0) > MAX_SCAN_BYTES) return;
  const key = p.hash || p.scriptId;
  if (scannedScripts.has(key)) return;
  scannedScripts.add(key);
  let src;
  try { src = (await cdp('Debugger.getScriptSource', { scriptId: p.scriptId }, target)).scriptSource; } catch (_) { return; }
  for (const f of window.CryptoTraceScan.scanSource(src, signatures)) {
    // positions are within the script; a script embedded in HTML starts at startLine/startColumn
    const line = f.line + (p.startLine || 0);
    const col = f.line === 0 ? f.col + (p.startColumn || 0) : f.col;
    const k = f.id + '|' + (p.url || p.scriptId) + '|' + line;
    if (findingKeys.has(k)) continue;
    findingKeys.add(k);
    renderRow({ n: 'S' + ++findingSeq, lib: 'scan', op: 'scan', alg: { name: f.name }, scan: f,
      site: p.url ? { url: p.url, line: line + 1, col: col + 1 } : null, scriptUrl: p.url || '(eval/inline script ' + p.scriptId + ')' });
  }
}

/* ------------------------- events ------------------------- */
function onEvent(source, method, params) {
  if (!attached || source.tabId !== tabId) return;
  if (method === 'Debugger.scriptParsed') {
    scanScript(source.sessionId ? { tabId, sessionId: source.sessionId } : DEBUGGEE, params);
    return;
  }
  if (method === 'Debugger.paused') {
    // Only tracing makes our session pause; the tracer records and always resumes.
    const target = source.sessionId ? { tabId, sessionId: source.sessionId } : DEBUGGEE;
    if (tracer) tracer.onPaused(target, params);
    else cdp('Debugger.resume', {}, target).catch(() => {});
    return;
  }
  if (method === 'Runtime.bindingCalled' && params.name === BINDING) {
    try {
      const rec = JSON.parse(params.payload);
      // where it came from (page or a worker/iframe session): tracing an unknown value runs in that realm
      Object.defineProperty(rec, '__target', { value: source.sessionId ? { tabId, sessionId: source.sessionId } : DEBUGGEE, enumerable: false });
      addRecord(rec);
    } catch (_) {}
    return;
  }
  if (method === 'Target.detachedFromTarget') {
    // a worker ended / an iframe went away: drop its per-session state
    childSessions.delete(params.sessionId);
    scriptsBySession.delete(params.sessionId);
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
      } catch (e) {
        setStatus('worker/iframe hook failed: ' + e.message, true);
      } finally {
        // it was attached paused (waitForDebuggerOnStart): resume it even when hooking failed, or it hangs forever
        await cdp('Runtime.runIfWaitingForDebugger', {}, child).catch(() => {});
      }
    })();
  }
}

function onDetach(source, reason) {
  if (source.tabId !== tabId) return;
  attached = false;
  hooked = false;
  tracer = null; // its breakpoints went away with the session; a later Hook ON starts a fresh tracer
  childSessions.clear();
  scriptsBySession.clear();
  updateHookBtn();
  const why = reason === 'canceled_by_user' ? '디버깅 배너에서 취소됨' : reason === 'target_closed' ? '탭이 닫힘' : reason;
  setStatus('디버거 분리됨 (' + why + ') — 캡처가 멈췄습니다. 다시 시작하려면 Hook ON (페이지가 새로고침됩니다).', true);
}

chrome.debugger.onEvent.addListener(onEvent);
chrome.debugger.onDetach.addListener(onDetach);
window.addEventListener('unload', () => { if (attached) chrome.debugger.detach(DEBUGGEE, () => void chrome.runtime.lastError); });

/* ------------------------- records + correlation ------------------------- */
// An `origin` record (hook-transport.js): a sent value that looks like ciphertext, traced to the encoding call
// that produced it. Shown as an "unknown" row only when no captured crypto call already explains that
// location (correlate.js ran on the transport record just before), once per location.
const originKeys = new Set();
function addOrigin(o) {
  if (window.isExplained(o, records)) return; // a hooked call explains it (correlate.js)
  const at = (() => { try { return new URL(o.url, 'http://x').pathname; } catch (_) { return ''; } })();
  const key = o.loc.in + '|' + (o.loc.path || o.loc.name || '') + '|' + at;
  if (originKeys.has(key)) return;
  originKeys.add(key);
  const top = o.frames[0];
  renderRow({ n: 'U' + originKeys.size, lib: 'origin', op: 'unknown', alg: { name: o.sink + ' → ' + applyText(o.loc) }, origin: o,
    apply: null, site: top ? { url: top.url, line: top.line, col: top.col } : null });
}

// Memory cap for long sessions: transport records (every request/response seen) are only needed for correlation
// when they arrive and for integrity drafting, so the oldest are dropped past this many. Crypto call records
// define the config and are kept.
const MAX_TRANSPORT = 1500;
let recordSeq = 0;
function pruneTransport() {
  let excess = records.filter((r) => r.lib === 'transport').length - MAX_TRANSPORT;
  if (excess <= 0) return;
  for (let i = 0; i < records.length && excess > 0; ) {
    const r = records[i];
    if (r.lib === 'transport' && r !== selected) {
      if (r._tr) r._tr.remove();
      records.splice(i, 1);
      excess--;
    } else i++;
  }
}

function addRecord(rec) {
  if (rec.lib === 'origin') return addOrigin(rec);
  rec.n = ++recordSeq;
  if (rec.lib === 'transport') window.correlate(rec, records); // correlate.js
  else if (rec.op === 'decrypt') window.correlateLate(rec, records); // decrypted after its response arrived
  records.push(rec);
  if (rec.lib === 'transport') pruneTransport();
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
  b.className = op === 'encrypt' ? 'op-encrypt' : op === 'decrypt' ? 'op-decrypt' : op === 'scan' ? 'op-scan' : op === 'unknown' ? 'op-unknown' : '';
  b.textContent = op || '';
  return b;
}

function isHidden(rec) {
  return el('onlyCipher').checked && !CIPHER_OPS.has(rec.op) && rec.op !== 'scan' && rec.op !== 'unknown' && rec.op !== 'call'; // findings and traced calls always shown
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
  const rows = rec.op === 'scan' ? [
    ['algorithm', { value: rec.scan.algo + (rec.scan.strength === 'weak' ? ' (약한 신호)' : '') }, ''],
    ['what', { value: rec.scan.name + (rec.scan.note ? ' - ' + rec.scan.note : '') }, ''],
    ['code', { value: rec.scan.snippet }, ''],
    ['script', { value: rec.scriptUrl + (rec.site ? ':' + rec.site.line + ':' + rec.site.col : '') }, ''],
    ['next', { value: '이 위치 주변 함수가 암호화 지점 후보입니다. Sources에서 열어 호출 흐름을 확인하세요.' }, ''],
  ] : rec.op === 'unknown' ? [
    ['value', { value: rec.origin.value }, ''],
    ['sent in', { value: applyText(rec.origin.loc) + '   @ ' + rec.origin.url + '  (' + rec.origin.via + ')' }, ''],
    ['made by', { value: rec.origin.sink + '()  ← 아래 함수들이 이 값을 만들었습니다 (위가 가장 안쪽)' }, ''],
    ['call stack', { value: rec.origin.frames.map((f) => f.fn + '   ' + f.url + ':' + f.line + ':' + f.col).join('\n') || '—' }, ''],
    ['next', { value: '알려진 라이브러리 호출로 설명되지 않는 암호문입니다. 스택의 사이트 함수(예: 직접 만든 encrypt)를 Sources에서 열어 알고리즘·키를 확인하세요.' }, ''],
  ] : [
    ['key', rec.key, ''],
    ['iv', rec.iv, ''],
    [rec.op === 'decrypt' ? 'input (암호문)' : rec.op === 'encrypt' ? 'input (평문)' : 'input', rec.input, isPlain('input') ? 'plain' : ''],
    [rec.op === 'encrypt' ? 'output (암호문)' : rec.op === 'decrypt' ? 'output (평문)' : 'output', rec.output, isPlain('output') ? 'plain' : ''],
    ['apply (req)', rec.apply ? { value: applyText(rec.apply) + (rec.apply.at ? '   @ ' + rec.apply.at : '') } : null, ''],
    ['apply (res)', rec.applyResponse ? { value: applyText(rec.applyResponse) + (rec.applyResponse.at ? '   @ ' + rec.applyResponse.at : '') } : null, ''],
    ['apply (ws)', rec.applyWebSocket ? { value: applyText(rec.applyWebSocket) + '   @ ' + rec.applyWebSocket.url + '  (Burp 미지원)' } : null, ''],
    ['site', rec.site && rec.site.url ? { value: rec.site.url + ':' + rec.site.line + ':' + rec.site.col } : null, ''],
    ['candidates', rec.candidates && rec.candidates.length
      ? { value: rec.candidates.map((c) => `${c.scope} ${c.name} = ${c.value.encoding}:${c.value.value}`).join('\n') } : null, ''],
  ];
  if (rec.lib === 'traced') {
    rows.push(['oracle', { value: rec.oracleKey ? '등록됨 — 판정이 안 되면 Burp 재암호화 때 이 함수를 직접 호출 (Burp Options + 패널 "오라클" 켜기)' : '등록 안 됨 (함수 참조를 찾지 못함)' }, '']);
    rows.push(['next', { value: 'Send to Burp 하면 서버가 위 후보로 알고리즘·키·IV를 판정합니다 (로드 결과 identified).' }, '']);
  }
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
    if (!obj && (label === 'format' || label === 'candidates' || label.startsWith('apply'))) continue;
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
  if (rec.op === 'unknown') {
    // L3: trace the functions on this stack -- the next call records their input/output and key candidates.
    const btn = document.createElement('button');
    // Re-arming stays possible: a page reload drops the registered functions (and the oracle stops tracing
    // once it runs), so the analyst can trace again without closing DevTools.
    btn.textContent = rec.traceArmed ? '다시 추적 (새로고침 후 오라클이 "not registered"이면)' : '이 함수들 추적 (다음 호출의 입력·출력·키 후보 기록)';
    btn.disabled = !tracer;
    btn.onclick = async () => {
      btn.disabled = true;
      try {
        const armed = await tracer.traceFrames(rec.origin.__target || DEBUGGEE, tracer.pickFrames(rec.origin.frames));
        rec.traceArmed = true;
        lastDetail = '';
        renderDetail(rec);
        setStatus('추적 시작: ' + armed.join(', ') + ' — 페이지에서 같은 기능을 다시 실행하세요');
      } catch (e) {
        btn.disabled = false;
        setStatus('추적 실패: ' + e.message, true);
      }
    };
    body.append(btn);
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
  recordSeq = 0;
  originKeys.clear(); // let "unknown" rows appear again (e.g. to re-trace after a page reload)
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

/* ------------------------- L4 browser oracle ------------------------- */
// ACTIVE, off on every DevTools session: while on (and Hook ON), long-poll Burp for jobs -- "re-encrypt this edited
// plaintext with page function X" -- run that registered function in the page (tracer.js oracleExpression) and
// post the result. One job at a time; Burp throttles (Options > min interval).
let oracleRunning = false;
let oracleState = '';
let oracleDone = 0;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function oracleSay(state, msg, isErr) {
  if (state === oracleState) return; // no status spam while polling
  oracleState = state;
  setStatus(msg, isErr);
}
// The inspected page's origin, so Burp routes this tab's jobs here (several tabs may run the oracle).
function inspectedOrigin() {
  return new Promise((resolve) => {
    try {
      chrome.devtools.inspectedWindow.eval('location.origin', (v, err) => resolve(!err && typeof v === 'string' && v !== 'null' ? v : ''));
    } catch (_) {
      resolve('');
    }
  });
}
const ORACLE_CALL_MS = 5000; // < Burp's stale limit (7 s) and the server's oracle timeout (8 s)
async function oracleLoop() {
  if (oracleRunning) return;
  oracleRunning = true;
  try {
    while (el('oracleOn').checked) {
      if (!attached) { oracleSay('detached', '오라클: Hook ON 상태에서만 동작합니다', true); await sleep(2000); continue; }
      const r = await CryptoTraceBridge.oracleNext(fetch, burp, 8000, await inspectedOrigin());
      if (r.error) { oracleSay('err:' + r.error, '오라클: ' + r.error, true); await sleep(3000); continue; }
      if (!r.enabled) { oracleSay('off', '오라클: Burp > CryptoTrace > Options에서 Browser oracle을 켜세요', true); await sleep(3000); continue; }
      oracleSay('ready', '오라클 대기 중 (Burp가 재암호화할 때 페이지 함수를 호출합니다)');
      if (!r.job) continue;
      const job = r.job;
      const owner = records.find((x) => x.lib === 'traced' && x.oracleKey === job.fn);
      try {
        const target = (owner && owner.__target) || DEBUGGEE;
        oracleSay('run' + job.oid, `오라클 #${job.oid}: 페이지 함수 ${String(job.fn).split('@')[0]}() 실행 중`);
        // Tracing must be off before the page function runs: with DevTools open, its own debugger session also
        // stops at our breakpoints (skipAllPauses is per session) and leaves the page paused. The function is
        // registered already, so tracing has done its job.
        if (tracer) {
          const wasTracing = tracer.traced(target).length > 0;
          await tracer.stop(target);
          if (wasTracing) setStatus('추적 종료: 오라클이 등록된 함수를 직접 호출합니다');
        }
        // never wait past the server's deadline: a stuck call would stop this loop from picking up the next jobs
        const deadline = Date.now() + ORACLE_CALL_MS;
        const run = () => {
          const left = Math.max(300, deadline - Date.now());
          return Promise.race([
            cdp('Runtime.evaluate', { expression: CryptoTraceTracer.oracleExpression(job.fn, job.value),
              awaitPromise: true, returnByValue: true, timeout: left }, target),
            sleep(left + 500).then(() => { throw new Error(`페이지 함수가 ${ORACLE_CALL_MS / 1000}초 안에 끝나지 않음 (Sources에서 일시정지 중?)`); }),
          ]);
        };
        let res = await run();
        // page reloaded since tracing: find the same function again (heap, by name + location) and call it once more
        if (CryptoTraceTracer.isNotRegistered(res) && tracer && await tracer.reregister(target, job.fn)) {
          setStatus(`오라클: 새로고침된 페이지에서 ${String(job.fn).split('@')[0]}()를 다시 찾아 등록했습니다`);
          res = await run();
        }
        // first line only: the description carries a stack of the injected expression, useless in Burp's log
        if (res.exceptionDetails) throw new Error(String((res.exceptionDetails.exception && res.exceptionDetails.exception.description) || 'page function threw').split('\n')[0].replace(/^Error: /, ''));
        await CryptoTraceBridge.oracleResult(fetch, burp, { oid: job.oid, ok: true, value: String(res.result.value) });
        oracleDone++;
        oracleState = '';
        oracleSay('done' + oracleDone, `오라클: 페이지 함수로 ${oracleDone}건 재암호화 (${String(job.fn).split('@')[0]})`);
      } catch (e) {
        await CryptoTraceBridge.oracleResult(fetch, burp, { oid: job.oid, ok: false, error: e.message });
        oracleState = '';
        oracleSay('fail', '오라클 실패: ' + e.message, true);
      }
    }
  } finally {
    oracleRunning = false;
    oracleState = '';
  }
}
el('oracleOn').onchange = () => {
  if (el('oracleOn').checked) oracleLoop();
  else setStatus('오라클 꺼짐');
};

async function sendToBurp(manual) {
  const { cfg, skipped } = loadableConfig(buildConfig(records));
  // Left-out locations grouped by their actual reason (loadableConfig: "<side> <where>: <reason>").
  const REASONS = [
    [/per request/, '요청마다 키가 바뀜(고정 키 아님)'],
    [/RSA key not captured/, 'RSA 키 미포착'],
    [/custom module/, '커스텀 모듈 필요'],
    [/key not captured/, '키 미포착'],
  ];
  const groups = new Map();
  for (const x of skipped) {
    const i = x.indexOf(': ');
    const where = i < 0 ? x : x.slice(0, i);
    const why = (REASONS.find(([re]) => re.test(x)) || [null, x.slice(i + 2)])[1];
    if (!groups.has(why)) groups.set(why, []);
    groups.get(why).push(where);
  }
  const note = skipped.length ? ` · ${skipped.length}개 위치 제외 — ` + [...groups].map(([why, ws]) => `${why}: ${ws.join(', ')}`).join(' / ') : '';
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
