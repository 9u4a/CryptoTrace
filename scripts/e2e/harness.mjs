// Headless-Chrome harness for end-to-end checks: one tab with the CryptoTrace hooks injected and the
// Debugger enabled exactly as panel.js does it (raw CDP instead of chrome.debugger), plus the panel's
// pure modules (signatures/correlate/config-builder/tracer) loaded for replaying its pipeline.
//   const b = await launchChrome(chromePath);  const tab = await b.open(url);  ...  await b.close();
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The panel's pure modules in one sandbox: CryptoTraceScan, correlate, isExplained, buildConfig, loadableConfig, CryptoTraceTracer. */
export function panelModules() {
  const sb = { window: {}, URL, Date };
  for (const f of ['signatures.js', 'correlate.js', 'config-builder.js', 'tracer.js']) {
    vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'chrome-ext', f), 'utf8'), sb, { filename: f });
  }
  sb.window.signatures = JSON.parse(fs.readFileSync(path.join(ROOT, 'chrome-ext/signatures.json'), 'utf8'));
  return sb.window;
}

export function findChrome() {
  const c = [process.env.CHROME, 'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'];
  return c.find((p) => p && fs.existsSync(p)) || null;
}

export async function launchChrome(chromePath) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-e2e-chrome-'));
  const proc = spawn(chromePath, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  let wsUrl;
  for (let i = 0; i < 150 && !wsUrl; i++) {
    await sleep(100);
    try { const [p, wsPath] = fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').trim().split('\n'); wsUrl = `ws://127.0.0.1:${p}${wsPath}`; } catch (_) {}
  }
  if (!wsUrl) throw new Error('Chrome did not start');
  const ws = new WebSocket(wsUrl);
  await new Promise((r, j) => { ws.addEventListener('open', r); ws.addEventListener('error', j); });
  let id = 0;
  const waiting = new Map();
  const sessions = new Map(); // sessionId -> tab
  ws.addEventListener('message', ({ data }) => {
    const m = JSON.parse(data);
    if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); }
    const tab = m.sessionId && sessions.get(m.sessionId);
    if (tab) tab._event(m);
  });
  const cdp = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const msg = { id: ++id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    waiting.set(msg.id, (m) => (m.error ? reject(new Error(method + ': ' + m.error.message)) : resolve(m.result)));
    ws.send(JSON.stringify(msg));
  });
  const hookSource = ['hook.js', 'hook-transport.js'].map((f) => fs.readFileSync(path.join(ROOT, 'chrome-ext', f), 'utf8')).join('\n;\n');

  return {
    cdp,
    /** Open a tab with hooks + scan-ready Debugger, navigate, wait for load. */
    async open(url, { settle = 1200 } = {}) {
      const { targetId } = await cdp('Target.createTarget', { url: 'about:blank' });
      const { sessionId: s } = await cdp('Target.attachToTarget', { targetId, flatten: true });
      const tab = { s, targetId, records: [], parsed: [], listeners: [] };
      tab._event = (m) => {
        if (m.method === 'Runtime.bindingCalled' && m.params.name === '__cryptotrace_emit') { try { tab.records.push(JSON.parse(m.params.payload)); } catch (_) {} }
        if (m.method === 'Debugger.scriptParsed') tab.parsed.push(m.params);
        for (const l of tab.listeners) l(m);
      };
      sessions.set(s, tab);
      await cdp('Page.enable', {}, s);
      await cdp('Runtime.enable', {}, s);
      await cdp('Runtime.addBinding', { name: '__cryptotrace_emit' }, s);
      await cdp('Debugger.enable', {}, s);
      await cdp('Debugger.setSkipAllPauses', { skip: true }, s);
      await cdp('Page.addScriptToEvaluateOnNewDocument', { source: hookSource }, s);
      await cdp('Page.navigate', { url }, s);
      await sleep(settle);
      tab.evaluate = async (expression) => {
        const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, s);
        if (r.exceptionDetails) throw new Error('page: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
        return r.result.value;
      };
      tab.close = () => cdp('Target.closeTarget', { targetId }).catch(() => {});
      return tab;
    },
    async close() {
      try { ws.close(); } catch (_) {}
      proc.kill();
      await sleep(500);
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) {}
    },
  };
}
