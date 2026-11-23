'use strict';

/* Function tracer (L3): records the inputs and outputs of page functions that have no hookable API.
 * Given call-site frames (e.g. the stack of an "unknown" ciphertext), it pauses once inside each function
 * to learn where it starts, then breaks at its entry and at every return point: each call yields a
 * `traced` record {fn, args, ret, candidates}. Key candidates are 8/12/16/24/32-byte values in the
 * function's scopes (closure/script variables), since keys are rarely passed as arguments.
 * Pauses that are not ours (`debugger;` statements) are resumed at once; the page never stays paused.
 * Transport-agnostic: createTracer({cdp(method, params, target), emit(record), keyOf(target)}) is used by
 * panel.js (chrome.debugger) and by the E2E harness (raw CDP). Needs hook.js's globalThis.__ct_ser. */
(function () {
  const KEY_LENGTHS = new Set([8, 12, 16, 24, 32]);
  const SCOPES = new Set(['local', 'closure', 'script', 'block', 'module']);
  const SER_FN = 'function () { return globalThis.__ct_ser ? globalThis.__ct_ser(this) : null; }';

  function createTracer({ cdp, emit, keyOf = (t) => JSON.stringify(t), maxCandidates = 24 }) {
    const states = new Map();
    const stateOf = (t) => {
      const k = keyOf(t);
      if (!states.has(k)) states.set(k, { bps: new Map(), fns: new Map(), on: false });
      return states.get(k);
    };

    // A RemoteObject -> {encoding, value} (via the page's serializer for objects).
    async function serRemote(t, ro) {
      if (!ro || ro.type === 'undefined') return null;
      if (ro.type === 'string') return { encoding: 'utf8', value: ro.value };
      if (ro.type === 'number' || ro.type === 'boolean') return { encoding: 'json', value: String(ro.value) };
      if (!ro.objectId) return null;
      try {
        const r = await cdp('Runtime.callFunctionOn', { objectId: ro.objectId, functionDeclaration: SER_FN, returnByValue: true, silent: true }, t);
        return r.result ? r.result.value : null;
      } catch (_) { return null; }
    }

    async function argsOf(t, cf) {
      try {
        const r = await cdp('Debugger.evaluateOnCallFrame', { callFrameId: cf.callFrameId, returnByValue: true, silent: true,
          expression: 'Array.prototype.map.call(arguments, (a) => globalThis.__ct_ser(a))' }, t);
        if (!r.exceptionDetails && Array.isArray(r.result && r.result.value)) return r.result.value;
      } catch (_) { /* arrow function: no `arguments` -- fall back to the local scope */ }
      const local = (cf.scopeChain || []).find((s) => s.type === 'local');
      if (!local) return [];
      const out = [];
      try {
        const { result } = await cdp('Runtime.getProperties', { objectId: local.object.objectId, ownProperties: true }, t);
        for (const p of result.slice(0, 8)) out.push(await serRemote(t, p.value));
      } catch (_) {}
      return out;
    }

    // Byte-sized values in the function's scopes: where a hard-coded key / IV usually lives.
    async function candidatesOf(t, cf) {
      const out = [];
      for (const scope of cf.scopeChain || []) {
        if (!SCOPES.has(scope.type) || !scope.object || !scope.object.objectId) continue;
        let props = [];
        try { props = (await cdp('Runtime.getProperties', { objectId: scope.object.objectId, ownProperties: true }, t)).result || []; } catch (_) {}
        for (const p of props.slice(0, 200)) {
          const v = p.value;
          if (!v) continue;
          const isStr = v.type === 'string' && KEY_LENGTHS.has(v.value.length);
          const m = (v.description || '').match(/^(?:Uint8Array|ArrayBuffer|Int8Array)\((\d+)\)$/);
          const isBytes = (v.subtype === 'typedarray' || v.subtype === 'arraybuffer') && m && KEY_LENGTHS.has(Number(m[1]));
          if (!isStr && !isBytes) continue;
          const value = await serRemote(t, v);
          if (value) out.push({ name: p.name, scope: scope.type, value });
          if (out.length >= maxCandidates) return out;
        }
      }
      return out;
    }

    // First hit inside a function: learn its range, break at its entry and every return point.
    async function arm(t, s, cf, bp, id) {
      await cdp('Debugger.removeBreakpoint', { breakpointId: id }, t).catch(() => {});
      s.bps.delete(id);
      const loc = cf.functionLocation;
      if (!loc) return;
      const key = loc.scriptId + ':' + loc.lineNumber + ':' + loc.columnNumber;
      if (s.fns.has(key)) return;
      const fn = { key, name: cf.functionName || bp.name || '(anonymous)', url: cf.url || bp.url,
        line: loc.lineNumber + 1, col: loc.columnNumber + 1, stack: [], candidates: null };
      s.fns.set(key, fn);
      const { locations } = await cdp('Debugger.getPossibleBreakpoints', { start: loc, restrictToFunction: true }, t);
      const body = locations.filter((l) => l.type !== 'return');
      for (const l of locations.filter((x) => x.type === 'return')) {
        const r = await cdp('Debugger.setBreakpoint', { location: { scriptId: l.scriptId, lineNumber: l.lineNumber, columnNumber: l.columnNumber } }, t);
        s.bps.set(r.breakpointId, { kind: 'return', fn: key });
      }
      if (body.length) {
        const first = body[0];
        const r = await cdp('Debugger.setBreakpoint', { location: { scriptId: first.scriptId, lineNumber: first.lineNumber, columnNumber: first.columnNumber } }, t);
        s.bps.set(r.breakpointId, { kind: 'entry', fn: key });
      }
      // the page this runs in (like hook records' `frame`): the config's scope host comes from it
      try {
        const r = await cdp('Debugger.evaluateOnCallFrame', { callFrameId: cf.callFrameId, expression: 'location.href', returnByValue: true, silent: true }, t);
        fn.frame = r.result && typeof r.result.value === 'string' ? r.result.value : '';
      } catch (_) { fn.frame = ''; }
      // the call in flight is already past its entry: take its arguments now
      fn.candidates = await candidatesOf(t, cf);
      fn.stack.push({ args: await argsOf(t, cf) });
    }

    async function onEntry(t, s, cf, bp) {
      const fn = s.fns.get(bp.fn);
      if (!fn) return;
      if (!fn.candidates) fn.candidates = await candidatesOf(t, cf);
      fn.stack.push({ args: await argsOf(t, cf) });
    }

    async function onReturn(t, s, cf, bp) {
      const fn = s.fns.get(bp.fn);
      if (!fn) return;
      const call = fn.stack.pop() || { args: null };
      const ret = await serRemote(t, cf.returnValue);
      const args = call.args || [];
      const input = args.find((a) => a && (a.encoding === 'utf8' || a.encoding === 'base64')) || null;
      emit({ lib: 'traced', op: 'call', fn: fn.name, alg: { name: fn.name + '()' }, args, input, output: ret,
        candidates: fn.candidates || [], site: { url: fn.url, line: fn.line, col: fn.col }, frame: fn.frame || '' });
    }

    const ORDER = { callsite: 0, entry: 1, return: 2 };

    return {
      /** Start tracing the functions that contain these call-site frames ({fn, url, line, col}, 1-based). */
      async traceFrames(t, frames) {
        const s = stateOf(t);
        if (!s.on) { await cdp('Debugger.setSkipAllPauses', { skip: false }, t); s.on = true; }
        const armed = [];
        for (const f of frames) {
          if (!f || !f.url) continue;
          try {
            const r = await cdp('Debugger.setBreakpointByUrl', { url: f.url, lineNumber: f.line - 1, columnNumber: f.col - 1 }, t);
            s.bps.set(r.breakpointId, { kind: 'callsite', name: f.fn, url: f.url });
            armed.push(f.fn);
          } catch (_) { /* not breakable here */ }
        }
        return armed;
      },
      /** Route every Debugger.paused event here. Always resumes. Returns true when the pause was ours. */
      async onPaused(t, p) {
        const s = stateOf(t);
        const ids = (p.hitBreakpoints || []).filter((id) => s.bps.has(id)).sort((a, b) => ORDER[s.bps.get(a).kind] - ORDER[s.bps.get(b).kind]);
        try {
          const cf = p.callFrames && p.callFrames[0];
          for (const id of ids) {
            const bp = s.bps.get(id);
            if (!bp || !cf) continue;
            if (bp.kind === 'callsite') await arm(t, s, cf, bp, id);
            else if (bp.kind === 'entry') await onEntry(t, s, cf, bp);
            else if (bp.kind === 'return') await onReturn(t, s, cf, bp);
          }
        } catch (_) { /* never leave the page paused */ } finally {
          await cdp('Debugger.resume', {}, t).catch(() => {});
        }
        return ids.length > 0;
      },
      /** Remove every tracing breakpoint and go back to never pausing. */
      async stop(t) {
        const s = stateOf(t);
        for (const id of s.bps.keys()) await cdp('Debugger.removeBreakpoint', { breakpointId: id }, t).catch(() => {});
        s.bps.clear();
        s.fns.clear();
        if (s.on) { await cdp('Debugger.setSkipAllPauses', { skip: true }, t).catch(() => {}); s.on = false; }
      },
      traced(t) { return [...stateOf(t).fns.values()].map((f) => ({ name: f.name, url: f.url, line: f.line })); },
    };
  }

  window.CryptoTraceTracer = { createTracer };
})();
