// Sample target client code. Keys are FAKE and hard-coded on purpose — this is what CryptoTrace must extract.
'use strict';

const $ = (id) => document.getElementById(id);
const log = (label, obj) => {
  $('log').textContent = `[${new Date().toLocaleTimeString()}] ${label}\n${JSON.stringify(obj, null, 2)}\n\n` + $('log').textContent;
};
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// Fake device id / request headers, like a typical banking web client sends.
const DEVICE_ID = 'WEB-' + Math.random().toString(16).slice(2, 10).toUpperCase();
const commonHeaders = () => ({ 'X-Request-Id': crypto.randomUUID(), 'X-Device-Id': DEVICE_ID, 'X-Channel': 'WEB' });

// ---- Plain (unencrypted) account list, mixed in like a real app ----
const won = (n) => n.toLocaleString('ko-KR') + '원';
async function loadAccounts() {
  const { data } = await (await fetch('/api/accounts', { headers: commonHeaders() })).json();
  $('acct-rows').innerHTML = data
    .map((a) => `<tr><td>${a.nick}<br><small>${a.acctNo}</small></td><td>${a.type === 'SAVING' ? '저축' : '입출금'}</td><td class="num">${won(a.balance)}</td></tr>`)
    .join('');
  const sel = $('b-from');
  const cur = sel.value;
  sel.innerHTML = data.map((a) => `<option value="${a.acctNo}">${a.nick} ${a.acctNo}</option>`).join('');
  if (cur) sel.value = cur;
}
loadAccounts();

// ---- A. CryptoJS AES-256-CBC, static key/IV ----
const A_KEY = CryptoJS.enc.Utf8.parse('ct-sample-aes-key-0123456789abcd');
const A_IV = CryptoJS.enc.Utf8.parse('ct-sample-iv-016');
const aOpts = { iv: A_IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 };

$('a-go').onclick = async () => {
  const plain = JSON.stringify({
    id: $('a-id').value,
    pw: $('a-pw').value,
    loginType: 'ID_PW',
    deviceId: DEVICE_ID,
    saveId: $('a-keep').checked,
    clientTs: Date.now(),
  });
  const data = CryptoJS.AES.encrypt(plain, A_KEY, aOpts).toString();
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...commonHeaders() },
    body: JSON.stringify({ data, channel: 'WEB', appVer: '3.12.0' }),
  });
  const text = await res.text();
  if (!res.ok) return log('로그인 실패', text);
  const reply = JSON.parse(CryptoJS.AES.decrypt(text, A_KEY, aOpts).toString(CryptoJS.enc.Utf8));
  if (reply.data) $('who').textContent = `${reply.data.custName}님 (${reply.data.grade}) · 최근 접속 ${reply.data.lastLoginAt.slice(0, 16).replace('T', ' ')}`;
  log('POST /api/login 응답 (복호화)', reply);
};

// ---- B. RSA-OAEP envelope with a fresh AES-GCM key per request ----
let serverKey;
async function getServerKey() {
  if (serverKey) return serverKey;
  const { spki } = await (await fetch('/api/pubkey')).json();
  serverKey = await crypto.subtle.importKey('spki', unb64(spki), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  return serverKey;
}

$('b-go').onclick = async () => {
  const rsa = await getServerKey();
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify({
    fromAcct: $('b-from').value,
    toBankCd: $('b-bank').value,
    to: $('b-to').value,
    toName: $('b-name').value,
    amount: Number($('b-amount').value),
    memo: $('b-memo').value,
    otpNo: $('b-otp').value,
    reqId: crypto.randomUUID(),
  }));
  const body = {
    ek: b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsa, rawKey)),
    iv: b64(iv),
    ct: b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plain)),
  };
  const res = await fetch('/api/transfer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...commonHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) return log('이체 실패', await res.text());
  const out = await res.json();
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(out.iv) }, aesKey, unb64(out.ct));
  log('POST /api/transfer 응답 (복호화)', JSON.parse(new TextDecoder().decode(dec)));
  loadAccounts();
};

// ---- C. Web Worker does the crypto, page only sends ----
const worker = new Worker('worker.js');
const pending = new Map();
let seq = 0;
worker.onmessage = ({ data }) => {
  pending.get(data.id)?.(data);
  pending.delete(data.id);
};
const callWorker = (op, payload) =>
  new Promise((resolve) => {
    const id = ++seq;
    pending.set(id, resolve);
    worker.postMessage({ id, op, payload });
  });

$('c-go').onclick = async () => {
  const plain = JSON.stringify({
    name: $('c-name').value,
    email: $('c-email').value,
    phone: $('c-phone').value,
    zipCode: $('c-zip').value,
    addr1: $('c-addr1').value,
    addr2: $('c-addr2').value,
    marketingAgree: $('c-mkt').checked,
  });
  const { result: body } = await callWorker('encrypt', plain);
  const res = await fetch('/api/profile', { method: 'POST', headers: { 'Content-Type': 'text/plain', ...commonHeaders() }, body });
  const text = await res.text();
  if (!res.ok) return log('저장 실패', text);
  const { result } = await callWorker('decrypt', text);
  log('POST /api/profile 응답 (복호화)', JSON.parse(result));
};
