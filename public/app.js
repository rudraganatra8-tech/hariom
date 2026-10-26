'use strict';
(() => {
// ---------- state ----------
const CFGK = 'hariom_cfg', CK = 'hariom_cache';
let CFG = {};
try { CFG = JSON.parse(localStorage.getItem(CFGK)) || {}; } catch {}
const saveCfg = () => { try { localStorage.setItem(CFGK, JSON.stringify(CFG)); } catch {} };
let S = null;      // { data:{parties,txns,reminders}, outbox:[] }  only in memory while unlocked
let K = null;      // local encryption key (derived from your PIN, never stored)
let PIN = '';      // kept in memory only, to log in again silently when the session expires
const emptyS = () => ({ data: { parties: [], txns: [], reminders: [], cash: [], cats: [] }, outbox: [] });
const TABS = ['home', 'recv', 'pay', 'more', 'rem', 'me'];
const UI = { tab: 'home', layers: [], sheet: null, status: 'idle', mode: 'login', hasUser: true, ready: true, recovery: null, remTab: 'up', pfilter: 'all', err: '', pinBuf: '', me: null, counts: {}, shell: false, startTab: null };

// ---------- helpers ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : 'x' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10));
const pad = (n) => String(n).padStart(2, '0');
const inr = (n) => { const a = Math.abs(n); return '₹' + new Intl.NumberFormat('en-IN', { minimumFractionDigits: Number.isInteger(a) ? 0 : 2, maximumFractionDigits: 2 }).format(a); };
const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const hm = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
const nowParts = () => { const d = new Date(); return { date: ymd(d), time: hm(d) }; };
const parseAt = (s) => { const [d, t = '00:00'] = s.split('T'); const [y, m, da] = d.split('-').map(Number); const [h, mi] = t.split(':').map(Number); return new Date(y, m - 1, da, h, mi); };
const fDate = (d) => d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
const fTime = (d) => d.toLocaleTimeString('en-IN', { hour: 'numeric', minute: '2-digit', hour12: true }).toUpperCase();
const fMonth = (d) => d.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' });
const initial = (n) => (n || '?').trim().charAt(0).toUpperCase();
const r2 = (n) => Math.round(n * 100) / 100;
const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const hap = (p = 8) => { if (CFG.haptics === false) return; try { navigator.vibrate && navigator.vibrate(p); } catch {} };

const ICON = {
  home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
  recv: '<path d="M17 7L7 17"/><path d="M17 17H7V7"/>',
  pay: '<path d="M7 17L17 7"/><path d="M7 7h10v10"/>',
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  back: '<path d="M15 18l-6-6 6-6"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  wa: '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>',
  dots: '<circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/>',
  inc: '<path d="M22 7l-8.5 8.5-5-5L2 17"/><path d="M16 7h6v6"/>',
  exp: '<path d="M22 17l-8.5-8.5-5 5L2 7"/><path d="M16 17h6v-6"/>',
  next: '<path d="M9 18l6-6-6-6"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
};
const ic = (n) => `<svg class="i" viewBox="0 0 24 24">${ICON[n]}</svg>`;

// ---------- local encryption (your data is locked on this phone with your PIN) ----------
const te = new TextEncoder(), td = new TextDecoder();
const IOS = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const STANDALONE = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
const BIO_NAME = IOS ? 'Face ID / Touch ID' : 'fingerprint / face';
let deferredInstall = null;
addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferredInstall = e; });
const b64e = (u8) => { let s = ''; for (const x of u8) s += String.fromCharCode(x); return btoa(s); };
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function deriveKey(pin, saltB64) {
  const base = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64d(saltB64), iterations: 150000 }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function sealCache() {
  if (!K || !S) return;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, K, te.encode(JSON.stringify(S))));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  try { localStorage.setItem(CK, b64e(out)); } catch {}
}
async function openCache(key) {
  const raw = localStorage.getItem(CK); if (!raw) throw new Error('none');
  const u = b64d(raw);
  return JSON.parse(td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12))));
}
let ptimer;
// ---------- quick unlock: fingerprint / face / phone screen lock (WebAuthn, handled by the phone itself) ----------
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
function idb() { return new Promise((res, rej) => { const r = indexedDB.open('hariom-bio', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function idbGet(k) { const db = await idb(); return new Promise((res, rej) => { const q = db.transaction('k').objectStore('k').get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); }
async function idbPut(k, v) { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('k', 'readwrite'); t.objectStore('k').put(v, k); t.oncomplete = () => res(); t.onerror = () => rej(t.error); }); }
async function idbDel(k) { try { const db = await idb(); db.transaction('k', 'readwrite').objectStore('k').delete(k); } catch {} }
async function bioAvailable() {
  try { return !!(window.PublicKeyCredential && navigator.credentials && (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())); } catch { return false; }
}
async function bioStore(pw) {
  let key = await idbGet('key');
  if (!key) { key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); await idbPut('key', key); }
  const iv = rnd(12); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(pw)));
  const all = new Uint8Array(12 + ct.length); all.set(iv); all.set(ct, 12); return b64e(all);
}
async function bioEnable(pw) {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: rnd(32), rp: { name: 'Hari Om' }, user: { id: rnd(16), name: CFG.phone || 'owner', displayName: 'Hari Om' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged' }, timeout: 60000 } });
  if (!cred) throw new Error('cancelled');
  CFG.bio = { id: b64e(new Uint8Array(cred.rawId)), blob: await bioStore(pw) }; saveCfg();
}
async function bioUnlock() {
  await navigator.credentials.get({ publicKey: { challenge: rnd(32), allowCredentials: [{ type: 'public-key', id: b64d(CFG.bio.id), transports: ['internal'] }], userVerification: 'required', timeout: 60000 } });
  const key = await idbGet('key'); const u = b64d(CFG.bio.blob);
  return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12)));
}
function bioClear() { if (CFG.bio) { CFG.bio = null; saveCfg(); } idbDel('key'); }
const persist = () => { clearTimeout(ptimer); ptimer = setTimeout(sealCache, 120); };
function wipeLocal() { bioClear(); try { localStorage.removeItem(CK); } catch {} CFG.salt = null; CFG.fails = 0; saveCfg(); S = null; K = null; PIN = ''; }

// ---------- data ----------
function applyOp(d, o) {
  const up = (arr, x) => { const i = arr.findIndex((a) => a.id === x.id); if (i >= 0) arr[i] = { ...arr[i], ...x }; else arr.push(x); };
  switch (o.t) {
    case 'party': up(d.parties, { id: o.id, name: o.name, phone: o.phone }); break;
    case 'txn': up(d.txns, { id: o.id, party_id: o.party_id, kind: o.kind, amount: o.amount, txn_at: o.txn_at, note: o.note }); break;
    case 'txn_del': d.txns = d.txns.filter((x) => x.id !== o.id); d.reminders = d.reminders.filter((x) => x.txn_id !== o.id); break;
    case 'party_del': d.parties = d.parties.filter((x) => x.id !== o.id); d.txns = d.txns.filter((x) => x.party_id !== o.id); d.reminders = d.reminders.filter((x) => x.party_id !== o.id); break;
    case 'rem': up(d.reminders, { id: o.id, target: o.target || 'party', party_id: o.party_id || null, txn_id: o.txn_id || null, message: o.message, send_at: o.send_at, repeat_type: o.repeat_type, repeat_n: o.repeat_n, status: o.status || 'active', last_sent: o.last_sent || null, last_error: null }); break;
    case 'rem_del': d.reminders = d.reminders.filter((x) => x.id !== o.id); break;
    case 'cash': up(d.cash, { id: o.id, kind: o.kind, amount: o.amount, category: o.category, at: o.at, note: o.note }); break;
    case 'cash_del': d.cash = d.cash.filter((x) => x.id !== o.id); break;
    case 'cat': up(d.cats, { id: o.id, kind: o.kind, name: o.name }); break;
    case 'cat_del': d.cats = d.cats.filter((x) => x.id !== o.id); break;
    case 'budget': if (o.amount > 0) up(d.cats, { id: o.id, kind: 'budget', name: String(o.amount) }); else d.cats = d.cats.filter((x) => x.id !== o.id); break;
  }
}
function op(o) { S.outbox.push(o); applyOp(S.data, o); persist(); renderAll(); scheduleSync(); }

function balances() {
  const m = new Map();
  for (const p of S.data.parties) m.set(p.id, { p, gave: 0, took: 0, last: 0, n: 0 });
  for (const t of S.data.txns) {
    const b = m.get(t.party_id); if (!b) continue;
    if (t.kind === 'gave') b.gave += t.amount; else b.took += t.amount;
    const ts = parseAt(t.txn_at).getTime(); if (ts > b.last) b.last = ts; b.n++;
  }
  for (const b of m.values()) b.net = r2(b.gave - b.took);
  return [...m.values()];
}
function totals() {
  const bs = balances(); let recv = 0, pay = 0;
  for (const b of bs) { if (b.net > 0) recv += b.net; else if (b.net < 0) pay -= b.net; }
  return { recv: r2(recv), pay: r2(pay), bs };
}
const partyById = (id) => S.data.parties.find((p) => p.id === id);
const waLink = (phone, text) => {
  let d = String(phone || '').replace(/\D/g, ''); if (d.length === 10) d = '91' + d;
  return `https://wa.me/${d}${text ? '?text=' + encodeURIComponent(text) : ''}`;
};
function nextSend(ms, type, n) {
  if (type === 'days') return ms + Math.max(1, n || 1) * 864e5;
  const d = new Date(ms); const y = d.getFullYear(); const m = d.getMonth() + 1;
  const dim = new Date(y, m + 1, 0).getDate();
  const day = type === 'monthend' ? dim : Math.min(n || d.getDate(), dim);
  return new Date(y, m, day, d.getHours(), d.getMinutes()).getTime();
}
const repeatLabel = (r) => r.repeat_type === 'days' ? `Every ${r.repeat_n} days` : r.repeat_type === 'monthly' ? 'Every month' : r.repeat_type === 'monthend' ? 'Last day of every month' : 'Once';
const dueCount = () => S ? S.data.reminders.filter((r) => r.status === 'active' && r.send_at <= Date.now()).length : 0;

// ---------- network / sync ----------
async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hariom' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(j.error || 'Something went wrong'); e.status = res.status; throw e; }
  return j;
}
let syncing = false, stimer;
function setStatus(s) { UI.status = s; const d = $('#dot'); if (d) d.className = 'dot ' + s; const t = $('#syncTxt'); if (t) t.textContent = s === 'ok' ? 'Synced' : s === 'sync' ? 'Syncing…' : s === 'off' ? 'Offline' : ''; }
function scheduleSync() { clearTimeout(stimer); stimer = setTimeout(sync, 400); }
async function relogin() {
  if (!PIN || !CFG.phone) return false;
  try { await api('/api/login', { username: CFG.phone, pin: PIN }); return true; } catch { return false; }
}
async function sync(retried) {
  if (!S || syncing) return;
  syncing = true; setStatus('sync');
  const ops = S.outbox.slice();
  let again = false;
  try {
    const r = await api('/api/sync', { ops });
    if (!S) return;
    S.outbox.splice(0, ops.length);
    const d = { parties: r.parties, txns: r.txns, reminders: r.reminders, cash: r.cash || [], cats: r.cats || [] };
    S.outbox.forEach((o) => applyOp(d, o));
    S.data = d; persist(); setStatus('ok'); renderAll();
  } catch (e) {
    if (e.status === 401) {
      if (!retried && await relogin()) again = true;
      else { syncing = false; return forceAuth('Session expired. Please log in again.'); }
    } else setStatus('off');
  } finally {
    syncing = false;
    if (S && !again && S.outbox.length && UI.status === 'ok') scheduleSync();
  }
  if (again) return sync(true);
}

// ---------- history-backed layers (Android back button works) ----------
function openLayer(l) { UI.layers.push(l); history.pushState({ k: 'layer' }, ''); UI.layerAnim = true; renderLayer(); }
function openSheet(s) { UI.sheet = s; history.pushState({ k: 'sheet' }, ''); renderSheet(); }
function closeSheet() { if (UI.sheet) history.back(); }
function closeLayer() { if (UI.layers.length) history.back(); }
window.addEventListener('popstate', () => {
  if (!S) return;
  if (UI.menu) { hideMenu(); return; }
  if (UI.sheet) { UI.sheet = null; renderSheet(); }
  else if (UI.layers.length) { UI.layers.pop(); renderLayer(); }
});

// ---------- small UI helpers ----------
let toastT;
function toast(msg) { const t = $('#toast'); if (!t) return; t.textContent = msg; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 2600); }
function burst() { const b = $('#burst'); if (!b) return; hap([14, 50, 14]); b.classList.remove('on'); void b.offsetWidth; b.classList.add('on'); }
function ask(title, text, ok = 'Delete', cls = 'red') {
  return new Promise((res) => {
    const d = $('#dlg'); d.innerHTML = `<div class="box"><h4>${esc(title)}</h4><p>${esc(text)}</p><div class="acts" style="margin:0"><button class="btn ghost" data-d="0">Cancel</button><button class="btn ${cls}" data-d="1">${esc(ok)}</button></div></div>`;
    d.classList.add('on');
    d.onclick = (e) => { const b = e.target.closest('[data-d]'); if (!b && e.target !== d) return; d.classList.remove('on'); d.onclick = null; res(b ? b.dataset.d === '1' : false); };
  });
}
function seg(name, opts, val, small) {
  const i = Math.max(0, opts.findIndex((o) => o[0] === val));
  return `<div class="seg ${small ? 'sm' : ''}" data-seg="${name}" data-tone="${esc(val)}"><div class="seg-in" style="--n:${opts.length};--i:${i}"><span class="seg-ind"></span>${opts.map(([v, l]) => `<button type="button" class="seg-b ${v === val ? 'on' : ''}" data-a="seg" data-name="${name}" data-v="${v}">${l}</button>`).join('')}</div></div>`;
}
function animateCounts(root) {
  root.querySelectorAll('[data-count]').forEach((el) => {
    const to = parseFloat(el.dataset.count), key = el.dataset.ck, from = UI.counts[key] ?? 0; UI.counts[key] = to;
    if (from === to || reduced()) return;
    const t0 = performance.now(), dur = 700;
    const f = (t) => { const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3); const v = from + (to - from) * e; el.textContent = inr(Number.isInteger(to) && Number.isInteger(from) ? Math.round(v) : v); if (p < 1) requestAnimationFrame(f); else el.textContent = inr(to); };
    requestAnimationFrame(f);
  });
}
function applyTheme() {
  let t = CFG.theme || 'light';
  if (t === 'auto') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
  const m = document.querySelector('meta[name=theme-color]'); if (m) m.content = t === 'dark' ? '#08080a' : '#fafafa';
}

// ---------- auth + lock screens ----------
function pwField(id, ph, ac, name) {
  return `<div class="pw"><input class="inp" ${name ? `name="${name}"` : `id="${id}"`} type="password" placeholder="${ph}" autocomplete="${ac}" autocapitalize="none" spellcheck="false"><button type="button" class="eye" data-a="eye" aria-label="Show or hide password">${ic('eye')}</button></div>`;
}
function authView() {
  if (UI.recovery) return `<div class="auth enter"><div class="om">ॐ</div><h1>Save your recovery key</h1><p class="sub">If you ever forget your password, this key is the only way back in. Write it down or take a screenshot now.</p>
  <div class="card" style="padding:22px"><div class="rkey">${esc(UI.recovery)}</div><div class="acts" style="margin:0"><button class="btn ghost" data-a="copy-key">Copy</button><button class="btn primary" data-a="key-done">I have saved it</button></div></div></div>`;
  const m = UI.mode, forgot = m === 'forgot';
  const tabs = forgot ? '' : `<div class="seg" data-tone="${m}"><div class="seg-in" style="--n:2;--i:${m === 'register' ? 0 : 1}"><span class="seg-ind"></span><button type="button" class="seg-b ${m === 'register' ? 'on' : ''}" data-a="mode" data-v="register">Create account</button><button type="button" class="seg-b ${m === 'login' ? 'on' : ''}" data-a="mode" data-v="login">Log in</button></div></div>`;
  const title = m === 'register' ? 'Create your private account' : forgot ? 'Reset your password' : 'Welcome back';
  return `<div class="auth enter"><div class="om">ॐ</div><h1>Hari Om</h1><p class="sub">${title}</p>
  <div class="card"><div id="authForm">
    ${tabs}
    <label class="f" ${tabs ? '' : 'style="margin-top:0"'}>Username</label>
    <input class="inp" id="a-user" placeholder="e.g. rudra" autocapitalize="none" autocorrect="off" spellcheck="false" autocomplete="username" value="${esc(CFG.phone || '')}">
    ${forgot ? `<label class="f">Recovery key</label><input class="inp" id="a-key" placeholder="XXXX-XXXX-XXXX-XXXX" autocapitalize="characters" autocomplete="off">` : ''}
    <label class="f">${forgot ? 'New password' : 'Password'}</label>
    ${pwField('a-pw', m === 'login' ? 'Your password' : 'At least 8 characters', m === 'login' ? 'current-password' : 'new-password')}
    <div class="err" id="a-err">${esc(UI.err)}</div>
    <button class="btn primary" style="width:100%;margin-top:6px" data-a="auth-go">${m === 'register' ? 'Create account' : forgot ? 'Reset password' : 'Log in'}</button>
  </div></div>
  ${IOS && !STANDALONE ? '<div class="iosnote"><b>On iPhone:</b> tap the Share button, choose <b>Add to Home Screen</b>, then open Hari Om from your home screen. That is needed for Face ID unlock and notifications.</div>' : ''}
  ${m === 'login' ? `<a class="link" data-a="mode" data-v="forgot">Forgot password? <b>Use recovery key</b></a>` : forgot ? `<a class="link" data-a="mode" data-v="login">Back to <b>log in</b></a>` : ''}</div>`;
}
function renderAuth() { UI.shell = false; $('#app').innerHTML = authView(); }
async function loadStatus() {
  try {
    const r = await api('/api/status'); UI.hasUser = r.hasUser; UI.ready = r.ready;
    if (!UI.touched && UI.mode === 'login' && !r.hasUser) UI.mode = 'register';
    if (r.hasUser === false && !UI.touched) UI.mode = 'register';
    if (!UI.recovery && !S) renderAuth();
  } catch {}
}
async function authGo() {
  const user = ($('#a-user').value || '').trim().toLowerCase(), pin = $('#a-pw').value, m = UI.mode;
  const fail = (t) => { UI.err = t; $('#a-err').textContent = t; };
  if (!/^[a-z0-9._]{3,30}$/.test(user)) return fail('Username: 3 to 30 letters, numbers, dots or underscores');
  if (pin.length < 8) return fail('Password must be at least 8 characters');
  const btn = $('[data-a=auth-go]'); btn.disabled = true; fail('');
  try {
    const body = { username: user, pin };
    if (m === 'forgot') body.recoveryKey = $('#a-key').value;
    const r = await api(m === 'register' ? '/api/register' : m === 'forgot' ? '/api/reset' : '/api/login', body);
    await afterAuth(r.username || user, pin, r.recoveryKey);
  } catch (e) {
    btn.disabled = false;
    fail(e.status ? e.message : 'No internet. Connect once to log in.');
  }
}
async function afterAuth(phone, pin, recoveryKey) {
  CFG.phone = phone; CFG.salt = b64e(crypto.getRandomValues(new Uint8Array(16))); CFG.fails = 0; saveCfg();
  K = await deriveKey(pin, CFG.salt); PIN = pin; S = emptyS(); await sealCache(); UI.err = ''; UI.askBio = true;
  if (recoveryKey) { UI.recovery = recoveryKey; renderAuth(); } else enterApp();
}
function forceAuth(msg) {
  wipeLocal(); UI.layers = []; UI.sheet = null; UI.mode = 'login'; UI.err = msg || ''; renderAuth(); loadStatus();
}
async function logout() {
  try { await api('/api/logout', {}); } catch {}
  forceAuth('');
}

function lockView(msg) {
  const bio = CFG.bio ? `<button class="btn primary" style="width:100%" data-a="bio-unlock">${ic('lock')}&nbsp; Unlock with ${BIO_NAME}</button><div class="or">or use your password</div>` : '';
  return `<div class="lock enter"><div class="om">ॐ</div><h1>Hari Om</h1><p id="lock-sub">${esc(msg || (CFG.bio ? 'Welcome back' : 'Enter your password'))}</p>
  <div class="card" style="width:100%;max-width:340px">${bio}${pwField('l-pw', 'Password', 'current-password')}<button class="btn ${CFG.bio ? 'ghost' : 'primary'}" style="width:100%;margin-top:12px" data-a="unlock">Unlock</button></div>
  <a class="link" data-a="relogin">Forgot password? <b>Log in again</b></a></div>`;
}
function renderLock(msg) { UI.shell = false; $('#app').innerHTML = lockView(msg); setTimeout(() => { if (CFG.bio && !msg && !IOS) bioTry(); else { const i = $('#l-pw'); if (i) i.focus(); } }, 120); }
async function bioTry() { if (!CFG.bio || UI.unlocking || !$('.lock')) return; try { const pw = await bioUnlock(); await doUnlock(pw); } catch (e) { console.debug('quick unlock:', e && e.name, e && e.message); const i = $('#l-pw'); if (i) i.focus(); } }
async function doUnlock(override) {
  const inp = $('#l-pw'); if (!inp || UI.unlocking) return;
  const pin = typeof override === 'string' ? override : inp.value; if (!pin) return;
  UI.unlocking = true;
  try {
    const key = await deriveKey(pin, CFG.salt);
    try {
      S = await openCache(key); K = key; PIN = pin; CFG.fails = 0; saveCfg(); UI.unlocking = false; enterApp(); return;
    } catch {
      if (typeof override === 'string') { bioClear(); UI.unlocking = false; renderLock('Quick unlock was reset. Enter your password.'); return; }
      CFG.fails = (CFG.fails || 0) + 1; saveCfg();
      if (CFG.fails >= 5) { UI.unlocking = false; forceAuth('Too many wrong passwords. Log in again to continue.'); return; }
    }
  } catch {}
  UI.unlocking = false; hap([40, 40, 40]);
  inp.value = ''; inp.classList.remove('shake'); void inp.offsetWidth; inp.classList.add('shake');
  const sub = $('#lock-sub'); if (sub) sub.textContent = `Wrong password. ${5 - CFG.fails} tries left.`;
}
async function lockNow() {
  await sealCache(); S = null; K = null; PIN = ''; UI.layers = []; UI.sheet = null; renderLock();
}
async function offerBio() {
  if (!S || CFG.bio || CFG.bioAsked || UI.sheet || UI.menu) return;
  if (!(await bioAvailable())) return;
  CFG.bioAsked = true; saveCfg();
  if (!(await ask('Unlock with ' + BIO_NAME + '?', 'Next time you open Hari Om you can use ' + (IOS ? 'Face ID or Touch ID' : 'your fingerprint, face or phone lock') + ' instead of typing the password. You can change this any time in the You tab.', 'Turn on', 'primary'))) return;
  try { await bioEnable(PIN); toast('Quick unlock is on'); burst(); if (UI.tab === 'me') renderView(false); } catch { bioClear(); toast('Could not turn it on. You can try again in the You tab.'); }
}
function enterApp() {
  if (S) { S.data.cash = S.data.cash || []; S.data.cats = S.data.cats || []; }
  UI.tab = UI.startTab || (CFG.tab && CFG.tab !== 'me' ? CFG.tab : 'home'); UI.startTab = null; UI.shell = false;
  renderAll(); sync();
  if (UI.askBio) { UI.askBio = false; setTimeout(offerBio, 1200); }
  if (UI.startAdd) { const k = UI.startAdd; UI.startAdd = null; setTimeout(() => { if (S && !UI.sheet) openSheet(k === 'in' || k === 'out' ? newCash(k) : newSlip(k, null)); }, 350); }
  try { if (location.search) history.replaceState(null, '', location.pathname); } catch {}
}

// ---------- notifications ----------
const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
const u8FromB64u = (s) => b64d(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
async function loadMe() { try { UI.me = await api('/api/me', {}); if (UI.tab === 'me') renderView(); } catch {} }
async function enablePush() {
  if (!pushSupported()) return toast('This browser does not support notifications');
  const perm = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
  if (perm !== 'granted') return toast('Notifications are blocked. Allow them in the browser settings.');
  try {
    const me = await api('/api/me', {});
    if (!me.vapid) return toast('Push keys are not set on the server yet (README step 2)');
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: u8FromB64u(me.vapid) });
    await api('/api/push/subscribe', { endpoint: sub.endpoint });
    toast('Notifications are on'); loadMe();
  } catch (e) { toast('Could not turn on notifications'); }
}
function offerPush() {
  if (!pushSupported() || Notification.permission === 'denied') return;
  if (Notification.permission === 'default' || !(UI.me && UI.me.subs > 0)) enablePush();
}

// ---------- views ----------
function homeView() {
  const { recv, pay, bs } = totals(); const tot = recv + pay; const gp = tot ? Math.round((recv / tot) * 100) : 0;
  const net = r2(recv - pay);
  const latest = [...S.data.txns].sort((a, b) => b.txn_at.localeCompare(a.txn_at)).slice(0, 8);
  const top = (f) => bs.filter(f).sort((a, b) => Math.abs(b.net) - Math.abs(a.net))[0];
  const tr = top((b) => b.net > 0), tp = top((b) => b.net < 0);
  const nextRem = S.data.reminders.filter((r) => r.status === 'active').sort((a, b) => a.send_at - b.send_at)[0];
  const due = dueCount(); const h = new Date().getHours();
  return `
  <div class="top"><div class="brand"><div class="om">ॐ</div><div><h1>Hari Om</h1><small id="syncTxt">${UI.status === 'ok' ? 'Synced' : ''}</small></div></div><span id="dot" class="dot ${UI.status}"></span></div>
  <div class="greet">${h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening'}. Here is where things stand.</div>
  <section class="card hero">
    <div class="hero-row">
      <div class="stat g"><span>You'll receive</span><b data-count="${recv}" data-ck="home-r">${inr(recv)}</b></div>
      <div class="stat r"><span>You'll pay</span><b data-count="${pay}" data-ck="home-p">${inr(pay)}</b></div>
    </div>
    <div class="bar">${tot ? `<i class="bg" style="width:${gp}%"></i><i class="br" style="width:${100 - gp}%"></i>` : ''}</div>
    <div class="net"><span>Net position</span><b class="${net >= 0 ? 'g' : 'r'}">${net >= 0 ? '+' : '−'}${inr(net)}</b></div>
  </section>
  <div class="secrow"><h2 class="sec">${(CFG.period || 'monthly') === 'yearly' ? 'This year' : (CFG.period || 'monthly') === 'lifetime' ? 'All time' : 'This month'}</h2><button class="lnk" data-a="tab" data-v="more">Income &amp; expenses ${ic('next')}</button></div>
  ${flowCard(CFG.period || 'monthly', periodKey(CFG.period || 'monthly') === 'all' ? 'all' : (CFG.period === 'yearly' ? yearNow() : monthNow()), 'h')}
  <h2 class="sec">Summary</h2>
  <div class="tiles">
    ${due ? `<button class="tile wide" data-a="tab" data-v="rem" style="text-align:left"><small>Needs your attention</small><b>${due} reminder${due === 1 ? '' : 's'} due now</b><em>Tap to open</em></button>` : ''}
    <div class="tile"><small>Parties</small><b>${S.data.parties.length}</b><em>${bs.filter((b) => b.net !== 0).length} with balance</em></div>
    <div class="tile"><small>Transactions</small><b>${S.data.txns.length}</b><em>recorded</em></div>
    <div class="tile"><small>Biggest to receive</small><b class="g">${tr ? esc(tr.p.name) : '—'}</b><em>${tr ? inr(tr.net) : 'Nobody owes you'}</em></div>
    <div class="tile"><small>Biggest to pay</small><b class="r">${tp ? esc(tp.p.name) : '—'}</b><em>${tp ? inr(tp.net) : 'You owe nobody'}</em></div>
    ${nextRem ? `<div class="tile wide"><small>Next reminder</small><b>${nextRem.target === 'self' ? 'Notify you' : esc(partyById(nextRem.party_id)?.name || '')}</b><em>${fDate(new Date(nextRem.send_at))}, ${fTime(new Date(nextRem.send_at))}</em></div>` : ''}
  </div>
  <h2 class="sec">Latest transactions</h2>
  ${latest.length ? `<div class="list">${latest.map(txnRow).join('')}</div>` : `<div class="empty"><div class="om">ॐ</div>No transactions yet.<br>Tap the + button to add your first one.</div>`}`;
}
function txnRow(t) {
  const p = partyById(t.party_id); const d = parseAt(t.txn_at); const g = t.kind === 'gave';
  return `<button class="row" data-a="txn" data-id="${t.id}"><span class="ic ${g ? 'g' : 'r'}">${ic(g ? 'recv' : 'pay')}</span><span class="pm"><b>${esc(p?.name || 'Unknown')}</b><small>${fDate(d)} · ${fTime(d)}${t.note ? ' · ' + esc(t.note) : ''}</small></span><span class="amt ${g ? 'g' : 'r'}">${g ? '+' : '−'}${inr(t.amount)}</span></button>`;
}
function listView(kind) {
  const { recv, pay, bs } = totals(); const isR = kind === 'recv';
  const rows = bs.filter((b) => (isR ? b.net > 0 : b.net < 0)).sort((a, b) => Math.abs(b.net) - Math.abs(a.net));
  const settled = bs.filter((b) => b.net === 0 && b.n > 0);
  const row = (b, i) => `<button class="row" data-a="party" data-id="${b.p.id}"><span class="no">${i == null ? '' : i + 1}</span><span class="av">${esc(initial(b.p.name))}</span><span class="pm"><b>${esc(b.p.name)}</b><small>Last: ${b.last ? fDate(new Date(b.last)) : '—'} · ${b.n} transaction${b.n === 1 ? '' : 's'}</small></span><span class="amt ${b.net > 0 ? 'g' : b.net < 0 ? 'r' : 'mu'}">${b.net === 0 ? 'Settled' : inr(b.net)}</span></button>`;
  return `
  <div class="top"><div class="brand"><div class="om">ॐ</div><div><h1>${isR ? 'Money to receive' : 'Money to pay'}</h1><small>${rows.length} part${rows.length === 1 ? 'y' : 'ies'}</small></div></div></div>
  <section class="card big-total ${isR ? 'g' : 'r'}"><small>${isR ? 'Total receivable' : 'Total payable'}</small><b data-count="${isR ? recv : pay}" data-ck="${kind}-t">${inr(isR ? recv : pay)}</b></section>
  <h2 class="sec">${isR ? 'Who owes you' : 'Whom you owe'}</h2>
  ${rows.length ? `<div class="list">${rows.map(row).join('')}</div>` : `<div class="empty">${isR ? 'Nobody owes you money right now.' : 'You do not owe anyone right now.'}</div>`}
  ${settled.length ? `<h2 class="sec">Settled</h2><div class="list">${settled.map((b) => row(b, null)).join('')}</div>` : ''}`;
}
function remView() {
  return `<div class="top"><div class="brand"><div class="om">ॐ</div><div><h1>Reminders</h1><small>Your alerts and WhatsApp messages</small></div></div></div>
  ${seg('rt', [['up', 'Upcoming'], ['done', 'Sent']], UI.remTab, true)}
  <div class="list" id="rlist" style="margin-top:18px">${remList()}</div>`;
}
function remList() {
  const now = Date.now(); const R = S.data.reminders;
  const items = UI.remTab === 'up' ? R.filter((r) => r.status !== 'sent').sort((a, b) => a.send_at - b.send_at) : R.filter((r) => r.last_sent).sort((a, b) => b.last_sent - a.last_sent);
  if (!items.length) return `<div class="empty">${UI.remTab === 'up' ? 'No upcoming reminders.<br>Save a transaction and set one.' : 'Nothing sent yet.'}</div>`;
  return items.map((r) => {
    const self = r.target === 'self'; const p = self ? null : partyById(r.party_id); const d = new Date(r.send_at); const isDone = UI.remTab === 'done';
    const badge = isDone ? `<span class="ok">${self ? 'Notified' : 'Sent'} ${fDate(new Date(r.last_sent))}</span>` : r.status === 'failed' ? '<span class="fail">Failed</span>' : r.send_at <= now ? '<span class="due">Due now</span>' : '';
    const who = self ? `<span class="who">${ic('bell')}Notify me</span>` : `<span class="who">${ic('wa')}${esc(p?.name || 'Unknown')}</span>`;
    return `<div class="rem"><div class="rt"><div class="pm"><b>${who}</b><small>${isDone && r.repeat_type === 'once' ? '' : 'Next: ' + fDate(d) + ', ' + fTime(d) + ' · '}${repeatLabel(r)}</small></div>${badge}</div>
    <p>${esc(r.message)}</p>${r.last_error ? `<small class="r">${esc(r.last_error)}</small>` : ''}
    <div class="ra">${isDone || self ? '' : `<button class="pill wa" data-a="rem-send" data-id="${r.id}">${ic('wa')}Send now</button>`}${r.status === 'failed' ? `<button class="pill" data-a="rem-retry" data-id="${r.id}">Retry</button>` : ''}<button class="pill dg" data-a="rem-del" data-id="${r.id}">${ic('trash')}Delete</button></div></div>`;
  }).join('');
}
function meView() {
  const pend = S.outbox.length; const me = UI.me;
  const perm = pushSupported() ? Notification.permission : 'unsupported';
  const pushOn = perm === 'granted' && me && me.subs > 0;
  let ntext = 'Get alerts on this phone for your reminders, even when the app is closed.', nbtn = `<button class="btn primary" data-a="push-on">Turn on notifications</button>`;
  if (perm === 'unsupported') { ntext = IOS ? (STANDALONE ? 'Notifications need iOS 16.4 or newer. Please update your iPhone.' : 'On iPhone, first tap Share > Add to Home Screen, then open Hari Om from your home screen and come back here.') : 'This browser does not support notifications. Open Hari Om in Chrome.'; nbtn = ''; }
  else if (perm === 'denied') { ntext = 'Notifications are blocked. Allow them for this site in your browser settings, then come back.'; nbtn = ''; }
  else if (me && !me.vapid) { ntext = 'Push keys are not set on the server yet. Finish step 2 of the README.'; nbtn = ''; }
  else if (pushOn) { ntext = 'Notifications are on for this phone.'; nbtn = `<div class="acts" style="margin:0"><button class="btn ghost" data-a="push-test">Send a test</button><button class="btn ghost danger" data-a="push-off">Turn off</button></div>`; }
  return `<div class="top"><div class="brand"><div class="om">ॐ</div><div><h1>You</h1><small>@${esc(CFG.phone || '')}</small></div></div><span id="dot" class="dot ${UI.status}"></span></div>
  <div class="me-row">
    <div class="setcol"><b>Notifications</b><div class="mu" style="font-size:13px;line-height:1.55">${esc(ntext)}</div>${nbtn}</div>
    <div class="setcol"><b>Appearance</b>${seg('theme', [['light', 'Light'], ['dark', 'Dark'], ['auto', 'Auto']], CFG.theme || 'light', true)}</div>
    <div class="setcol"><b>Lock the app after</b>${seg('lockmin', [['1', '1 min'], ['5', '5 min'], ['15', '15 min']], String(CFG.lockMin || 5), true)}<div class="mu" style="font-size:12.5px">When you leave the app for this long it asks for your password again.</div></div>
    <div class="setrow"><div class="pm"><b>Quick unlock</b><small>${IOS ? 'Face ID or Touch ID instead of typing' : 'Fingerprint, face or phone lock instead of typing'}</small></div><button class="sw ${CFG.bio ? 'on' : ''}" data-a="bio-toggle" aria-label="Toggle quick unlock"></button></div>
    ${deferredInstall && !STANDALONE ? `<button class="btn primary" data-a="install">Install Hari Om on this phone</button>` : ''}
    ${navigator.vibrate ? `<div class="setrow"><div class="pm"><b>Vibration feedback</b><small>A tiny buzz when you tap</small></div><button class="sw ${CFG.haptics === false ? '' : 'on'}" data-a="toggle-hap" aria-label="Toggle vibration"></button></div>` : ''}
    <div class="tile"><small>Sync status</small><b id="syncTxt">${UI.status === 'ok' ? 'Synced' : UI.status === 'off' ? 'Offline' : 'Idle'}</b><em>${pend ? pend + ' change(s) waiting to upload' : 'Everything is saved on the server'}</em></div>
    <div class="note"><b>WhatsApp</b><br>${me && me.wa ? 'Connected. Messages to your parties are sent automatically at the time you pick.' : 'Not connected yet. When a message is due you get a notification, and <b>Send now</b> in Reminders opens WhatsApp with it ready.'}</div>
    <button class="btn ghost" data-a="lock-now">${ic('lock')}&nbsp; Lock now</button>
    <button class="btn ghost" data-a="sync">Sync now</button>
    <button class="btn ghost" data-a="change-pin">Change password</button>
    <button class="btn ghost" data-a="export">Download backup</button>
    <button class="btn ghost danger" data-a="logout">Log out</button>
  </div>`;
}
function partyList(id) {
  const f = UI.pfilter;
  const ts = S.data.txns.filter((t) => t.party_id === id && (f === 'all' || t.kind === f)).sort((a, b) => b.txn_at.localeCompare(a.txn_at));
  if (!ts.length) return '<div class="empty">No transactions here.</div>';
  let out = '', cur = '';
  for (const t of ts) { const m = fMonth(parseAt(t.txn_at)); if (m !== cur) { cur = m; out += `<div class="month">${m}</div>`; } out += `<div class="list" style="margin-bottom:10px">${txnRowNoName(t)}</div>`; }
  return out;
}
function txnRowNoName(t) {
  const d = parseAt(t.txn_at); const g = t.kind === 'gave';
  return `<button class="row" data-a="txn" data-id="${t.id}"><span class="ic ${g ? 'g' : 'r'}">${ic(g ? 'recv' : 'pay')}</span><span class="pm"><b>${fDate(d)}</b><small>${fTime(d)} · ${g ? 'You gave' : 'You took'}${t.note ? ' · ' + esc(t.note) : ''}</small></span><span class="amt ${g ? 'g' : 'r'}">${g ? '+' : '−'}${inr(t.amount)}</span></button>`;
}
function partyView(id) {
  const b = balances().find((x) => x.p.id === id); if (!b) return '';
  const p = b.p; const cls = b.net > 0 ? 'g' : b.net < 0 ? 'r' : 'mu';
  return `<div class="layer-in"><div class="bar-top"><button class="ibtn" data-a="back" aria-label="Back">${ic('back')}</button><b style="font-size:17px">Party</b></div>
  <section class="card pcard"><div class="phead"><div class="av big">${esc(initial(p.name))}</div><div style="min-width:0"><h2>${esc(p.name)}</h2><small>${p.phone ? '+91 ' + esc(p.phone) : 'No mobile number saved'}</small></div></div>
    <div class="pbal"><div><small class="mu">${b.net > 0 ? "You'll receive" : b.net < 0 ? "You'll pay" : 'All settled'}</small><br><b class="${cls}">${b.net === 0 ? '₹0' : inr(b.net)}</b></div><small class="mu">${b.n} transaction${b.n === 1 ? '' : 's'}</small></div>
    <div class="pacts"><button class="pill" data-a="remind-party" data-id="${p.id}">${ic('bell')}Remind</button>${p.phone ? `<button class="pill wa" data-a="wa-open" data-id="${p.id}">${ic('wa')}Chat</button>` : `<button class="pill" data-a="edit-party" data-id="${p.id}">${ic('edit')}Add number</button>`}<button class="pill dg" data-a="del-party" data-id="${p.id}" aria-label="Delete party">${ic('trash')}</button></div></section>
  ${seg('pf', [['all', 'All'], ['gave', 'You gave'], ['took', 'You took']], UI.pfilter, true)}
  <div id="plist" style="margin-top:6px">${partyList(id)}</div></div>
  <div class="foot"><div class="foot-in"><button class="btn green" data-a="add" data-kind="gave" data-party="${p.id}">You Gave</button><button class="btn red" data-a="add" data-kind="took" data-party="${p.id}">You Took</button></div></div>`;
}

// ---------- shell + render ----------
const NAV = [['home', 'Home'], ['recv', 'Receive'], ['pay', 'Pay'], ['dots', 'More'], ['bell', 'Remind'], ['user', 'You']];
function buildShell() {
  $('#app').innerHTML = `<main id="view"></main>
  <button class="fab" id="fab" data-a="add" aria-label="Add transaction">${ic('plus')}</button>
  <nav class="nav-container" id="nav" style="--n:6;--i:0"><span class="nav-ind"></span>
   ${NAV.map(([ico, label], i) => `<a class="nav-item" data-a="tab" data-v="${TABS[i]}">${ico === 'bell' ? '<span class="badge" id="rbadge" style="display:none"></span>' : ''}${ic(ico)}${label}</a>`).join('')}
  </nav>
  <div id="menu"></div><div id="layer" class="layer" style="display:none"></div><div id="sheet"></div><div id="dlg"></div><div id="toast"></div>
  <div id="burst"><div class="c"><svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></div></div>`;
  UI.shell = true;
}
function renderView(anim) {
  const v = $('#view'); if (!v || !S) return;
  const t = UI.tab;
  FLOW_ANIM = !!anim; if (anim) for (const k of Object.keys(UI.counts)) if (k.startsWith('flow-')) delete UI.counts[k];
  v.innerHTML = t === 'home' ? homeView() : t === 'recv' ? listView('recv') : t === 'pay' ? listView('pay') : t === 'more' ? moreView() : t === 'rem' ? remView() : meView();
  v.classList.toggle('noanim', !anim);
  v.querySelectorAll('.list').forEach((l) => [...l.children].forEach((c, i) => c.style.setProperty('--k', Math.min(i, 9))));
  if (anim) { v.classList.remove('enter'); void v.offsetWidth; v.classList.add('enter'); }
  animateCounts(v);
}
function renderNav() {
  const nav = $('#nav'); if (!nav || !S) return;
  const i = TABS.indexOf(UI.tab); nav.style.setProperty('--i', i);
  nav.querySelectorAll('.nav-item').forEach((el, k) => el.classList.toggle('active', k === i));
  const due = dueCount(); const b = $('#rbadge'); if (b) { b.style.display = due ? 'flex' : 'none'; b.textContent = due > 9 ? '9+' : due; }
  const fab = $('#fab'); if (fab) fab.style.display = UI.layers.length || UI.tab === 'me' ? 'none' : 'grid';
}
function renderLayer() {
  const el = $('#layer'); if (!el || !S) return;
  const top = UI.layers[UI.layers.length - 1];
  if (!top) { el.style.display = 'none'; el.innerHTML = ''; renderNav(); return; }
  const keep = el.scrollTop; const html = partyView(top.id);
  if (!html) { UI.layers = []; el.style.display = 'none'; renderNav(); return; }
  el.style.display = 'block'; el.innerHTML = html;
  if (UI.layerAnim) { el.classList.remove('in'); void el.offsetWidth; el.classList.add('in'); UI.layerAnim = false; el.scrollTop = 0; } else el.scrollTop = keep;
  renderNav();
}
function renderAll() {
  if (!S) return;
  if (!UI.shell || !$('#view')) { buildShell(); renderView(true); } else renderView(false);
  renderLayer(); renderNav();
}

// ---------- income and expenses ----------
let FLOW_ANIM = true;
const DEF = {
  in: ['Salary', 'Business', 'Freelance', 'Interest', 'Gift', 'Refund', 'Other'],
  out: ['Food', 'Groceries', 'Travel', 'Fuel', 'Bills', 'Rent', 'Shopping', 'Health', 'Education', 'Entertainment', 'Other'],
};
const monthNow = () => ymd(new Date()).slice(0, 7);
const monthLabel = (k) => { const [y, m] = k.split('-').map(Number); return new Date(y, m - 1, 1).toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }); };
const shiftMonth = (k, n) => { const [y, m] = k.split('-').map(Number); const d = new Date(y, m - 1 + n, 1); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}`; };
const inrC = (n) => (n >= 1e7 ? '₹' + +(n / 1e7).toFixed(1) + 'Cr' : n >= 1e5 ? '₹' + +(n / 1e5).toFixed(1) + 'L' : n >= 1e3 ? '₹' + +(n / 1e3).toFixed(1) + 'k' : '₹' + Math.round(n));
const yearNow = () => String(new Date().getFullYear());
const periodKey = (p) => (p === 'yearly' ? UI.cy || yearNow() : p === 'lifetime' ? 'all' : UI.cm || monthNow());
const periodLabel = (p, k) => (p === 'yearly' ? k : p === 'lifetime' ? 'Lifetime' : monthLabel(k));
const isCurrentPeriod = (p, k) => p === 'lifetime' || (p === 'yearly' ? k === yearNow() : k === monthNow());
const inPeriod = (at, p, k) => (p === 'lifetime' ? true : p === 'yearly' ? at.slice(0, 4) === k : at.slice(0, 7) === k);
function cashTotals(p, k) {
  let income = 0, spent = 0;
  for (const c of S.data.cash) if (inPeriod(c.at, p, k)) { if (c.kind === 'in') income += c.amount; else spent += c.amount; }
  return { income: r2(income), spent: r2(spent) };
}
const budgetFor = (p) => { const c = S.data.cats.find((x) => x.id === 'budget-' + p); const v = c ? parseFloat(c.name) : 0; return v > 0 ? v : 0; };
function flowCard(period, key, tag) {
  const t = cashTotals(period, key); const left = r2(t.income - t.spent);
  const W = 320, H = 196, pl = 40, pr = 10, pt = 12, base = 170; const max = Math.max(t.income, t.spent, Math.abs(left), 1);
  const bw = 66, gap = (W - pl - pr - 3 * bw) / 2;
  const bars = [['g', t.income], ['r', t.spent], ['p', Math.abs(left)]];
  const grid = [0, 1, 2, 3].map((k) => { const y = +(base - (k * (base - pt)) / 3).toFixed(1); return `<line class="gl ${k === 0 ? 'axis' : ''}" x1="${pl - 6}" x2="${W - pr}" y1="${y}" y2="${y}"/><text class="ax" x="${pl - 10}" y="${y + 3.5}" text-anchor="end">${k === 0 ? '0' : inrC((max * k) / 3)}</text>`; }).join('');
  const rects = bars.map(([c, v], i) => {
    const x = +(pl + i * (bw + gap)).toFixed(1);
    if (!(v > 0)) return `<rect class="bar stub ${c}" x="${x}" y="${base - 2}" width="${bw}" height="2" rx="1"/>`;
    const h = Math.max(5, (v / max) * (base - pt)); const r = Math.min(bw * 0.46, h); const y = +(base - h).toFixed(1);
    return `<path class="bar ${c}" style="--d:${i * 0.16}s" d="M${x} ${base}V${+(y + r).toFixed(1)}A${r} ${r} 0 0 1 ${+(x + r).toFixed(1)} ${y}H${+(x + bw - r).toFixed(1)}A${r} ${r} 0 0 1 ${+(x + bw).toFixed(1)} ${+(y + r).toFixed(1)}V${base}Z"/>`;
  }).join('');
  const hasAny = t.income > 0 || t.spent > 0;
  const bud = budgetFor(period); const bpct = bud ? Math.min(100, Math.round((t.spent / bud) * 100)) : 0;
  const live = isCurrentPeriod(period, key) && period !== 'lifetime';
  const val = (id, v, cls, label, neg) => `<div><b class="${cls}">${neg ? '−' : ''}<span data-count="${Math.abs(v)}" data-ck="flow-${id}${tag}">${inr(v)}</span></b><small>${label}</small></div>`;
  return `<section class="card flow ${FLOW_ANIM ? 'draw' : ''}">
    <div class="fhead"><span class="live ${live ? 'on' : ''}"><i></i>${live ? 'Live' : period === 'lifetime' ? 'All time' : 'Summary'}</span><small>${periodLabel(period, key)}</small></div>
    <svg class="fsvg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Income, expenses and money left">
      ${grid}${rects}
    </svg>
    <div class="fvals">${val('i', t.income, '', 'Income')}${val('s', t.spent, '', 'Expenses')}${val('l', left, left < 0 ? 'r' : '', 'Left', left < 0)}</div>
    ${hasAny ? '' : '<div class="fempty">Tap + and add an income or expense. The bars will rise live.</div>'}
    ${bud ? `<div class="bud"><div class="budh"><span>Budget ${inr(bud)}</span><b class="${t.spent > bud ? 'r' : ''}">${t.spent > bud ? 'Over by ' + inr(t.spent - bud) : inr(bud - t.spent) + ' left'}</b></div><div class="ubar ${bpct >= 90 ? 'hot' : ''}"><i style="width:${bpct}%"></i></div></div>` : ''}
  </section>`;
}
function moreView() {
  const period = CFG.period || 'monthly'; const key = periodKey(period); const cur = isCurrentPeriod(period, key); const bud = budgetFor(period);
  const nav = period === 'lifetime' ? '' : `<button class="ibtn" data-a="pn" data-v="-1" aria-label="Previous">${ic('back')}</button><b>${periodLabel(period, key)}</b><button class="ibtn" data-a="pn" data-v="1" aria-label="Next" ${cur ? 'disabled' : ''}>${ic('next')}</button>`;
  return `<div class="top"><div class="brand"><div class="om">ॐ</div><div><h1>Income &amp; expenses</h1><small>Your own money</small></div></div></div>
  ${seg('period', [['monthly', 'Monthly'], ['yearly', 'Yearly'], ['lifetime', 'Lifetime']], period, true)}
  <div class="mnav">${nav || '<b>All your entries</b>'}</div>
  ${flowCard(period, key, 'm')}
  <button class="btn ghost bset" data-a="budget">${bud ? 'Change ' + period + ' budget · ' + inr(bud) : 'Set a ' + period + ' budget'}</button>
  <div style="margin-top:20px">${seg('ck', [['in', 'Income'], ['out', 'Expense']], UI.ck || 'out', true)}</div>
  <div id="cashlist">${cashList(period, key)}</div>`;
}
function cashRow(c) {
  const d = parseAt(c.at); const g = c.kind === 'in';
  return `<button class="row" data-a="cash" data-id="${c.id}"><span class="ic ${g ? 'g' : 'r'}">${ic(g ? 'inc' : 'exp')}</span><span class="pm"><b>${fDate(d)}</b><small>${fTime(d)}${c.note ? ' · ' + esc(c.note) : ''}</small></span><span class="amt ${g ? 'g' : 'r'}">${g ? '+' : '−'}${inr(c.amount)}</span></button>`;
}
function cashList(period, key) {
  const kind = UI.ck || 'out'; const isIn = kind === 'in';
  const rows = S.data.cash.filter((c) => c.kind === kind && inPeriod(c.at, period, key)).sort((a, b) => b.at.localeCompare(a.at));
  const total = r2(rows.reduce((a, c) => a + c.amount, 0));
  const by = new Map(); for (const c of rows) { if (!by.has(c.category)) by.set(c.category, []); by.get(c.category).push(c); }
  const mine = S.data.cats.filter((c) => c.kind === kind).map((c) => c.name);
  for (const n of mine) if (!by.has(n)) by.set(n, []);
  const sum = (a) => a.reduce((x, c) => x + c.amount, 0);
  const secs = [...by.entries()].sort((a, b) => sum(b[1]) - sum(a[1]) || a[0].localeCompare(b[0]));
  const sec = ([name, list], i) => {
    const v = r2(sum(list)); const pct = total ? Math.round((v / total) * 100) : 0; const own = mine.includes(name) && !DEF[kind].includes(name);
    return `<section class="card csec" style="--k:${Math.min(i, 9)}"><div class="csh"><div><b>${esc(name)}${own ? ' <i class="own">Yours</i>' : ''}</b><small>${list.length} ${list.length === 1 ? 'entry' : 'entries'}${total && v ? ' · ' + pct + '%' : ''}</small></div><b class="amt ${isIn ? 'g' : 'r'}">${inr(v)}</b></div>
      <div class="cbar ${isIn ? 'g' : 'r'}"><i style="width:${v ? Math.max(3, pct) : 0}%"></i></div>
      ${list.length ? `<div class="clist">${list.map(cashRow).join('')}</div>` : '<div class="cnone">Nothing here yet</div>'}</section>`;
  };
  return `<section class="card big-total ${isIn ? 'g' : 'r'}" style="margin-top:16px"><small>${isIn ? 'Total income' : 'Total spent'} · ${periodLabel(period, key)}</small><b data-count="${total}" data-ck="flow-t">${inr(total)}</b></section>
  <h2 class="sec">${isIn ? 'Income by source' : 'Expenses by category'}</h2>
  ${secs.some(([, l]) => l.length) || mine.length ? `<div class="csecs">${secs.map(sec).join('')}</div>` : `<div class="empty"><div class="om">ॐ</div>${isIn ? 'No income recorded yet.' : 'No expenses recorded yet.'}<br>Tap the + button to add one.</div>`}`;
}

// plus-button menu: opens like a page unfolding out of the button
function menuHTML() {
  const T = (k, ico, cls, t, sub, i) => `<button class="mt" style="--k:${i}" data-a="pick-kind" data-v="${k}"><span class="mi ${cls}">${ic(ico)}</span><b>${t}</b><small>${sub}</small></button>`;
  return `<div class="mscrim" data-a="menu-close"></div><div class="mcard">
    <div class="mcap">Between people</div>
    <div class="mrow">${T('gave', 'recv', 'g', 'You Gave', 'Money you will receive', 0)}${T('took', 'pay', 'r', 'You Took', 'Money you will pay', 1)}</div>
    <div class="mcap">Your own money</div>
    <div class="mrow">${T('in', 'inc', 'g', 'Income', 'Salary, business, gifts', 2)}${T('out', 'exp', 'r', 'Expense', 'Food, travel, bills', 3)}</div>
  </div>`;
}
function showMenu() {
  if (UI.menu || UI.sheet) return;
  UI.menu = true; history.pushState({ k: 'menu' }, '');
  const m = $('#menu'); m.className = 'on'; m.innerHTML = menuHTML();
  const f = $('#fab'); if (f) f.classList.add('open'); hap([6, 30, 10]);
}
function hideMenu() {
  UI.menu = false;
  const m = $('#menu'); const f = $('#fab'); if (f) f.classList.remove('open');
  if (!m || !m.classList.contains('on')) return;
  m.classList.add('out'); setTimeout(() => { if (!UI.menu) { m.className = ''; m.innerHTML = ''; } }, 300);
}
function newCash(kind) {
  const n = nowParts(); const last = (CFG.lastCat || {})[kind];
  return { step: 'cash', f: { id: null, kind, amount: '', cat: last || DEF[kind][0], date: n.date, time: n.time, note: '' } };
}
function catChips(f) {
  const customs = S.data.cats.filter((c) => c.kind === f.kind && !DEF[f.kind].some((d) => d.toLowerCase() === c.name.toLowerCase()));
  const chip = (n, id) => `<button type="button" class="chip ${n === f.cat ? 'on' : ''}" data-a="cat" data-v="${esc(n)}">${esc(n)}${id ? `<span class="cx" data-a="cat-del" data-id="${id}" aria-label="Remove category">×</span>` : ''}</button>`;
  const known = DEF[f.kind].concat(customs.map((c) => c.name));
  const extra = f.cat && !known.some((n) => n === f.cat) ? chip(f.cat) : '';
  return DEF[f.kind].map((n) => chip(n)).join('') + customs.map((c) => chip(c.name, c.id)).join('') + extra + `<button type="button" class="chip add" data-a="cat-new">+ New</button>`;
}
function cashHTML(s) {
  const f = s.f; const isIn = f.kind === 'in';
  return `<div class="sh-head"><h3><span id="ch-title">${f.id ? 'Edit ' : ''}${isIn ? 'Income' : 'Expense'}</span><small id="ch-sub">${isIn ? 'Money that came to you' : 'Money you spent'}</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  ${seg('ckind', [['in', 'Income'], ['out', 'Expense']], f.kind)}
  <label class="f">Amount (₹)</label><input class="inp" name="amount" inputmode="decimal" placeholder="0" autocomplete="off" value="${esc(f.amount)}">
  <label class="f" id="cat-label">${isIn ? 'Where did it come from?' : 'What was it for?'}</label>
  <div class="chips" id="catbox">${catChips(f)}</div>
  <div class="newcat" id="newcat" style="display:none"><input class="inp" id="f-newcat" maxlength="30" placeholder="Name your own category" autocomplete="off"><button class="btn primary" data-a="cat-add">Add</button></div>
  <div class="two"><div><label class="f">Date</label><input class="inp" type="date" name="date" value="${f.date}"></div><div><label class="f">Time</label><input class="inp" type="time" name="time" value="${f.time}"></div></div>
  <div class="acts"><button class="btn ghost" data-a="cash-save">Save</button><button class="btn primary" data-a="cash-next">Next</button></div>`;
}
function cashNoteHTML(s) {
  const f = s.f; const isIn = f.kind === 'in';
  return `<div class="sh-head"><h3>Description<small>${isIn ? 'Income' : 'Expense'} · ${esc(f.cat)} · ${inr(parseFloat(String(f.amount).replace(/,/g, '')) || 0)}</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  <label class="f" style="margin-top:0">${isIn ? 'Add a note about this income' : 'What was this expense for?'}</label>
  <textarea class="inp" name="note" id="f-cnote" placeholder="Optional. You can leave it empty." style="min-height:130px">${esc(f.note)}</textarea>
  <div class="acts"><button class="btn ghost" data-a="cash-back">Back</button><button class="btn primary" data-a="cash-save">Save</button></div>`;
}
function cashDetailHTML(s) {
  const c = S.data.cash.find((x) => x.id === s.id); if (!c) return '<div class="empty">Entry not found</div>';
  const d = parseAt(c.at); const g = c.kind === 'in';
  return `<div class="sh-head"><h3>${g ? 'Income' : 'Expense'} details</h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  <div class="big-amt"><span class="tag ${g ? 'g' : 'r'}">${g ? 'Income' : 'Expense'}</span><b class="${g ? 'g' : 'r'}">${g ? '+' : '−'}${inr(c.amount)}</b></div>
  <div class="kv"><span>${g ? 'Source' : 'Category'}</span><span>${esc(c.category)}</span></div>
  <div class="kv"><span>Date</span><span>${fDate(d)}</span></div>
  <div class="kv"><span>Time</span><span>${fTime(d)}</span></div>
  <div class="kv"><span>Description</span><span>${c.note ? esc(c.note) : '—'}</span></div>
  <div class="acts"><button class="btn ghost danger" data-a="cash-delete" data-id="${c.id}">Delete</button><button class="btn primary" data-a="cash-edit" data-id="${c.id}">Edit</button></div>`;
}
function budgetHTML(s) {
  const f = s.f; const nm = { monthly: 'monthly', yearly: 'yearly', lifetime: 'lifetime' }[f.period];
  return `<div class="sh-head"><h3>Set ${nm} budget<small>The most you plan to spend. Leave empty to remove it.</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  <label class="f" style="margin-top:0">Budget amount (₹)</label><input class="inp" name="amount" inputmode="decimal" placeholder="e.g. 20000" autocomplete="off" value="${esc(f.amount)}">
  <div class="acts"><button class="btn ghost" data-a="close">Cancel</button><button class="btn primary" data-a="budget-save">Save</button></div>`;
}
function cashValid(f) {
  const amount = parseFloat(String(f.amount).replace(/,/g, ''));
  if (!(amount > 0)) { toast('Enter a valid amount'); return null; }
  if (!f.cat) { toast('Pick a category'); return null; }
  if (!f.date || !f.time) { toast('Pick date and time'); return null; }
  return r2(amount);
}
function cashSave() {
  const f = UI.sheet.f; const amount = cashValid(f); if (amount == null) return;
  op({ t: 'cash', id: f.id || uid(), kind: f.kind, amount, category: f.cat, at: `${f.date}T${f.time}`, note: (f.note || '').trim() });
  CFG.lastCat = { ...(CFG.lastCat || {}), [f.kind]: f.cat }; saveCfg();
  burst(); closeSheet(); toast(f.id ? 'Updated' : f.kind === 'in' ? 'Income saved' : 'Expense saved');
}

// ---------- sheets ----------
function renderSheet() {
  const el = $('#sheet'); if (!el) return;
  const s = UI.sheet;
  if (!s) {
    const p = $('#sheet .panel');
    if (p) { p.classList.add('out'); const sc = $('#sheet .scrim'); if (sc) sc.classList.add('out'); setTimeout(() => { if (!UI.sheet) el.innerHTML = ''; }, 270); } else el.innerHTML = '';
    return;
  }
  const body = s.step === 'slip' ? slipHTML(s) : s.step === 'msg' ? msgHTML(s) : s.step === 'sched' ? schedHTML(s) : s.step === 'pin' ? pinHTML(s) : s.step === 'cash' ? cashHTML(s) : s.step === 'cashnote' ? cashNoteHTML(s) : s.step === 'cashdetail' ? cashDetailHTML(s) : s.step === 'budget' ? budgetHTML(s) : detailHTML(s);
  const panel = $('#sheet .panel');
  if (panel && !panel.classList.contains('out')) {
    panel.innerHTML = `<div class="grab"></div><div class="swap">${body}</div>`; panel.scrollTop = 0;
  } else {
    el.innerHTML = `<div class="scrim" data-a="close"></div><div class="panel"><div class="grab"></div><div class="swap">${body}</div></div>`;
  }
  if (s.step === 'slip') matchParty();
  const step = s.step;
  setTimeout(() => {
    if (!UI.sheet || UI.sheet.step !== step) return;
    const t = step === 'slip' ? (s.f.name ? $('[name=amount]') : $('#f-name')) : step === 'msg' ? $('#f-msg') : step === 'pin' ? $('[name=cur]') : step === 'cash' ? (s.f.id ? null : $('[name=amount]')) : step === 'cashnote' ? $('#f-cnote') : step === 'budget' ? $('[name=amount]') : null;
    if (t) t.focus({ preventScroll: true });
  }, 430);
}
function newSlip(kind, partyId) {
  const p = partyId ? partyById(partyId) : null; const n = nowParts();
  const k = kind || (UI.tab === 'pay' ? 'took' : UI.tab === 'recv' ? 'gave' : CFG.lastKind || 'gave');
  return { step: 'slip', f: { id: null, kind: k, name: p?.name || '', phone: p?.phone || '', amount: '', date: n.date, time: n.time, note: '', partyId: p?.id || null } };
}
function slipHTML(s) {
  const f = s.f;
  return `<div class="sh-head"><h3>${f.id ? 'Edit' : 'Transaction'} Slip<small>${f.id ? 'Update the details' : 'Record money given or taken'}</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  ${seg('kind', [['gave', 'You Gave'], ['took', 'You Took']], f.kind)}
  <label class="f">Party name</label><input class="inp" name="name" id="f-name" autocomplete="off" placeholder="Type a name" value="${esc(f.name)}">
  <div class="sug" id="sug"></div><div class="hint" id="pmatch"></div>
  <label class="f">Mobile number (for WhatsApp)</label><input class="inp" name="phone" id="f-phone" inputmode="numeric" maxlength="10" placeholder="10 digit number" value="${esc(f.phone)}">
  <label class="f">Amount (₹)</label><input class="inp" name="amount" inputmode="decimal" placeholder="0" value="${esc(f.amount)}">
  <div class="two"><div><label class="f">Date</label><input class="inp" type="date" name="date" value="${f.date}"></div><div><label class="f">Time</label><input class="inp" type="time" name="time" value="${f.time}"></div></div>
  <label class="f">Description</label><textarea class="inp" name="note" style="min-height:90px" placeholder="What was this for?">${esc(f.note)}</textarea>
  <div class="acts"><button class="btn ghost danger" data-a="slip-delete">${f.id ? 'Delete' : 'Cancel'}</button><button class="btn primary" data-a="slip-save">Save</button></div>`;
}
function matchParty() {
  const s = UI.sheet; if (!s || s.step !== 'slip') return;
  const f = s.f; const q = f.name.trim().toLowerCase();
  const exact = q && S.data.parties.find((p) => p.name.trim().toLowerCase() === q);
  let sug;
  if (q) sug = S.data.parties.filter((p) => p.name.toLowerCase().includes(q) && p !== exact).slice(0, 4);
  else { const last = new Map(balances().map((b) => [b.p.id, b.last])); sug = [...S.data.parties].sort((a, b) => (last.get(b.id) || 0) - (last.get(a.id) || 0)).slice(0, 4); }
  f.partyId = exact ? exact.id : null;
  const phoneEl = $('#f-phone');
  if (exact && !f.phone && exact.phone) { f.phone = exact.phone; if (phoneEl) phoneEl.value = exact.phone; }
  const sg = $('#sug'); if (sg) sg.innerHTML = sug.map((p) => `<button type="button" data-a="pick" data-id="${p.id}">${esc(p.name)}</button>`).join('');
  const h = $('#pmatch'); if (h) h.textContent = !q ? '' : exact ? 'Existing party. This will be added to their account.' : 'New party. It will be created when you save.';
}
function msgHTML(s) {
  const f = s.f; const p = partyById(f.partyId); const self = f.target === 'self';
  return `<div class="step"><i class="on"></i><i class="on"></i><i></i></div>
  <div class="sh-head"><h3>${self ? 'Remind me' : 'Message'}<small id="msg-sub">${self ? 'A notification will reach you on this phone' : 'To ' + esc(p?.name || '') + (p?.phone ? ' · +91 ' + esc(p.phone) : '')}</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  ${seg('target', [['party', 'To ' + esc(short(p?.name || 'party', 12))], ['self', 'To me']], f.target, true)}
  <label class="f" id="msg-label">${self ? 'What should the notification say?' : 'Type the message to send'}</label>
  <textarea class="inp" name="message" id="f-msg" placeholder="${self ? 'e.g. Pay back the money today' : 'Write your message…'}">${esc(f.message)}</textarea>
  <div id="phone-wrap" style="display:${!self && !p?.phone ? 'block' : 'none'}"><label class="f">This party has no mobile number. Add it so WhatsApp can reach them</label><input class="inp" name="phone" inputmode="numeric" maxlength="10" placeholder="10 digit number" value="${esc(f.phone || '')}"></div>
  <div class="acts"><button class="btn ghost" data-a="msg-skip">Skip</button><button class="btn primary" data-a="msg-next">Next</button></div>`;
}
function schedHTML(s) {
  const f = s.f; const self = f.target === 'self';
  const R = [['once', 'Once'], ['d15', 'Every 15 days'], ['d30', 'Every 30 days'], ['monthly', 'Every month'], ['monthend', 'Last day of month'], ['custom', 'Custom days']];
  return `<div class="step"><i class="on"></i><i class="on"></i><i class="on"></i></div>
  <div class="sh-head"><h3>${self ? 'Notify me on' : 'Send on'}<small>Pick the exact date, time and repeat</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  <div class="two"><div><label class="f" style="margin-top:0">Date</label><input class="inp" type="date" name="sdate" id="f-sdate" value="${f.sdate}"></div><div><label class="f" style="margin-top:0">Time</label><input class="inp" type="time" name="stime" value="${f.stime}"></div></div>
  <label class="f">Repeat</label><div class="chips" id="rchips">${R.map(([v, l]) => `<button type="button" class="chip ${f.repeat === v ? 'on' : ''}" data-a="rpt" data-v="${v}">${l}</button>`).join('')}</div>
  <div id="custom" style="display:${f.repeat === 'custom' ? 'block' : 'none'}"><label class="f">Repeat every (days)</label><input class="inp" name="custom" inputmode="numeric" placeholder="e.g. 7" value="${esc(f.custom)}"></div>
  <div class="acts"><button class="btn ghost" data-a="sched-back">Back</button><button class="btn primary" data-a="sched-save">${self ? 'Set reminder' : 'Schedule'}</button></div>`;
}
function pinHTML(s) {
  return `<div class="sh-head"><h3>Change password<small>Your other logins will be signed out</small></h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  <label class="f" style="margin-top:0">Current password</label>${pwField('', 'Current password', 'current-password', 'cur')}
  <label class="f">New password</label>${pwField('', 'At least 8 characters', 'new-password', 'nw')}
  <div class="err" id="pin-err"></div>
  <div class="acts"><button class="btn ghost" data-a="close">Cancel</button><button class="btn primary" data-a="pin-save">Change password</button></div>`;
}
function detailHTML(s) {
  const t = S.data.txns.find((x) => x.id === s.id); if (!t) return '<div class="empty">Transaction not found</div>';
  const p = partyById(t.party_id); const d = parseAt(t.txn_at); const g = t.kind === 'gave';
  const rems = S.data.reminders.filter((r) => r.txn_id === t.id);
  return `<div class="sh-head"><h3>Transaction details</h3><button class="ibtn" data-a="close" aria-label="Close">${ic('x')}</button></div>
  <div class="big-amt"><span class="tag ${g ? 'g' : 'r'}">${g ? 'You gave' : 'You took'}</span><b class="${g ? 'g' : 'r'}">${g ? '+' : '−'}${inr(t.amount)}</b></div>
  <div class="kv"><span>Party</span><span>${esc(p?.name || '')}</span></div>
  <div class="kv"><span>Mobile</span><span>${p?.phone ? '+91 ' + esc(p.phone) : '—'}</span></div>
  <div class="kv"><span>Date</span><span>${fDate(d)}</span></div>
  <div class="kv"><span>Time</span><span>${fTime(d)}</span></div>
  <div class="kv"><span>Type</span><span>${g ? 'Money lent. You will receive it back' : 'Money borrowed. You have to pay it back'}</span></div>
  <div class="kv"><span>Description</span><span>${t.note ? esc(t.note) : '—'}</span></div>
  ${rems.length ? `<div class="kv"><span>Reminders</span><span>${rems.map((r) => `${r.target === 'self' ? 'You' : 'WhatsApp'}: ${fDate(new Date(r.send_at))}, ${fTime(new Date(r.send_at))} (${repeatLabel(r)})`).join('<br>')}</span></div>` : ''}
  <div class="acts"><button class="btn ghost danger" data-a="txn-delete" data-id="${t.id}">Delete</button><button class="btn ghost" data-a="txn-edit" data-id="${t.id}">Edit</button><button class="btn primary" data-a="txn-remind" data-id="${t.id}">Remind</button></div>`;
}

// ---------- actions ----------
function composerFor(partyId, txnId, target) {
  const d = new Date(Date.now() + 864e5);
  return { step: 'msg', f: { partyId, txnId: txnId || null, target, message: '', phone: '', sdate: ymd(d), stime: CFG.lastTime || '10:00', repeat: 'once', custom: '' } };
}
function saveSlip() {
  const s = UI.sheet; const f = s.f;
  const name = f.name.trim(); const amount = parseFloat(String(f.amount).replace(/,/g, ''));
  const phone = String(f.phone || '').replace(/\D/g, '');
  if (!name) return toast('Enter the party name');
  if (!(amount > 0)) return toast('Enter a valid amount');
  if (!f.date || !f.time) return toast('Pick date and time');
  if (phone && !/^\d{10}$/.test(phone)) return toast('Mobile number must be 10 digits');
  let p = f.partyId ? partyById(f.partyId) : S.data.parties.find((x) => x.name.trim().toLowerCase() === name.toLowerCase());
  const pid = p ? p.id : uid();
  if (!p || (phone && phone !== p.phone) || name !== p.name) op({ t: 'party', id: pid, name, phone: phone || p?.phone || '' });
  const id = f.id || uid();
  op({ t: 'txn', id, party_id: pid, kind: f.kind, amount: r2(amount), txn_at: `${f.date}T${f.time}`, note: f.note.trim() });
  CFG.lastKind = f.kind; saveCfg();
  burst();
  if (f.id) { closeSheet(); toast('Transaction updated'); return; }
  UI.sheet = composerFor(pid, id, f.kind === 'took' ? 'self' : 'party');
  renderSheet();
}
function scheduleSave() {
  const f = UI.sheet.f;
  if (!f.sdate || !f.stime) return toast('Pick date and time');
  const at = new Date(`${f.sdate}T${f.stime}`).getTime();
  if (!(at > Date.now() + 20000)) return toast('Pick a time in the future');
  let rt = 'once', rn = 0;
  if (f.repeat === 'd15') { rt = 'days'; rn = 15; }
  else if (f.repeat === 'd30') { rt = 'days'; rn = 30; }
  else if (f.repeat === 'custom') { rn = parseInt(f.custom, 10); if (!(rn >= 1 && rn <= 3650)) return toast('Enter the number of days'); rt = 'days'; }
  else if (f.repeat === 'monthly') { rt = 'monthly'; rn = new Date(at).getDate(); }
  else if (f.repeat === 'monthend') { rt = 'monthend'; }
  const self = f.target === 'self';
  op({ t: 'rem', id: uid(), target: f.target, party_id: self ? null : f.partyId, txn_id: f.txnId || null, message: f.message.trim(), send_at: at, repeat_type: rt, repeat_n: rn, status: 'active', last_sent: null });
  CFG.lastTime = f.stime; saveCfg();
  burst(); closeSheet();
  toast(self ? 'Reminder set. You will be notified.' : 'Message scheduled');
  if (self) offerPush();
}

document.addEventListener('click', (e) => { if (e.target.closest('[data-a],.nav-item,.fab')) hap(8); }, true);
document.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-a]'); if (!el) return;
  const a = el.dataset.a; const id = el.dataset.id; const s = UI.sheet;
  switch (a) {
    case 'unlock': doUnlock(); break;
    case 'bio-unlock': bioTry(); break;
    case 'install': if (deferredInstall) { deferredInstall.prompt(); deferredInstall = null; renderView(false); } break;
    case 'bio-toggle': {
      if (CFG.bio) { bioClear(); toast('Quick unlock is off'); renderView(false); break; }
      if (!(await bioAvailable())) { toast(IOS ? 'Face ID or Touch ID is not available. Open Hari Om from your Home Screen icon and make sure a passcode is set.' : 'No fingerprint, face or screen lock is available on this phone or browser'); break; }
      try { await bioEnable(PIN); toast('Quick unlock is on'); burst(); } catch { bioClear(); toast('Could not turn it on'); }
      renderView(false); break;
    }
    case 'eye': { const i = el.parentElement.querySelector('input'); i.type = i.type === 'password' ? 'text' : 'password'; el.classList.toggle('on', i.type === 'text'); break; }
    case 'relogin': forceAuth(''); break;
    case 'tab': if (UI.tab !== el.dataset.v) { UI.tab = el.dataset.v; if (UI.tab !== 'me') { CFG.tab = UI.tab; saveCfg(); } renderView(true); renderNav(); window.scrollTo(0, 0); if (UI.tab === 'me') loadMe(); } break;
    case 'party': openLayer({ id }); break;
    case 'back': closeLayer(); break;
    case 'close': closeSheet(); break;
    case 'add': if (el.dataset.kind || el.dataset.party) openSheet(newSlip(el.dataset.kind || null, el.dataset.party || null)); else if (UI.menu) history.back(); else showMenu(); break;
    case 'menu-close': history.back(); break;
    case 'pick-kind': {
      const k = el.dataset.v; try { history.replaceState({ k: 'sheet' }, ''); } catch {}
      hideMenu(); UI.sheet = k === 'in' || k === 'out' ? newCash(k) : newSlip(k, null); renderSheet(); break;
    }
    case 'pn': { const per = CFG.period || 'monthly'; const n = parseInt(el.dataset.v, 10); if (per === 'yearly') { const ny = String(parseInt(UI.cy || yearNow(), 10) + n); if (ny > yearNow()) break; UI.cy = ny; } else { const nk = shiftMonth(UI.cm || monthNow(), n); if (nk > monthNow()) break; UI.cm = nk; } renderView(true); break; }
    case 'budget': { const per = CFG.period || 'monthly'; openSheet({ step: 'budget', f: { period: per, amount: budgetFor(per) ? String(budgetFor(per)) : '' } }); break; }
    case 'budget-save': { const f = s.f; const v = parseFloat(String(f.amount).replace(/,/g, '')); if (f.amount && !(v > 0)) return toast('Enter a valid amount'); op({ t: 'budget', id: 'budget-' + f.period, period: f.period, amount: v > 0 ? r2(v) : 0 }); closeSheet(); toast(v > 0 ? 'Budget saved' : 'Budget removed'); break; }
    case 'cash': openSheet({ step: 'cashdetail', id }); break;
    case 'cash-edit': { const c = S.data.cash.find((x) => x.id === id); const d = parseAt(c.at); UI.sheet = { step: 'cash', f: { id: c.id, kind: c.kind, amount: String(c.amount), cat: c.category, date: ymd(d), time: hm(d), note: c.note || '' } }; renderSheet(); break; }
    case 'cash-delete': if (await ask('Delete this entry?', 'It will be removed permanently.')) { closeSheet(); op({ t: 'cash_del', id }); toast('Deleted'); } break;
    case 'cash-next': { if (cashValid(s.f) == null) break; s.step = 'cashnote'; renderSheet(); break; }
    case 'cash-back': s.step = 'cash'; renderSheet(); break;
    case 'cash-save': cashSave(); break;
    case 'cat': { s.f.cat = el.dataset.v; $('#catbox').innerHTML = catChips(s.f); break; }
    case 'cat-new': { const nc = $('#newcat'); nc.style.display = 'flex'; const i = $('#f-newcat'); i.value = ''; i.focus(); break; }
    case 'cat-add': {
      const i = $('#f-newcat'); const name = (i.value || '').trim().replace(/\s+/g, ' ').slice(0, 30);
      if (!name) return toast('Type a category name');
      const hit = DEF[s.f.kind].concat(S.data.cats.filter((c) => c.kind === s.f.kind).map((c) => c.name)).find((n) => n.toLowerCase() === name.toLowerCase());
      if (!hit) op({ t: 'cat', id: uid(), kind: s.f.kind, name });
      s.f.cat = hit || name; $('#newcat').style.display = 'none'; $('#catbox').innerHTML = catChips(s.f); break;
    }
    case 'cat-del': { const c = S.data.cats.find((x) => x.id === id); if (!c) break; op({ t: 'cat_del', id }); if (s.f.cat === c.name) s.f.cat = DEF[s.f.kind][0]; $('#catbox').innerHTML = catChips(s.f); toast('Category removed'); break; }
    case 'txn': openSheet({ step: 'detail', id }); break;
    case 'txn-edit': { const t = S.data.txns.find((x) => x.id === id); const p = partyById(t.party_id); const d = parseAt(t.txn_at); UI.sheet = { step: 'slip', f: { id: t.id, kind: t.kind, name: p.name, phone: p.phone || '', amount: String(t.amount), date: ymd(d), time: hm(d), note: t.note || '', partyId: p.id } }; renderSheet(); break; }
    case 'txn-delete': if (await ask('Delete transaction?', 'This will remove it and its reminders permanently.')) { closeSheet(); op({ t: 'txn_del', id }); toast('Deleted'); } break;
    case 'txn-remind': { const t = S.data.txns.find((x) => x.id === id); UI.sheet = composerFor(t.party_id, t.id, t.kind === 'took' ? 'self' : 'party'); renderSheet(); break; }
    case 'remind-party': { const b = balances().find((x) => x.p.id === id); openSheet(composerFor(id, null, b && b.net < 0 ? 'self' : 'party')); break; }
    case 'wa-open': window.open(waLink(partyById(id).phone), '_blank', 'noopener'); break;
    case 'edit-party': { const p = partyById(id); const n = nowParts(); openSheet({ step: 'slip', f: { id: null, kind: 'gave', name: p.name, phone: p.phone || '', amount: '', date: n.date, time: n.time, note: '', partyId: p.id } }); break; }
    case 'del-party': if (await ask('Delete this party?', 'All their transactions and reminders will be deleted permanently.')) { const n = UI.layers.length; UI.layers = []; op({ t: 'party_del', id }); if (n) history.go(-n); toast('Deleted'); } break;
    case 'seg': {
      const name = el.dataset.name, v = el.dataset.v; const box = el.closest('.seg'); const inner = $('.seg-in', box);
      const btns = [...inner.querySelectorAll('.seg-b')]; inner.style.setProperty('--i', btns.indexOf(el)); box.dataset.tone = v;
      btns.forEach((b) => b.classList.toggle('on', b === el));
      if (name === 'kind' && s) s.f.kind = v;
      if (name === 'ckind' && s) {
        s.f.kind = v; s.f.cat = (CFG.lastCat || {})[v] || DEF[v][0]; const isIn = v === 'in';
        $('#catbox').innerHTML = catChips(s.f); $('#ch-title').textContent = (s.f.id ? 'Edit ' : '') + (isIn ? 'Income' : 'Expense');
        $('#ch-sub').textContent = isIn ? 'Money that came to you' : 'Money you spent'; $('#cat-label').textContent = isIn ? 'Where did it come from?' : 'What was it for?'; $('#newcat').style.display = 'none';
      }
      if (name === 'period') { CFG.period = v; saveCfg(); renderView(true); }
      if (name === 'ck') { UI.ck = v; const cl = $('#cashlist'); if (cl) { cl.innerHTML = cashList(CFG.period || 'monthly', periodKey(CFG.period || 'monthly')); cl.querySelectorAll('.list').forEach((l) => [...l.children].forEach((c, i) => c.style.setProperty('--k', Math.min(i, 9)))); delete UI.counts['flow-t']; animateCounts(cl); } }
      if (name === 'target' && s) {
        s.f.target = v; const self = v === 'self'; const p = partyById(s.f.partyId);
        $('#msg-label').textContent = self ? 'What should the notification say?' : 'Type the message to send';
        $('#f-msg').placeholder = self ? 'e.g. Pay back the money today' : 'Write your message…';
        $('#msg-sub').textContent = self ? 'A notification will reach you on this phone' : 'To ' + (p?.name || '') + (p?.phone ? ' · +91 ' + p.phone : '');
        $('#phone-wrap').style.display = !self && !p?.phone ? 'block' : 'none';
      }
      if (name === 'pf') { UI.pfilter = v; const pl = $('#plist'); const top = UI.layers[UI.layers.length - 1]; if (pl && top) pl.innerHTML = partyList(top.id); }
      if (name === 'rt') { UI.remTab = v; const rl = $('#rlist'); rl.innerHTML = remList(); [...rl.children].forEach((c, i) => c.style.setProperty('--k', Math.min(i, 9))); }
      if (name === 'theme') { CFG.theme = v; saveCfg(); applyTheme(); }
      if (name === 'lockmin') { CFG.lockMin = parseInt(v, 10); saveCfg(); }
      break;
    }
    case 'pick': { const p = partyById(id); s.f.name = p.name; s.f.phone = p.phone || ''; $('#f-name').value = p.name; $('#f-phone').value = p.phone || ''; matchParty(); const am = $('[name=amount]'); if (am) am.focus(); break; }
    case 'slip-save': saveSlip(); break;
    case 'slip-delete': if (s.f.id) { if (await ask('Delete transaction?', 'This will remove it permanently.')) { const tid = s.f.id; closeSheet(); op({ t: 'txn_del', id: tid }); toast('Deleted'); } } else closeSheet(); break;
    case 'msg-skip': closeSheet(); break;
    case 'msg-next': {
      if (!s.f.message.trim()) return toast(s.f.target === 'self' ? 'Write what the notification should say' : 'Type your message first');
      if (s.f.target === 'party') {
        const p = partyById(s.f.partyId); const ph = String(s.f.phone || '').replace(/\D/g, '');
        if (!p.phone) { if (!/^\d{10}$/.test(ph)) return toast('Add a 10 digit mobile number'); op({ t: 'party', id: p.id, name: p.name, phone: ph }); }
      }
      UI.sheet.step = 'sched'; renderSheet(); break;
    }
    case 'sched-back': s.step = 'msg'; renderSheet(); break;
    case 'rpt': {
      s.f.repeat = el.dataset.v; $('#rchips').querySelectorAll('.chip').forEach((c) => c.classList.toggle('on', c === el));
      $('#custom').style.display = s.f.repeat === 'custom' ? 'block' : 'none';
      if (s.f.repeat === 'monthend') { const [y, m] = s.f.sdate.split('-').map(Number); s.f.sdate = `${y}-${pad(m)}-${pad(new Date(y, m, 0).getDate())}`; $('#f-sdate').value = s.f.sdate; }
      break;
    }
    case 'sched-save': scheduleSave(); break;
    case 'rem-send': {
      const r = S.data.reminders.find((x) => x.id === id); const p = partyById(r.party_id);
      if (!p?.phone) return toast('No mobile number saved for this party');
      window.open(waLink(p.phone, r.message), '_blank', 'noopener');
      const now = Date.now(); const o = { t: 'rem', ...r, last_sent: now };
      if (r.repeat_type === 'once') o.status = 'sent'; else { let nx = nextSend(r.send_at, r.repeat_type, r.repeat_n); for (let i = 0; nx <= now && i < 1000; i++) nx = nextSend(nx, r.repeat_type, r.repeat_n); o.send_at = nx; o.status = 'active'; }
      op(o); break;
    }
    case 'rem-retry': { const r = S.data.reminders.find((x) => x.id === id); op({ t: 'rem', ...r, status: 'active', send_at: Date.now() + 60000 }); toast('Will retry in a minute'); break; }
    case 'rem-del': if (await ask('Delete reminder?', 'It will not be sent.')) { op({ t: 'rem_del', id }); toast('Reminder deleted'); } break;
    case 'push-on': await enablePush(); break;
    case 'push-test': try { const r = await api('/api/push/test', {}); toast(r.sent ? 'Test sent. Check your notifications.' : 'No device is registered yet'); } catch (err) { toast(err.message); } break;
    case 'push-off': try { await api('/api/push/unsubscribe', {}); const reg = await navigator.serviceWorker.ready; const sub = await reg.pushManager.getSubscription(); if (sub) await sub.unsubscribe(); toast('Notifications are off'); loadMe(); } catch { toast('Could not turn off'); } break;
    case 'toggle-hap': CFG.haptics = CFG.haptics === false ? true : false; saveCfg(); el.classList.toggle('on', CFG.haptics !== false); if (CFG.haptics !== false) hap(20); break;
    case 'lock-now': lockNow(); break;
    case 'change-pin': openSheet({ step: 'pin', f: { cur: '', nw: '' } }); break;
    case 'pin-save': {
      const f = s.f; const er = $('#pin-err');
      if (f.nw.length < 8) { er.textContent = 'New password must be at least 8 characters'; break; }
      if (f.cur !== PIN) { er.textContent = 'Current password is wrong'; break; }
      if (f.nw === f.cur) { er.textContent = 'Choose a different password'; break; }
      try {
        await api('/api/change-password', { pin: f.cur, newPin: f.nw });
        CFG.salt = b64e(crypto.getRandomValues(new Uint8Array(16))); saveCfg(); K = await deriveKey(f.nw, CFG.salt); PIN = f.nw; await sealCache();
        if (CFG.bio) { try { CFG.bio.blob = await bioStore(f.nw); saveCfg(); } catch { bioClear(); } }
        closeSheet(); toast('Password changed'); burst();
      } catch (err) { er.textContent = err.message; }
      break;
    }
    case 'sync': scheduleSync(); toast('Syncing…'); break;
    case 'export': {
      const b = new Blob([JSON.stringify(S.data, null, 2)], { type: 'application/json' }); const u = URL.createObjectURL(b);
      const l = document.createElement('a'); l.href = u; l.download = `hariom-backup-${nowParts().date}.json`; l.click(); setTimeout(() => URL.revokeObjectURL(u), 3000);
      toast('Backup saved. It is not encrypted, so keep it private.'); break;
    }
    case 'logout': if (await ask('Log out?', S.outbox.length ? 'Some changes have not been uploaded yet and will be lost.' : 'You will need your username and password to get back in.', 'Log out')) logout(); break;
    case 'mode': UI.mode = el.dataset.v; UI.touched = true; UI.err = ''; renderAuth(); break;
    case 'auth-go': authGo(); break;
    case 'copy-key': try { await navigator.clipboard.writeText(UI.recovery); toast('Copied'); } catch { toast('Select and copy it manually'); } break;
    case 'key-done': UI.recovery = null; enterApp(); break;
  }
});

document.addEventListener('input', (e) => {
  const t = e.target; const s = UI.sheet;
  if (!s || !t.name || !s.f) return;
  const map = { sdate: 'sdate', stime: 'stime' };
  s.f[map[t.name] || t.name] = t.name === 'phone' ? t.value.replace(/\D/g, '') : t.value;
  if (t.name === 'phone') t.value = s.f.phone;
  if (t.name === 'name' && s.step === 'slip') matchParty();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && e.target.closest('#authForm')) authGo();
  if (e.key === 'Enter' && e.target.id === 'l-pw') doUnlock();
  if (e.key === 'Enter' && e.target.id === 'f-newcat') { e.preventDefault(); const b = $('[data-a=cat-add]'); if (b) b.click(); }
});

let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { hiddenAt = Date.now(); if (S) sealCache(); return; }
  if (S && hiddenAt && Date.now() - hiddenAt > (CFG.lockMin || 5) * 60000) lockNow();
  else if (S) { sync(); renderNav(); }
  hiddenAt = 0;
});
window.addEventListener('online', () => sync());
setInterval(() => { if (S) { sync(); renderNav(); } }, 60000);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

// ---------- boot ----------
(function boot() {
  applyTheme();
  const q = new URLSearchParams(location.search).get('tab'); if (TABS.includes(q)) UI.startTab = q;
  const qa = new URLSearchParams(location.search).get('add'); if (['gave', 'took', 'in', 'out'].includes(qa)) UI.startAdd = qa;
  if (CFG.salt && CFG.phone && localStorage.getItem(CK)) { renderLock(); return; }
  renderAuth(); loadStatus();
})();
})();
