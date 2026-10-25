// Hari Om backend v2
// - login with username + password (hashed with a server-side secret, escalating lockout)
// - HttpOnly cookie session, CSRF + origin checks, strict security headers
// - all personal data encrypted at rest with AES-256-GCM (key is a Cloudflare secret if you set one, otherwise generated once and stored beside the data)
// - sends WhatsApp reminders and push notifications to your phone from a cron trigger

import { SCHEMA } from './schema.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const SESSION_DAYS = 30;
const PBKDF2_ITER = 50000; // the server-side pepper is what protects the password, see README
const MAX_FAILS = 5;
const LOCK_MIN = [15, 60, 360, 1440];
const IST = 330 * 60000;
const MAX_BODY = 1_000_000;
const COOKIE = 'hs';

const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
  "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'; worker-src 'self'";

function sec(h) {
  h.set('Content-Security-Policy', CSP);
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'no-referrer');
  h.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  h.set('Cross-Origin-Resource-Policy', 'same-origin');
  return h;
}

function json(data, status = 200, cookies = []) {
  const h = sec(new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }));
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response(JSON.stringify(data), { status, headers: h });
}

// ---------- encoding helpers ----------
function b64(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64u = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha256Hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const newSalt = () => b64(crypto.getRandomValues(new Uint8Array(16)));

function same(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---------- keys (derived from the DATA_KEY secret) ----------
let keyCache = null;
async function keys(env) {
  if (!env.DATA_KEY) throw new Error('NO_KEY');
  if (keyCache && keyCache.src === env.DATA_KEY) return keyCache;
  const raw = unb64(env.DATA_KEY);
  if (raw.length !== 32) throw new Error('NO_KEY');
  const master = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  const sub = (info) =>
    crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) }, master, 256);
  const hmac = async (info) =>
    crypto.subtle.importKey('raw', await sub(info), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  keyCache = {
    src: env.DATA_KEY,
    aes: await crypto.subtle.importKey('raw', await sub('hariom-aes'), 'AES-GCM', false, ['encrypt', 'decrypt']),
    mac: await hmac('hariom-mac'),
    pepper: await hmac('hariom-pin-pepper'),
  };
  return keyCache;
}

// Encrypts an object. The row identity is bound in as "additional data", so a ciphertext cannot be moved to another row.
async function encField(env, obj, aad) {
  const k = await keys(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad) },
    k.aes,
    enc.encode(JSON.stringify(obj))
  );
  return 'v1.' + b64(iv) + '.' + b64(ct);
}
async function decField(env, s, aad) {
  const k = await keys(env);
  const [v, iv, ct] = String(s).split('.');
  if (v !== 'v1' || !iv || !ct) throw new Error('BAD_CIPHER');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv), additionalData: enc.encode(aad) }, k.aes, unb64(ct));
  return JSON.parse(dec.decode(pt));
}
async function phoneHash(env, phone) {
  const k = await keys(env);
  return hex(await crypto.subtle.sign('HMAC', k.mac, enc.encode('user:' + phone)));
}
// PIN / recovery key hash: HMAC with the server secret first, then PBKDF2. A stolen database alone cannot be brute forced.
async function hashSecret(env, secret, saltB64) {
  const k = await keys(env);
  const pre = await crypto.subtle.sign('HMAC', k.pepper, enc.encode(String(secret)));
  const base = await crypto.subtle.importKey('raw', pre, 'PBKDF2', false, ['deriveBits']);
  return b64(
    await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: PBKDF2_ITER }, base, 256)
  );
}

// ---------- validation ----------
const okId = (s) => typeof s === 'string' && /^[\w-]{6,64}$/.test(s);
const str = (s, n) => String(s ?? '').slice(0, n);
function normUser(u) {
  const x = String(u || '').trim().toLowerCase();
  return /^[a-z0-9._]{3,30}$/.test(x) ? x : null;
}
const okPw = (s) => typeof s === 'string' && s.length >= 8 && s.length <= 64;
function makeRecoveryKey() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const chars = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => alphabet[b % alphabet.length]);
  return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join('')).join('-');
}

// ---------- rate limit ----------
async function limited(env, key, max, windowMs) {
  const now = Date.now();
  const r = await env.DB.prepare('SELECT n,reset FROM rl WHERE k=?').bind(key).first();
  if (!r || r.reset <= now) {
    await env.DB.prepare('INSERT INTO rl(k,n,reset) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=1, reset=excluded.reset')
      .bind(key, now + windowMs)
      .run();
    return false;
  }
  if (r.n >= max) return true;
  await env.DB.prepare('UPDATE rl SET n=n+1 WHERE k=?').bind(key).run();
  return false;
}

// ---------- sessions ----------
const cookieHeader = (token, secure, maxAge) =>
  `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
function getCookie(req, name) {
  for (const part of (req.headers.get('Cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}
async function startSession(env, userId, secure) {
  const token = randHex(32);
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
    env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(
      await sha256Hex(token),
      userId,
      now + SESSION_DAYS * 864e5
    ),
  ]);
  return cookieHeader(token, secure, SESSION_DAYS * 86400);
}
async function authUser(req, env, secure) {
  const tok = getCookie(req, COOKIE);
  if (!/^[0-9a-f]{64}$/.test(tok)) return null;
  const th = await sha256Hex(tok);
  const now = Date.now();
  const row = await env.DB.prepare('SELECT user_id,expires_at FROM sessions WHERE token_hash=? AND expires_at>?').bind(th, now).first();
  if (!row) return null;
  let refresh = null;
  if (row.expires_at - now < (SESSION_DAYS - 1) * 864e5) {
    await env.DB.prepare('UPDATE sessions SET expires_at=? WHERE token_hash=?').bind(now + SESSION_DAYS * 864e5, th).run();
    refresh = cookieHeader(tok, secure, SESSION_DAYS * 86400);
  }
  return { uid: row.user_id, th, refresh };
}

async function failAttempt(env, user) {
  const failed = (user.failed || 0) + 1;
  if (failed >= MAX_FAILS) {
    const mins = LOCK_MIN[Math.min(user.lockouts || 0, LOCK_MIN.length - 1)];
    await env.DB.prepare('UPDATE users SET failed=0, lockouts=lockouts+1, locked_until=? WHERE id=?')
      .bind(Date.now() + mins * 60000, user.id)
      .run();
  } else {
    await env.DB.prepare('UPDATE users SET failed=? WHERE id=?').bind(failed, user.id).run();
  }
}
const lockedResponse = (user) => {
  const mins = Math.ceil((user.locked_until - Date.now()) / 60000);
  return json({ error: `Too many wrong attempts. Try again in ${mins > 90 ? Math.ceil(mins / 60) + ' hours' : mins + ' min'}.` }, 429);
};


// ---------- first-run setup: tables and keys are created automatically ----------
// If you set DATA_KEY / VAPID_JWK as Cloudflare secrets they are used (strongest). Otherwise random keys are
// generated once and kept in the database, so nothing has to be set up by hand.
let bootP = null;
async function bootOnce(env) {
  await env.DB.batch(SCHEMA.map((q) => env.DB.prepare(q)));
  const o = {};
  if (!env.DATA_KEY || !env.VAPID_JWK) {
    const get = async (k) => (await env.DB.prepare('SELECT v FROM meta WHERE k=?').bind(k).first())?.v;
    if (!env.DATA_KEY) {
      await env.DB.prepare('INSERT OR IGNORE INTO meta(k,v) VALUES(?,?)').bind('data_key', b64(crypto.getRandomValues(new Uint8Array(32)))).run();
      o.DATA_KEY = await get('data_key');
    }
    if (!env.VAPID_JWK) {
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      await env.DB.prepare('INSERT OR IGNORE INTO meta(k,v) VALUES(?,?)').bind('vapid_jwk', JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey))).run();
      o.VAPID_JWK = await get('vapid_jwk');
    }
  }
  return o;
}
async function boot(env) {
  if (!bootP) {
    bootP = bootOnce(env);
    bootP.catch(() => { bootP = null; });
  }
  const o = await bootP;
  return Object.keys(o).length ? Object.assign(Object.create(env), o) : env;
}

// ---------- API ----------
async function api(req, env, url) {
  const path = url.pathname;
  const secure = url.protocol === 'https:';

  if (req.method === 'GET' && path === '/api/status') {
    const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
    return json({ hasUser: (r?.n || 0) > 0, ready: true });
  }
  if (req.method !== 'POST') return json({ error: 'Not found' }, 404);

  // CSRF defence: custom header + the request must come from this very site
  if (req.headers.get('X-Requested-With') !== 'hariom') return json({ error: 'Bad request' }, 403);
  if (req.headers.get('Origin') !== url.origin) return json({ error: 'Bad origin' }, 403);

  if (parseInt(req.headers.get('content-length') || '0', 10) > MAX_BODY) return json({ error: 'Too large' }, 413);
  const text = await req.text();
  if (text.length > MAX_BODY) return json({ error: 'Too large' }, 413);
  let body = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      return json({ error: 'Bad request' }, 400);
    }
    if (!body || typeof body !== 'object') return json({ error: 'Bad request' }, 400);
  }

  const ip = req.headers.get('CF-Connecting-IP') || 'local';

  if (path === '/api/register' || path === '/api/login' || path === '/api/reset') {
    if (await limited(env, 'auth:' + ip, 15, 10 * 60000)) return json({ error: 'Too many requests. Wait a few minutes.' }, 429);
  }

  if (path === '/api/register') {
    const phone = normUser(body.username);
    const pin = String(body.pin || '');
    if (!phone) return json({ error: 'Username must be 3 to 30 letters, numbers, dots or underscores' }, 400);
    if (!okPw(pin)) return json({ error: 'Password must be at least 8 characters' }, 400);
    const id = crypto.randomUUID();
    const pinSalt = newSalt();
    const recSalt = newSalt();
    const recoveryKey = makeRecoveryKey();
    const res = await env.DB.prepare(
      `INSERT INTO users(id,phone_h,pin_hash,pin_salt,recovery_hash,recovery_salt,created_at)
       SELECT ?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`
    )
      .bind(
        id,
        await phoneHash(env, phone),
        await hashSecret(env, pin, pinSalt),
        pinSalt,
        await hashSecret(env, recoveryKey, recSalt),
        recSalt,
        Date.now()
      )
      .run();
    if (!res.meta || res.meta.changes !== 1) return json({ error: 'This app already has an owner. Please log in.' }, 403);
    return json({ username: phone, recoveryKey }, 200, [await startSession(env, id, secure)]);
  }

  if (path === '/api/login') {
    const phone = normUser(body.username);
    const pin = String(body.pin || '');
    const bad = () => json({ error: 'Wrong username or password' }, 401);
    if (!phone || !okPw(pin)) return bad();
    const user = await env.DB.prepare('SELECT * FROM users WHERE phone_h=?').bind(await phoneHash(env, phone)).first();
    if (!user) {
      await hashSecret(env, pin, newSalt()); // same work as a real check, so timing does not reveal anything
      return bad();
    }
    if (user.locked_until > Date.now()) return lockedResponse(user);
    if (!same(await hashSecret(env, pin, user.pin_salt), user.pin_hash)) {
      await failAttempt(env, user);
      return bad();
    }
    await env.DB.prepare('UPDATE users SET failed=0, lockouts=0, locked_until=0 WHERE id=?').bind(user.id).run();
    return json({ username: phone }, 200, [await startSession(env, user.id, secure)]);
  }

  if (path === '/api/reset') {
    const phone = normUser(body.username);
    const key = String(body.recoveryKey || '').trim().toUpperCase();
    const pin = String(body.pin || '');
    if (!phone || !key || !okPw(pin)) return json({ error: 'Fill every field correctly (password at least 8 characters)' }, 400);
    const user = await env.DB.prepare('SELECT * FROM users WHERE phone_h=?').bind(await phoneHash(env, phone)).first();
    if (!user || !same(await hashSecret(env, key, user.recovery_salt), user.recovery_hash)) {
      if (!user) await hashSecret(env, key, newSalt());
      return json({ error: 'Username or recovery key is wrong' }, 401);
    }
    const salt = newSalt();
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET pin_hash=?, pin_salt=?, failed=0, lockouts=0, locked_until=0 WHERE id=?').bind(
        await hashSecret(env, pin, salt),
        salt,
        user.id
      ),
      env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(user.id),
    ]);
    return json({ username: phone }, 200, [await startSession(env, user.id, secure)]);
  }

  if (path === '/api/logout') {
    const a = await authUser(req, env, secure);
    if (a) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(a.th).run();
    return json({ ok: true }, 200, [cookieHeader('', secure, 0)]);
  }

  // ----- everything below needs a valid login -----
  const a = await authUser(req, env, secure);
  if (!a) return json({ error: 'Session expired' }, 401);
  const uid = a.uid;
  const out = (data, status = 200) => json(data, status, a.refresh ? [a.refresh] : []);

  if (path === '/api/sync') {
    await applyOps(env, uid, Array.isArray(body.ops) ? body.ops.slice(0, 500) : []);
    return out(await loadState(env, uid));
  }

  if (path === '/api/me') {
    const subs = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs WHERE user_id=?').bind(uid).first();
    return out({
      vapid: env.VAPID_JWK ? (await vapid(env)).pub : null,
      wa: !!(env.WA_TOKEN && env.WA_PHONE_ID && env.WA_TEMPLATE),
      subs: subs?.n || 0,
    });
  }

  if (path === '/api/change-password') {
    const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(uid).first();
    const pin = String(body.pin || '');
    const nw = String(body.newPin || '');
    if (!okPw(nw)) return out({ error: 'New password must be at least 8 characters' }, 400);
    if (user.locked_until > Date.now()) return lockedResponse(user);
    if (!okPw(pin) || !same(await hashSecret(env, pin, user.pin_salt), user.pin_hash)) {
      await failAttempt(env, user);
      return out({ error: 'Current password is wrong' }, 401);
    }
    const salt = newSalt();
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET pin_hash=?, pin_salt=?, failed=0, lockouts=0 WHERE id=?').bind(await hashSecret(env, nw, salt), salt, uid),
      env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').bind(uid, a.th),
    ]);
    return out({ ok: true });
  }

  if (path === '/api/push/subscribe') {
    const endpoint = String(body.endpoint || '');
    if (!okEndpoint(endpoint)) return out({ error: 'Unsupported push service' }, 400);
    const id = (await sha256Hex(endpoint)).slice(0, 32);
    const d = await encField(env, { endpoint }, `sub:${id}:${uid}`);
    await env.DB.prepare(
      'INSERT INTO push_subs(id,user_id,d,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET d=excluded.d WHERE push_subs.user_id=excluded.user_id'
    )
      .bind(id, uid, d, Date.now())
      .run();
    return out({ ok: true });
  }
  if (path === '/api/push/unsubscribe') {
    await env.DB.prepare('DELETE FROM push_subs WHERE user_id=?').bind(uid).run();
    return out({ ok: true });
  }
  if (path === '/api/push/test') {
    if (await limited(env, 'test:' + uid, 10, 10 * 60000)) return out({ error: 'Slow down a little' }, 429);
    await notify(env, uid, 'Hari Om', 'Notifications are working. You will be reminded here.');
    return out({ sent: await pushAll(env, uid) });
  }
  if (path === '/api/notifs') {
    const { results } = await env.DB.prepare('SELECT id,d,created_at FROM notifs WHERE user_id=? AND shown=0 ORDER BY created_at LIMIT 10').bind(uid).all();
    const items = [];
    for (const r of results) {
      try {
        const n = await decField(env, r.d, `notif:${r.id}:${uid}`);
        items.push({ id: r.id, title: n.title, body: n.body, url: n.url || '/' });
      } catch {}
      await env.DB.prepare('UPDATE notifs SET shown=1 WHERE id=?').bind(r.id).run();
    }
    return out({ items });
  }

  return out({ error: 'Not found' }, 404);
}

// ---------- sync ----------
async function applyOps(env, uid, ops) {
  const db = env.DB;
  const now = Date.now();
  const stmts = [];
  for (const o of ops) {
    if (!o || typeof o !== 'object' || !okId(o.id)) continue;
    switch (o.t) {
      case 'party': {
        const name = str(o.name, 120).trim();
        const phone = String(o.phone || '').replace(/\D/g, '');
        if (!name || (phone && !/^\d{10}$/.test(phone))) break;
        const d = await encField(env, { name, phone }, `party:${o.id}:${uid}`);
        stmts.push(
          db
            .prepare('INSERT INTO parties(id,user_id,d,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET d=excluded.d WHERE parties.user_id=excluded.user_id')
            .bind(o.id, uid, d, now)
        );
        break;
      }
      case 'txn': {
        const amount = Number(o.amount);
        if (!okId(o.party_id) || !['gave', 'took'].includes(o.kind) || !Number.isFinite(amount) || amount <= 0 || amount > 1e12) break;
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(o.txn_at || '')) break;
        const d = await encField(
          env,
          { kind: o.kind, amount: Math.round(amount * 100) / 100, txn_at: o.txn_at, note: str(o.note, 5000) },
          `txn:${o.id}:${uid}`
        );
        stmts.push(
          db
            .prepare(
              'INSERT INTO txns(id,user_id,party_id,d,created_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET party_id=excluded.party_id, d=excluded.d WHERE txns.user_id=excluded.user_id'
            )
            .bind(o.id, uid, o.party_id, d, now)
        );
        break;
      }
      case 'txn_del':
        stmts.push(db.prepare('DELETE FROM reminders WHERE txn_id=? AND user_id=?').bind(o.id, uid));
        stmts.push(db.prepare('DELETE FROM txns WHERE id=? AND user_id=?').bind(o.id, uid));
        break;
      case 'party_del':
        stmts.push(db.prepare('DELETE FROM reminders WHERE party_id=? AND user_id=?').bind(o.id, uid));
        stmts.push(db.prepare('DELETE FROM txns WHERE party_id=? AND user_id=?').bind(o.id, uid));
        stmts.push(db.prepare('DELETE FROM parties WHERE id=? AND user_id=?').bind(o.id, uid));
        break;
      case 'rem': {
        const target = o.target === 'self' ? 'self' : 'party';
        const sendAt = Math.round(Number(o.send_at));
        const message = str(o.message, 1000).trim();
        if ((target === 'party' && !okId(o.party_id)) || !Number.isFinite(sendAt) || !message) break;
        const rt = ['once', 'days', 'monthly', 'monthend'].includes(o.repeat_type) ? o.repeat_type : 'once';
        const st = ['active', 'sent', 'failed'].includes(o.status) ? o.status : 'active';
        const rn = Math.max(0, Math.min(3650, parseInt(o.repeat_n, 10) || 0));
        const last = Number.isFinite(Number(o.last_sent)) && o.last_sent ? Math.round(Number(o.last_sent)) : null;
        const d = await encField(env, { message }, `rem:${o.id}:${uid}`);
        stmts.push(
          db
            .prepare(
              `INSERT INTO reminders(id,user_id,target,party_id,txn_id,d,send_at,repeat_type,repeat_n,status,last_sent,last_error,notified)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,0)
               ON CONFLICT(id) DO UPDATE SET target=excluded.target, party_id=excluded.party_id, txn_id=excluded.txn_id, d=excluded.d,
                 notified=CASE WHEN reminders.send_at=excluded.send_at THEN reminders.notified ELSE 0 END,
                 send_at=excluded.send_at, repeat_type=excluded.repeat_type, repeat_n=excluded.repeat_n,
                 status=excluded.status, last_sent=excluded.last_sent, last_error=NULL
               WHERE reminders.user_id=excluded.user_id`
            )
            .bind(o.id, uid, target, target === 'party' ? o.party_id : null, okId(o.txn_id) ? o.txn_id : null, d, sendAt, rt, rn, st, last)
        );
        break;
      }
      case 'rem_del':
        stmts.push(db.prepare('DELETE FROM reminders WHERE id=? AND user_id=?').bind(o.id, uid));
        break;
    }
  }
  for (let i = 0; i < stmts.length; i += 50) await db.batch(stmts.slice(i, i + 50));
}

async function loadState(env, uid) {
  const db = env.DB;
  const [p, t, r] = await db.batch([
    db.prepare('SELECT id,d FROM parties WHERE user_id=?').bind(uid),
    db.prepare('SELECT id,party_id,d FROM txns WHERE user_id=?').bind(uid),
    db
      .prepare('SELECT id,target,party_id,txn_id,d,send_at,repeat_type,repeat_n,status,last_sent,last_error FROM reminders WHERE user_id=?')
      .bind(uid),
  ]);
  const parties = [];
  const txns = [];
  const reminders = [];
  for (const x of p.results) {
    try {
      const v = await decField(env, x.d, `party:${x.id}:${uid}`);
      parties.push({ id: x.id, name: v.name, phone: v.phone });
    } catch {}
  }
  for (const x of t.results) {
    try {
      const v = await decField(env, x.d, `txn:${x.id}:${uid}`);
      txns.push({ id: x.id, party_id: x.party_id, kind: v.kind, amount: v.amount, txn_at: v.txn_at, note: v.note });
    } catch {}
  }
  for (const x of r.results) {
    try {
      const v = await decField(env, x.d, `rem:${x.id}:${uid}`);
      const { d, ...rest } = x;
      reminders.push({ ...rest, message: v.message });
    } catch {}
  }
  return { parties, txns, reminders };
}

// ---------- push notifications to your own phone (Web Push, VAPID, no message body goes through the push service) ----------
export function okEndpoint(e) {
  try {
    const u = new URL(e);
    if (u.protocol !== 'https:' || u.port || u.username || e.length > 700) return false;
    const h = u.hostname;
    return (
      h === 'fcm.googleapis.com' ||
      h === 'android.googleapis.com' ||
      h.endsWith('.push.services.mozilla.com') ||
      h.endsWith('.push.apple.com') ||
      h.endsWith('.notify.windows.com')
    );
  } catch {
    return false;
  }
}

let vapidCache = null;
async function vapid(env) {
  if (vapidCache && vapidCache.src === env.VAPID_JWK) return vapidCache;
  const jwk = JSON.parse(env.VAPID_JWK);
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const pub = b64u(new Uint8Array([4, ...unb64u(jwk.x), ...unb64u(jwk.y)]));
  vapidCache = { src: env.VAPID_JWK, key, pub };
  return vapidCache;
}
async function vapidJwt(env, aud) {
  const v = await vapid(env);
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(
    enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || 'mailto:admin@hariom.app' }))
  );
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, v.key, enc.encode(head + '.' + claims));
  return { jwt: `${head}.${claims}.${b64u(sig)}`, pub: v.pub };
}

async function notify(env, uid, title, body) {
  const id = crypto.randomUUID();
  const d = await encField(env, { title, body: String(body).slice(0, 500), url: '/?tab=rem' }, `notif:${id}:${uid}`);
  await env.DB.prepare('INSERT INTO notifs(id,user_id,d,created_at,shown) VALUES(?,?,?,?,0)').bind(id, uid, d, Date.now()).run();
}

async function pushAll(env, uid) {
  if (!env.VAPID_JWK) return 0;
  const { results } = await env.DB.prepare('SELECT id,d FROM push_subs WHERE user_id=?').bind(uid).all();
  let sent = 0;
  for (const s of results) {
    let endpoint = '';
    try {
      endpoint = (await decField(env, s.d, `sub:${s.id}:${uid}`)).endpoint;
    } catch {}
    if (!okEndpoint(endpoint)) {
      await env.DB.prepare('DELETE FROM push_subs WHERE id=?').bind(s.id).run();
      continue;
    }
    try {
      const { jwt, pub } = await vapidJwt(env, new URL(endpoint).origin);
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { Authorization: `vapid t=${jwt}, k=${pub}`, TTL: '86400', Urgency: 'high' },
      });
      if (res.status === 404 || res.status === 410) await env.DB.prepare('DELETE FROM push_subs WHERE id=?').bind(s.id).run();
      else if (res.ok) sent++;
    } catch {}
  }
  return sent;
}

// ---------- reminders (runs every minute) ----------
export function nextSend(ms, type, n) {
  if (type === 'days') return ms + Math.max(1, n || 1) * 864e5;
  const d = new Date(ms + IST); // UTC getters now read IST wall-clock time
  const y = d.getUTCFullYear();
  const m = d.getUTCMonth() + 1;
  const dim = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  const day = type === 'monthend' ? dim : Math.min(n || d.getUTCDate(), dim);
  return Date.UTC(y, m, day, d.getUTCHours(), d.getUTCMinutes()) - IST;
}

const waNumber = (p) => {
  const d = String(p || '').replace(/\D/g, '');
  if (d.length === 10) return '91' + d;
  if (d.length === 12 && d.startsWith('91')) return d;
  return null;
};
const clean = (s) => String(s).replace(/[\r\n\t]+/g, ' ').replace(/ {2,}/g, ' ').trim().slice(0, 1000);

async function sendWhatsApp(env, to, name, message) {
  const res = await fetch(`https://graph.facebook.com/v21.0/${encodeURIComponent(env.WA_PHONE_ID)}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.WA_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to,
      type: 'template',
      template: {
        name: env.WA_TEMPLATE,
        language: { code: env.WA_LANG || 'en' },
        components: [
          { type: 'body', parameters: [{ type: 'text', text: clean(name) || 'Sir/Madam' }, { type: 'text', text: clean(message) }] },
        ],
      },
    }),
  });
  if (!res.ok) {
    const err = new Error(`WhatsApp ${res.status}: ${(await res.text().catch(() => '')).slice(0, 200)}`);
    err.status = res.status;
    throw err;
  }
}

async function advance(env, r, now) {
  if (r.repeat_type === 'once') {
    await env.DB.prepare("UPDATE reminders SET status='sent', last_sent=?, last_error=NULL WHERE id=?").bind(now, r.id).run();
  } else {
    let next = nextSend(r.send_at, r.repeat_type, r.repeat_n);
    for (let i = 0; next <= now && i < 1000; i++) next = nextSend(next, r.repeat_type, r.repeat_n);
    await env.DB.prepare('UPDATE reminders SET send_at=?, last_sent=?, last_error=NULL WHERE id=?').bind(next, now, r.id).run();
  }
}

export async function runReminders(env) {
  if (!env.DATA_KEY) return;
  const now = Date.now();
  const { results } = await env.DB.prepare("SELECT * FROM reminders WHERE status='active' AND send_at<=? ORDER BY send_at LIMIT 20")
    .bind(now)
    .all();
  const waOn = !!(env.WA_TOKEN && env.WA_PHONE_ID && env.WA_TEMPLATE);
  const toPush = new Set();

  for (const r of results) {
    const fail = (msg) => env.DB.prepare("UPDATE reminders SET status='failed', last_error=? WHERE id=?").bind(msg.slice(0, 300), r.id).run();
    try {
      const { message } = await decField(env, r.d, `rem:${r.id}:${r.user_id}`);
      if (r.target === 'self') {
        await notify(env, r.user_id, 'Hari Om reminder', message);
        toPush.add(r.user_id);
        await advance(env, r, now);
        continue;
      }
      const prow = await env.DB.prepare('SELECT d FROM parties WHERE id=? AND user_id=?').bind(r.party_id, r.user_id).first();
      if (!prow) {
        await fail('Party not found');
        continue;
      }
      const party = await decField(env, prow.d, `party:${r.party_id}:${r.user_id}`);
      if (waOn) {
        const to = waNumber(party.phone);
        if (!to) {
          await fail('This party has no mobile number saved');
          continue;
        }
        try {
          await sendWhatsApp(env, to, party.name, message);
          await advance(env, r, now);
        } catch (e) {
          if (!e.status || e.status >= 500) {
            await env.DB.prepare('UPDATE reminders SET send_at=?, last_error=? WHERE id=?')
              .bind(now + 10 * 60000, String(e.message).slice(0, 300), r.id)
              .run();
          } else {
            await fail(String(e.message));
          }
        }
      } else if (r.notified !== r.send_at) {
        // WhatsApp is not connected: tell the owner it is time, one tap sends it from the app
        await notify(env, r.user_id, `Time to message ${party.name}`, message);
        toPush.add(r.user_id);
        await env.DB.prepare('UPDATE reminders SET notified=? WHERE id=?').bind(r.send_at, r.id).run();
      }
    } catch (e) {
      await fail('Could not read this reminder');
    }
  }
  for (const uid of toPush) await pushAll(env, uid);

  if (new Date(now).getUTCMinutes() === 0) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM notifs WHERE created_at<?').bind(now - 7 * 864e5),
      env.DB.prepare('DELETE FROM sessions WHERE expires_at<?').bind(now),
      env.DB.prepare('DELETE FROM rl WHERE reset<?').bind(now),
    ]);
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await api(req, await boot(env), url);
      } catch (e) {
        if (e && e.message === 'NO_KEY') return json({ error: 'Server is not set up yet. Finish step 2 of the README (secrets).' }, 503);
        return json({ error: 'Server error' }, 500);
      }
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('Method not allowed', { status: 405, headers: sec(new Headers()) });
    const res = await env.ASSETS.fetch(req);
    const out = new Response(res.body, res);
    sec(out.headers);
    out.headers.set('Cache-Control', 'no-cache');
    return out;
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(boot(env).then(runReminders));
  },
};
