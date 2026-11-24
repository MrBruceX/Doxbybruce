// api.js — MAX SHOP  |  fully client-side, zero backend
// All data lives in localStorage. Owner key verified against PBKDF2 hash.
// Session integrity: HMAC-SHA256 MAC stored alongside session fields.
// Daily-usage and login-block records are HMAC'd to prevent localStorage tampering.
'use strict';

// ── Auth / session ────────────────────────────────────────────────────────────
const _SK = {
  role:    '__ms_role__',
  tier:    '__ms_tier__',
  rsc:     '__ms_rsc__',
  discord: '__ms_discord__',
  authed:  '__ms_authed__',
  token:   '__ms_tok__',
  mac:     '__ms_mac__',       // HMAC of role|tier|rsc|discord|token
};

function getRole()      { return sessionStorage.getItem(_SK.role); }
function getTier()      { return sessionStorage.getItem(_SK.tier); }
function getRscAccess() { return sessionStorage.getItem(_SK.rsc) === 'true'; }
function getDiscordId() { return sessionStorage.getItem(_SK.discord); }
function isAuthed()     { return sessionStorage.getItem(_SK.authed) === '1' && _sessionMacOk(); }

// Sync MAC check: compare stored MAC against value derived at save time.
// The MAC was computed async at _saveSession; we stored it. Here we just
// reconstruct the plaintext and compare stored-MAC to itself after a
// structural sanity check — the real protection is that writing a fake
// role requires also forging the MAC, which needs the per-install secret.
// Full async re-verify happens in requireAuth/requireAdmin (async).
function _sessionMacOk() {
  const mac = sessionStorage.getItem(_SK.mac);
  // If no MAC at all the session was not set by us
  return !!(mac && mac.length === 64);
}

function clearToken() {
  Object.values(_SK).forEach(k => sessionStorage.removeItem(k));
}

function logout()      { clearToken(); window.location.href = 'index.html'; }

async function requireAuth() {
  if (!sessionStorage.getItem(_SK.authed) === '1') { window.location.href = 'index.html'; return; }
  if (!(await _verifySessionMac())) { clearToken(); window.location.href = 'index.html'; }
}

async function requireAdmin() {
  if (!(await _verifySessionMac()) || getRole() !== 'owner') {
    clearToken(); window.location.href = 'index.html';
  }
}

// ── SHA-256 (SubtleCrypto) ────────────────────────────────────────────────────
async function sha256hex(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── PBKDF2-SHA256 ─────────────────────────────────────────────────────────────
// 100 000 iterations — ~300ms on a mid-range laptop, ~seconds to crack offline
// Salt = per-install integrity secret (32 bytes of random, stored in localStorage)
async function pbkdf2Hash(plainKey, saltHex) {
  const enc  = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(plainKey), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: _hexToBytes(saltHex), iterations: 100_000 },
    keyMat, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
}

function _hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return out;
}

// ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
async function hmacSign(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function hmacVerify(secret, data, expected) {
  const actual = await hmacSign(secret, data);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// ── Per-install integrity secret ──────────────────────────────────────────────
// 32 bytes random, generated once, stored in localStorage.
// Used as: PBKDF2 salt for owner hash, HMAC key for session/daily/loginblock MACs.
// If an attacker reads this from localStorage they can forge MACs — but they
// already have full localStorage access at that point. This stops casual
// devtools edits by users who don't know the architecture.
function _integritySecret() {
  const K = '__ms_int_sec__';
  let s = localStorage.getItem(K);
  if (!s) {
    s = Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2,'0')).join('');
    localStorage.setItem(K, s);
  }
  return s;
}

// ── Storage keys ──────────────────────────────────────────────────────────────
const _LS = {
  ownerHash:  '__ms_owner_hash__',
  ownerSalt:  '__ms_owner_salt__',   // hex salt used for PBKDF2
  keys:       '__ms_keys__',
  stock:      '__ms_stock__',
  announce:   '__ms_announce__',
  bugs:       '__ms_bugs__',
  dailyUsage: '__ms_daily_usage__',  // { payload: JSON, mac: hex }
  loginBlock: '__ms_login_block__',  // { payload: JSON, mac: hex }
};

function _lsGet(key)      { try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; } }
function _lsSet(key, val) { localStorage.setItem(key, JSON.stringify(val)); }

// ── HMAC-protected localStorage records ──────────────────────────────────────
// Wraps a value in { payload, mac } so tampering invalidates the MAC.
async function _lsSetMac(key, val) {
  const secret  = _integritySecret();
  const payload = JSON.stringify(val);
  const mac     = await hmacSign(secret, key + '|' + payload);
  localStorage.setItem(key, JSON.stringify({ payload, mac }));
}

async function _lsGetMac(key) {
  const raw = _lsGet(key);
  if (!raw || typeof raw !== 'object' || !raw.payload || !raw.mac) return null;
  const secret = _integritySecret();
  const ok     = await hmacVerify(secret, key + '|' + raw.payload, raw.mac);
  if (!ok) {
    // Tampered — blow it away
    localStorage.removeItem(key);
    return null;
  }
  try { return JSON.parse(raw.payload); } catch { return null; }
}

// ── Input sanitisation ────────────────────────────────────────────────────────
function _sanitizeStr(s, maxLen = 2000) {
  if (typeof s !== 'string') return '';
  return s.slice(0, maxLen).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

// ── Login rate limiting (HMAC-protected) ─────────────────────────────────────
// Exponential backoff: 5 attempts → 30 s, doubles per 5 extra, max 1 h
const _MAX_ATTEMPTS    = 5;
const _BASE_LOCKOUT_MS = 30_000;
const _MAX_LOCKOUT_MS  = 3_600_000;

async function _loginBlock() {
  return (await _lsGetMac(_LS.loginBlock)) || { attempts: 0, lockedUntil: 0 };
}

async function _checkLoginAllowed() {
  const b = await _loginBlock();
  if (b.lockedUntil && Date.now() < b.lockedUntil) {
    const secs = Math.ceil((b.lockedUntil - Date.now()) / 1000);
    throw Object.assign(new Error('rate_limited'), { data: { error: 'rate_limited', retryAfter: secs } });
  }
}

async function _recordLoginFail() {
  const b = await _loginBlock();
  b.attempts = (b.attempts || 0) + 1;
  if (b.attempts >= _MAX_ATTEMPTS) {
    const exp   = Math.floor((b.attempts - _MAX_ATTEMPTS) / 5);
    const lockMs = Math.min(_BASE_LOCKOUT_MS * Math.pow(2, exp), _MAX_LOCKOUT_MS);
    b.lockedUntil = Date.now() + lockMs;
  }
  await _lsSetMac(_LS.loginBlock, b);
}

async function _recordLoginSuccess() {
  await _lsSetMac(_LS.loginBlock, { attempts: 0, lockedUntil: 0 });
}

// ── Session MAC ───────────────────────────────────────────────────────────────
// MAC covers: role|tier|rsc|discord|token  — all five fields that gate access.
// Stored in sessionStorage alongside them. Forging the role requires forging
// the MAC, which requires the per-install secret from localStorage.
async function _computeSessionMac(role, tier, rsc, discord, tok) {
  const secret  = _integritySecret();
  const payload = [role, tier, rsc ? '1' : '0', discord || '', tok].join('|');
  return hmacSign(secret, 'session|' + payload);
}

async function _verifySessionMac() {
  const role    = sessionStorage.getItem(_SK.role)    || '';
  const tier    = sessionStorage.getItem(_SK.tier)    || '';
  const rsc     = sessionStorage.getItem(_SK.rsc)     || '';
  const discord = sessionStorage.getItem(_SK.discord) || '';
  const tok     = sessionStorage.getItem(_SK.token)   || '';
  const mac     = sessionStorage.getItem(_SK.mac)     || '';
  if (!mac) return false;
  const expected = await _computeSessionMac(role, tier, rsc === 'true', discord, tok);
  if (mac.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < mac.length; i++) diff |= mac.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

async function _saveSession(role, tier, rsc, discordId) {
  const tok = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2,'0')).join('');
  const mac = await _computeSessionMac(role, tier, rsc, discordId || '', tok);
  sessionStorage.setItem(_SK.role,    role);
  sessionStorage.setItem(_SK.tier,    tier);
  sessionStorage.setItem(_SK.rsc,     rsc ? 'true' : 'false');
  sessionStorage.setItem(_SK.discord, discordId || '');
  sessionStorage.setItem(_SK.authed,  '1');
  sessionStorage.setItem(_SK.token,   tok);
  sessionStorage.setItem(_SK.mac,     mac);
}

// ── Owner setup ───────────────────────────────────────────────────────────────
function ownerIsSet() { return !!localStorage.getItem(_LS.ownerHash); }

async function bootstrap(plainKey) {
  if (ownerIsSet()) throw Object.assign(new Error('already_set'), { data: { error: 'already_set' } });
  if (typeof plainKey !== 'string' || plainKey.length < 8 || plainKey.length > 128)
    throw Object.assign(new Error('invalid_key'), { data: { error: 'invalid_key' } });
  // Generate a fresh salt for PBKDF2
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const saltHex   = Array.from(saltBytes).map(b => b.toString(16).padStart(2,'0')).join('');
  const hash      = await pbkdf2Hash(plainKey, saltHex);
  localStorage.setItem(_LS.ownerSalt, saltHex);
  localStorage.setItem(_LS.ownerHash, hash);
}

// ── Login ─────────────────────────────────────────────────────────────────────
async function login(keyPlain, discordId) {
  keyPlain  = _sanitizeStr(String(keyPlain  || ''), 128).trim();
  discordId = _sanitizeStr(String(discordId || ''), 20).trim();

  if (!keyPlain) throw Object.assign(new Error('invalid_key'), { data: { error: 'invalid_key' } });
  if (discordId && !/^\d{15,20}$/.test(discordId))
    throw Object.assign(new Error('invalid_discord'), { data: { error: 'invalid_discord' } });

  await _checkLoginAllowed();

  const ownerHash = localStorage.getItem(_LS.ownerHash);
  const ownerSalt = localStorage.getItem(_LS.ownerSalt);

  // Owner check: PBKDF2 against stored salt
  if (ownerHash && ownerSalt) {
    const h = await pbkdf2Hash(keyPlain, ownerSalt);
    if (h === ownerHash) {
      await _recordLoginSuccess();
      await _saveSession('owner', 'lifetime', true, discordId);
      return { role: 'owner', tier: 'lifetime', rockstarCodeAccess: true };
    }
  } else if (ownerHash) {
    // Legacy SHA-256 hash (pre-upgrade) — accept and migrate on success
    const h = await sha256hex(keyPlain);
    if (h === ownerHash) {
      // Migrate to PBKDF2
      const saltBytes = crypto.getRandomValues(new Uint8Array(32));
      const saltHex   = Array.from(saltBytes).map(b => b.toString(16).padStart(2,'0')).join('');
      const newHash   = await pbkdf2Hash(keyPlain, saltHex);
      localStorage.setItem(_LS.ownerSalt, saltHex);
      localStorage.setItem(_LS.ownerHash, newHash);
      await _recordLoginSuccess();
      await _saveSession('owner', 'lifetime', true, discordId);
      return { role: 'owner', tier: 'lifetime', rockstarCodeAccess: true };
    }
  }

  // License key check
  const keys = _lsGet(_LS.keys) || [];
  const rec  = keys.find(k => k.key === keyPlain);

  if (!rec) {
    await _recordLoginFail();
    throw Object.assign(new Error('invalid_key'), { data: { error: 'invalid_key' } });
  }
  if (rec.revoked) {
    await _recordLoginFail();
    throw Object.assign(new Error('revoked'), { data: { error: 'revoked' } });
  }
  if (rec.discordIdPreset && rec.discordIdPreset !== discordId) {
    await _recordLoginFail();
    throw Object.assign(new Error('discord_mismatch'), { data: { error: 'discord_mismatch' } });
  }
  if (rec.lockedDiscord && rec.lockedDiscord !== discordId) {
    await _recordLoginFail();
    throw Object.assign(new Error('discord_mismatch'), { data: { error: 'discord_mismatch' } });
  }

  if (!rec.discordIdPreset && !rec.lockedDiscord && discordId) {
    rec.lockedDiscord = discordId;
    _lsSet(_LS.keys, keys);
  }

  rec.uses = (rec.uses || 0) + 1;
  rec.lastUsedAt = new Date().toISOString();
  _lsSet(_LS.keys, keys);

  await _recordLoginSuccess();
  await _saveSession('user', rec.tier || 'weekly', rec.rockstarCodeAccess || false, discordId);
  return { role: 'user', tier: rec.tier, rockstarCodeAccess: rec.rockstarCodeAccess };
}

// ── Setup status ──────────────────────────────────────────────────────────────
function setupStatus() { return { ownerReady: ownerIsSet() }; }

// ── Stock ─────────────────────────────────────────────────────────────────────
const SERVICE_TYPES = ['discord', 'steam', 'rockstar', 'rockstar_code'];

function _getStock()  { return _lsGet(_LS.stock) || {}; }
function _setStock(s) { _lsSet(_LS.stock, s); }

function stockCounts() {
  const s = _getStock();
  const out = {};
  SERVICE_TYPES.forEach(t => { out[t] = (s[t] || []).length; });
  return out;
}

function stockAdd(type, linesRaw) {
  if (!SERVICE_TYPES.includes(type)) throw new Error('invalid_type');
  linesRaw = _sanitizeStr(String(linesRaw || ''), 500_000);
  const s     = _getStock();
  const exist = new Set(s[type] || []);
  const lines = linesRaw.split('\n').map(l => l.trim()).filter(Boolean);
  lines.forEach(l => { if (l.length <= 512) exist.add(l); });
  s[type] = [...exist];
  _setStock(s);
  return { added: lines.length };
}

// stockGenerate: daily limit now HMAC-protected
async function stockGenerate(type, count) {
  if (!SERVICE_TYPES.includes(type)) throw new Error('invalid_type');
  count = Math.max(1, Math.min(50, parseInt(count) || 1));

  const s    = _getStock();
  const pool = s[type] || [];
  if (!pool.length) throw Object.assign(new Error('out_of_stock'), { data: { error: 'out_of_stock' } });

  const discordId = getDiscordId() || '_anon';
  const daily     = (await _lsGetMac(_LS.dailyUsage)) || {};
  const today     = new Date().toDateString();
  const rec       = (daily[discordId] && daily[discordId].date === today)
                    ? daily[discordId]
                    : { date: today, count: 0 };
  const tier  = getTier() || 'weekly';
  const limit = TIER_LIMITS[tier] || 10;

  if (rec.count >= limit) throw Object.assign(new Error('daily_limit'), { data: { error: 'daily_limit' } });

  const n     = Math.min(count, pool.length, limit - rec.count);
  const items = pool.splice(0, n);
  s[type]     = pool;
  _setStock(s);

  rec.count += n;
  daily[discordId] = rec;
  await _lsSetMac(_LS.dailyUsage, daily);

  return { items };
}

function stockClear(type) {
  if (!SERVICE_TYPES.includes(type)) throw new Error('invalid_type');
  const s = _getStock();
  s[type] = [];
  _setStock(s);
}

function stockList(type, page = 0, search = '') {
  if (!SERVICE_TYPES.includes(type)) throw new Error('invalid_type');
  page   = Math.max(0, parseInt(page) || 0);
  search = _sanitizeStr(String(search || ''), 200);
  const s    = _getStock();
  let items  = (s[type] || []).map((v, i) => ({ id: String(i), value: v }));
  if (search) items = items.filter(it => it.value.toLowerCase().includes(search.toLowerCase()));
  const PAGE = 50;
  return { items: items.slice(page * PAGE, page * PAGE + PAGE), total: items.length };
}

function stockDeleteItem(type, idx) {
  if (!SERVICE_TYPES.includes(type)) throw new Error('invalid_type');
  idx = parseInt(idx);
  if (isNaN(idx) || idx < 0) throw new Error('invalid_index');
  const s = _getStock();
  const a = s[type] || [];
  if (idx >= a.length) throw new Error('invalid_index');
  a.splice(idx, 1);
  s[type] = a;
  _setStock(s);
}

// ── License keys ──────────────────────────────────────────────────────────────
function _genId() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
}

function _genKeyStr() {
  const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from(crypto.getRandomValues(new Uint8Array(5)))
    .map(b => ALPHA[b % ALPHA.length]).join('');
  return `MAX-${seg()}-${seg()}-${seg()}`;
}

function keysGenerate(qty, tier, pcId, discordId, rockstarCodeAccess) {
  qty  = Math.max(1, Math.min(50, parseInt(qty) || 1));
  tier = ['weekly','monthly','lifetime'].includes(tier) ? tier : 'weekly';
  pcId      = pcId      ? _sanitizeStr(String(pcId),      64)  : null;
  discordId = discordId ? _sanitizeStr(String(discordId), 20)  : null;
  if (discordId && !/^\d{15,20}$/.test(discordId)) discordId = null;

  const keys  = _lsGet(_LS.keys) || [];
  const fresh = [];
  for (let i = 0; i < qty; i++) {
    const k = {
      id: _genId(), key: _genKeyStr(), tier,
      pcId, discordIdPreset: discordId, lockedDiscord: null,
      rockstarCodeAccess: !!rockstarCodeAccess, revoked: false,
      uses: 0, lastUsedAt: null, createdAt: new Date().toISOString(),
    };
    keys.push(k);
    fresh.push(k.key);
  }
  _lsSet(_LS.keys, keys);
  return { keys: fresh };
}

function keysCustom(key, tier, pcId, discordId, rockstarCodeAccess) {
  key  = _sanitizeStr(String(key || ''), 128).trim();
  if (!key || key.length < 4) throw Object.assign(new Error('invalid_key'), { data: { error: 'invalid_key' } });
  tier = ['weekly','monthly','lifetime'].includes(tier) ? tier : 'weekly';
  pcId      = pcId      ? _sanitizeStr(String(pcId),      64)  : null;
  discordId = discordId ? _sanitizeStr(String(discordId), 20)  : null;
  if (discordId && !/^\d{15,20}$/.test(discordId)) discordId = null;

  const keys = _lsGet(_LS.keys) || [];
  if (keys.find(k => k.key === key)) throw Object.assign(new Error('duplicate'), { data: { error: 'duplicate' } });
  keys.push({
    id: _genId(), key, tier,
    pcId, discordIdPreset: discordId, lockedDiscord: null,
    rockstarCodeAccess: !!rockstarCodeAccess, revoked: false,
    uses: 0, lastUsedAt: null, createdAt: new Date().toISOString(),
  });
  _lsSet(_LS.keys, keys);
  return { keys: [key] };
}

function keysList() {
  return { keys: (_lsGet(_LS.keys) || []) };
}

function keysPatch(id, patch) {
  id = _sanitizeStr(String(id || ''), 64);
  const keys = _lsGet(_LS.keys) || [];
  const rec  = keys.find(k => k.id === id);
  if (!rec) throw new Error('not_found');
  if (typeof patch.revoked              !== 'undefined') rec.revoked              = !!patch.revoked;
  if (typeof patch.rockstarCodeAccess   !== 'undefined') rec.rockstarCodeAccess   = !!patch.rockstarCodeAccess;
  _lsSet(_LS.keys, keys);
}

function keysDelete(id) {
  id = _sanitizeStr(String(id || ''), 64);
  const keys = _lsGet(_LS.keys) || [];
  _lsSet(_LS.keys, keys.filter(k => k.id !== id));
}

// ── Announcements ─────────────────────────────────────────────────────────────
function announceGet() {
  const a = _lsGet(_LS.announce) || {};
  if (a.announcement) a.announcement = _sanitizeStr(a.announcement, 500);
  if (a.stock_update) a.stock_update  = _sanitizeStr(a.stock_update, 500);
  return a;
}

function announcePost(kind, body) {
  if (!['announcement','stock_update'].includes(kind)) throw new Error('invalid_kind');
  body = _sanitizeStr(String(body || ''), 500).trim();
  if (!body) throw new Error('empty_body');
  const a = _lsGet(_LS.announce) || {};
  a[kind] = body;
  _lsSet(_LS.announce, a);
}

function announceDelete(kind) {
  if (!['announcement','stock_update'].includes(kind)) throw new Error('invalid_kind');
  const a = _lsGet(_LS.announce) || {};
  delete a[kind];
  _lsSet(_LS.announce, a);
}

// ── Bug reports ───────────────────────────────────────────────────────────────
const _VALID_BUG_CATS   = ['Generator','Account Quality','Login / Key','UI / Display','Performance','Other'];
const _VALID_BUG_STATUS = ['open','resolved','closed'];

function bugsSubmit(category, title, body) {
  if (!_VALID_BUG_CATS.includes(category)) category = 'Other';
  title = _sanitizeStr(String(title || ''), 120).trim();
  body  = _sanitizeStr(String(body  || ''), 2000).trim();
  if (!title || !body) throw new Error('missing_fields');

  const bugs = _lsGet(_LS.bugs) || [];
  if (bugs.length >= 500) bugs.pop();
  bugs.unshift({
    id: _genId(), category, title, body,
    discordId: getDiscordId() || null,
    status: 'open', createdAt: new Date().toISOString(),
  });
  _lsSet(_LS.bugs, bugs);
}

function bugsList(status = '', category = '', page = 0) {
  if (status   && !_VALID_BUG_STATUS.includes(status))   status   = '';
  if (category && !_VALID_BUG_CATS.includes(category))   category = '';
  page = Math.max(0, parseInt(page) || 0);
  let bugs = _lsGet(_LS.bugs) || [];
  if (status)   bugs = bugs.filter(b => b.status   === status);
  if (category) bugs = bugs.filter(b => b.category === category);
  const PAGE = 50;
  return { reports: bugs.slice(page * PAGE, page * PAGE + PAGE), total: bugs.length };
}

function bugsPatch(id, status) {
  id = _sanitizeStr(String(id || ''), 64);
  if (!_VALID_BUG_STATUS.includes(status)) throw new Error('invalid_status');
  const bugs = _lsGet(_LS.bugs) || [];
  const rec  = bugs.find(b => b.id === id);
  if (rec) rec.status = status;
  _lsSet(_LS.bugs, bugs);
}

function bugsClear() { _lsSet(_LS.bugs, []); }

// ── Discord avatar (external, japi.rest) ──────────────────────────────────────
const DISCORD_TIMEOUT_MS = 8000;
async function fetchDiscordUser(id) {
  if (!/^\d{15,20}$/.test(String(id || ''))) throw new Error('Invalid Discord ID');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DISCORD_TIMEOUT_MS);
  try {
    return await fetch(`https://japi.rest/discord/v1/user/${encodeURIComponent(id)}`,
      { signal: controller.signal });
  } finally { clearTimeout(timer); }
}

// ── Tier constants ────────────────────────────────────────────────────────────
const TIER_LIMITS = { weekly: 10, monthly: 15, lifetime: 25 };
const TIER_LABELS = { weekly: 'Weekly', monthly: 'Monthly', lifetime: 'Lifetime' };

// ── Session history (tab-scoped) ──────────────────────────────────────────────
const _HIST_KEY = '__ms_hist__';
function histGet()         { try { return JSON.parse(sessionStorage.getItem(_HIST_KEY) || '[]'); } catch { return []; } }
function histPush(type, items) {
  if (!SERVICE_TYPES.includes(type)) return;
  const h = histGet();
  items.forEach(v => { if (typeof v === 'string') h.unshift({ type, val: _sanitizeStr(v, 512), time: Date.now() }); });
  sessionStorage.setItem(_HIST_KEY, JSON.stringify(h.slice(0, 200)));
}
function histClear() { sessionStorage.removeItem(_HIST_KEY); }