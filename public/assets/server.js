// server.js — MAX SHOP backend  |  Node >=20, Express, PostgreSQL (Render)
'use strict';
require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const bcrypt       = require('bcrypt');
const jwt          = require('jsonwebtoken');
const multer       = require('multer');
const path         = require('path');
const { pool, initSchema } = require('./db');

const PORT          = process.env.PORT || 3000;
const JWT_SECRET    = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 12;
const TIER_LIMITS   = { weekly: 10, monthly: 15, lifetime: 25 };
const SERVICE_TYPES = ['discord', 'steam', 'rockstar', 'rockstar_code'];
const VALID_TIERS   = ['weekly', 'monthly', 'lifetime'];
const VALID_KINDS   = ['announcement', 'stock_update'];
const VALID_BUG_CATS = ['Generator','Account Quality','Login / Key','UI / Display','Performance','Other'];
const VALID_BUG_STATUS = ['open','resolved','closed'];
const MAX_UPLOAD_MB = 100;

if (!JWT_SECRET) { console.error('[fatal] JWT_SECRET env var missing'); process.exit(1); }

const app = express();

app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));

const ALLOWED_ORIGIN = process.env.FRONTEND_ORIGIN || '*';
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
// serves /assets/services/*.png and /assets/logo.png at URL path /assets/*
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', retryAfter: 900 },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: { error: 'upload_rate_limited' },
});

app.use('/api/', apiLimiter);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ok = /^(video\/(mp4|webm)|image\/(jpeg|png|gif|webp))$/.test(file.mimetype);
    cb(ok ? null : new Error('invalid_mime'), ok);
  },
});

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'unauthorized' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'forbidden' });
    next();
  });
}

function sanitize(s, max = 2000) {
  if (typeof s !== 'string') return '';
  return s.slice(0, max).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

function genKeyStr() {
  const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 5 }, () =>
    ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
  return `MAX-${seg()}-${seg()}-${seg()}`;
}

app.post('/api/setup', async (req, res) => {
  try {
    const { key } = req.body;
    if (!key || typeof key !== 'string' || key.length < 8 || key.length > 128)
      return res.status(400).json({ error: 'invalid_key' });
    const existing = await pool.query(`SELECT value FROM owner_config WHERE key = 'owner_hash'`);
    if (existing.rows.length) return res.status(409).json({ error: 'already_set' });
    const hash = await bcrypt.hash(key, BCRYPT_ROUNDS);
    await pool.query(`INSERT INTO owner_config(key, value) VALUES('owner_hash', $1)`, [hash]);
    res.json({ ok: true });
  } catch (e) {
    console.error('[setup]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/setup/status', async (req, res) => {
  try {
    const r = await pool.query(`SELECT 1 FROM owner_config WHERE key='owner_hash'`);
    res.json({ ownerReady: r.rows.length > 0 });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    let { key, discordId } = req.body;
    key       = sanitize(String(key       || ''), 128).trim();
    discordId = sanitize(String(discordId || ''), 20).trim();

    if (!key) return res.status(400).json({ error: 'invalid_key' });
    if (discordId && !/^\d{15,20}$/.test(discordId))
      return res.status(400).json({ error: 'invalid_discord' });

    const ownerRow = await pool.query(`SELECT value FROM owner_config WHERE key='owner_hash'`);
    if (ownerRow.rows.length) {
      const match = await bcrypt.compare(key, ownerRow.rows[0].value);
      if (match) {
        const token = jwt.sign(
          { role: 'owner', tier: 'lifetime', rsc: true, discordId },
          JWT_SECRET, { expiresIn: '12h' }
        );
        return res.json({ token, role: 'owner', tier: 'lifetime', rockstarCodeAccess: true });
      }
    }

    const keysRes = await pool.query(
      `SELECT id, key_hash, tier, discord_id_preset, locked_discord,
              rockstar_code_access, revoked
       FROM license_keys WHERE revoked = FALSE`
    );

    let matched = null;
    for (const row of keysRes.rows) {
      if (await bcrypt.compare(key, row.key_hash)) { matched = row; break; }
    }

    if (!matched) return res.status(401).json({ error: 'invalid_key' });
    if (matched.revoked) return res.status(401).json({ error: 'revoked' });
    if (matched.discord_id_preset && matched.discord_id_preset !== discordId)
      return res.status(401).json({ error: 'discord_mismatch' });
    if (matched.locked_discord && matched.locked_discord !== discordId)
      return res.status(401).json({ error: 'discord_mismatch' });

    if (!matched.discord_id_preset && !matched.locked_discord && discordId) {
      await pool.query(`UPDATE license_keys SET locked_discord=$1 WHERE id=$2`, [discordId, matched.id]);
    }

    await pool.query(`UPDATE license_keys SET uses=uses+1, last_used_at=NOW() WHERE id=$1`, [matched.id]);

    const token = jwt.sign(
      { role: 'user', tier: matched.tier, rsc: matched.rockstar_code_access, discordId },
      JWT_SECRET, { expiresIn: '12h' }
    );
    res.json({ token, role: 'user', tier: matched.tier, rockstarCodeAccess: matched.rockstar_code_access });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/stock/counts', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`SELECT type, COUNT(*) AS cnt FROM stock GROUP BY type`);
    const out = Object.fromEntries(SERVICE_TYPES.map(t => [t, 0]));
    r.rows.forEach(row => { out[row.type] = parseInt(row.cnt); });
    res.json(out);
  } catch (e) {
    console.error('[stock/counts]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/stock/generate', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    let { type, count } = req.body;
    if (!SERVICE_TYPES.includes(type)) return res.status(400).json({ error: 'invalid_type' });
    count = Math.max(1, Math.min(50, parseInt(count) || 1));

    const { discordId, tier } = req.user;
    const userId = discordId || 'anon_' + req.ip;
    const limit  = TIER_LIMITS[tier] || 10;

    await client.query('BEGIN');
    await client.query(
      `INSERT INTO daily_usage(discord_id, date, count) VALUES($1, CURRENT_DATE, 0)
       ON CONFLICT (discord_id, date) DO NOTHING`, [userId]
    );
    const usageRow = await client.query(
      `SELECT count FROM daily_usage WHERE discord_id=$1 AND date=CURRENT_DATE`, [userId]
    );
    const used = parseInt(usageRow.rows[0]?.count || 0);
    if (used >= limit) { await client.query('ROLLBACK'); return res.status(429).json({ error: 'daily_limit' }); }

    const take = Math.min(count, limit - used);
    const stockRes = await client.query(
      `SELECT id, value FROM stock WHERE type=$1 ORDER BY created_at ASC LIMIT $2 FOR UPDATE SKIP LOCKED`,
      [type, take]
    );
    if (!stockRes.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'out_of_stock' }); }

    const ids   = stockRes.rows.map(r => r.id);
    const items = stockRes.rows.map(r => r.value);

    await client.query(`DELETE FROM stock WHERE id = ANY($1)`, [ids]);
    await client.query(
      `UPDATE daily_usage SET count=count+$1 WHERE discord_id=$2 AND date=CURRENT_DATE`,
      [items.length, userId]
    );
    await client.query('COMMIT');
    res.json({ items });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('[stock/generate]', e);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.post('/api/stock/add', adminMiddleware, async (req, res) => {
  try {
    let { type, lines } = req.body;
    if (!SERVICE_TYPES.includes(type)) return res.status(400).json({ error: 'invalid_type' });
    lines = sanitize(String(lines || ''), 500_000);
    const rows = lines.split('\n').map(l => l.trim()).filter(l => l && l.length <= 512);
    if (!rows.length) return res.status(400).json({ error: 'empty' });
    let added = 0;
    for (const val of rows) {
      const r = await pool.query(
        `INSERT INTO stock(type, value) VALUES($1,$2) ON CONFLICT(type,value) DO NOTHING`, [type, val]
      );
      added += r.rowCount;
    }
    res.json({ added });
  } catch (e) {
    console.error('[stock/add]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/stock/list', adminMiddleware, async (req, res) => {
  try {
    const type   = req.query.type   || '';
    const search = sanitize(req.query.search || '', 200);
    const page   = Math.max(0, parseInt(req.query.page) || 0);
    const PAGE   = 50;
    if (!SERVICE_TYPES.includes(type)) return res.status(400).json({ error: 'invalid_type' });
    const params = [type, PAGE, page * PAGE];
    let q = `SELECT id, value FROM stock WHERE type=$1`;
    if (search) { q += ` AND value ILIKE $4`; params.push('%' + search + '%'); }
    q += ` ORDER BY created_at ASC LIMIT $2 OFFSET $3`;
    const [rows, total] = await Promise.all([
      pool.query(q, params),
      pool.query(
        `SELECT COUNT(*) FROM stock WHERE type=$1${search ? ' AND value ILIKE $2' : ''}`,
        search ? [type, '%' + search + '%'] : [type]
      ),
    ]);
    res.json({ items: rows.rows, total: parseInt(total.rows[0].count) });
  } catch (e) {
    console.error('[stock/list]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.delete('/api/stock/item/:id', adminMiddleware, async (req, res) => {
  try {
    await pool.query(`DELETE FROM stock WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.delete('/api/stock/clear/:type', adminMiddleware, async (req, res) => {
  try {
    const { type } = req.params;
    if (!SERVICE_TYPES.includes(type)) return res.status(400).json({ error: 'invalid_type' });
    await pool.query(`DELETE FROM stock WHERE type=$1`, [type]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.post('/api/keys/generate', adminMiddleware, async (req, res) => {
  try {
    let { qty, tier, pcId, discordId, rockstarCodeAccess } = req.body;
    qty  = Math.max(1, Math.min(50, parseInt(qty) || 1));
    tier = VALID_TIERS.includes(tier) ? tier : 'weekly';
    pcId      = pcId      ? sanitize(String(pcId), 64)  : null;
    discordId = discordId ? sanitize(String(discordId), 20) : null;
    if (discordId && !/^\d{15,20}$/.test(discordId)) discordId = null;
    const plainKeys = [];
    for (let i = 0; i < qty; i++) {
      const plain = genKeyStr();
      const hash  = await bcrypt.hash(plain, BCRYPT_ROUNDS);
      await pool.query(
        `INSERT INTO license_keys (key_hash, tier, label, pc_id, discord_id_preset, rockstar_code_access)
         VALUES($1,$2,$3,$4,$5,$6)`,
        [hash, tier, tier.charAt(0).toUpperCase()+tier.slice(1), pcId, discordId, !!rockstarCodeAccess]
      );
      plainKeys.push(plain);
    }
    res.json({ keys: plainKeys });
  } catch (e) {
    console.error('[keys/generate]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/keys/custom', adminMiddleware, async (req, res) => {
  try {
    let { key, tier, pcId, discordId, rockstarCodeAccess } = req.body;
    key  = sanitize(String(key || ''), 128).trim();
    if (!key || key.length < 4) return res.status(400).json({ error: 'invalid_key' });
    tier = VALID_TIERS.includes(tier) ? tier : 'weekly';
    pcId      = pcId      ? sanitize(String(pcId), 64)  : null;
    discordId = discordId ? sanitize(String(discordId), 20) : null;
    if (discordId && !/^\d{15,20}$/.test(discordId)) discordId = null;
    const hash = await bcrypt.hash(key, BCRYPT_ROUNDS);
    await pool.query(
      `INSERT INTO license_keys (key_hash, tier, label, pc_id, discord_id_preset, rockstar_code_access)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [hash, tier, tier.charAt(0).toUpperCase()+tier.slice(1), pcId, discordId, !!rockstarCodeAccess]
    );
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'duplicate' });
    console.error('[keys/custom]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/keys/list', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, tier, label, pc_id, discord_id_preset, locked_discord,
              rockstar_code_access, revoked, uses, last_used_at, created_at
       FROM license_keys ORDER BY created_at DESC`
    );
    res.json({ keys: r.rows });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.patch('/api/keys/:id', adminMiddleware, async (req, res) => {
  try {
    const { revoked, rockstarCodeAccess } = req.body;
    const updates = [];
    const params  = [];
    if (typeof revoked            === 'boolean') { params.push(revoked);            updates.push(`revoked=$${params.length}`); }
    if (typeof rockstarCodeAccess === 'boolean') { params.push(rockstarCodeAccess); updates.push(`rockstar_code_access=$${params.length}`); }
    if (!updates.length) return res.status(400).json({ error: 'nothing_to_patch' });
    params.push(req.params.id);
    await pool.query(`UPDATE license_keys SET ${updates.join(',')} WHERE id=$${params.length}`, params);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.delete('/api/keys/:id', adminMiddleware, async (req, res) => {
  try {
    await pool.query(`DELETE FROM license_keys WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.get('/api/announce', authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT kind, body FROM announcements WHERE active=TRUE ORDER BY created_at DESC`
    );
    const out = {};
    r.rows.forEach(row => { out[row.kind] = sanitize(row.body, 500); });
    res.json(out);
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.post('/api/announce', adminMiddleware, async (req, res) => {
  try {
    let { kind, body } = req.body;
    if (!VALID_KINDS.includes(kind)) return res.status(400).json({ error: 'invalid_kind' });
    body = sanitize(String(body || ''), 500).trim();
    if (!body) return res.status(400).json({ error: 'empty_body' });
    await pool.query(`UPDATE announcements SET active=FALSE WHERE kind=$1`, [kind]);
    await pool.query(`INSERT INTO announcements(kind, body) VALUES($1,$2)`, [kind, body]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.delete('/api/announce/:kind', adminMiddleware, async (req, res) => {
  try {
    const { kind } = req.params;
    if (!VALID_KINDS.includes(kind)) return res.status(400).json({ error: 'invalid_kind' });
    await pool.query(`UPDATE announcements SET active=FALSE WHERE kind=$1`, [kind]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.post('/api/bugs', authMiddleware, async (req, res) => {
  try {
    let { category, title, body } = req.body;
    if (!VALID_BUG_CATS.includes(category)) category = 'Other';
    title = sanitize(String(title || ''), 120).trim();
    body  = sanitize(String(body  || ''), 2000).trim();
    if (!title || !body) return res.status(400).json({ error: 'missing_fields' });
    await pool.query(
      `INSERT INTO bug_reports(discord_id, category, title, body) VALUES($1,$2,$3,$4)`,
      [req.user.discordId || null, category, title, body]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.get('/api/bugs', adminMiddleware, async (req, res) => {
  try {
    const status   = VALID_BUG_STATUS.includes(req.query.status)   ? req.query.status   : '';
    const category = VALID_BUG_CATS.includes(req.query.category)   ? req.query.category : '';
    const page     = Math.max(0, parseInt(req.query.page) || 0);
    const PAGE     = 50;
    const wheres = [];
    const params = [];
    if (status)   { params.push(status);   wheres.push(`status=$${params.length}`); }
    if (category) { params.push(category); wheres.push(`category=$${params.length}`); }
    const where = wheres.length ? 'WHERE ' + wheres.join(' AND ') : '';
    const countParams  = [...params];
    const selectParams = [...params, PAGE, page * PAGE];
    const [rows, total] = await Promise.all([
      pool.query(
        `SELECT id, discord_id, category, title, body, status, created_at
         FROM bug_reports ${where}
         ORDER BY created_at DESC LIMIT $${selectParams.length-1} OFFSET $${selectParams.length}`,
        selectParams
      ),
      pool.query(`SELECT COUNT(*) FROM bug_reports ${where}`, countParams),
    ]);
    res.json({ reports: rows.rows, total: parseInt(total.rows[0].count) });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.patch('/api/bugs/:id', adminMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    if (!VALID_BUG_STATUS.includes(status)) return res.status(400).json({ error: 'invalid_status' });
    await pool.query(`UPDATE bug_reports SET status=$1 WHERE id=$2`, [status, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.delete('/api/bugs', adminMiddleware, async (req, res) => {
  try {
    await pool.query(`DELETE FROM bug_reports`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.post('/api/guide/upload/:category/:kind', adminMiddleware, uploadLimiter,
  upload.single('file'), async (req, res) => {
    try {
      const { category, kind } = req.params;
      const validCats = ['steam','rockstar','discord','generator'];
      if (!validCats.includes(category) || !['video','picture'].includes(kind))
        return res.status(400).json({ error: 'invalid_params' });
      if (!req.file) return res.status(400).json({ error: 'no_file' });
      await pool.query(
        `INSERT INTO guide_media(category, kind, filename, mime_type, size_bytes, data)
         VALUES($1,$2,$3,$4,$5,$6)
         ON CONFLICT(category, kind)
         DO UPDATE SET filename=$3, mime_type=$4, size_bytes=$5, data=$6, created_at=NOW()`,
        [category, kind, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer]
      );
      res.json({ ok: true });
    } catch (e) {
      console.error('[guide/upload]', e);
      res.status(500).json({ error: 'server_error' });
    }
  }
);

app.get('/api/guide/:category/:kind', authMiddleware, async (req, res) => {
  try {
    const { category, kind } = req.params;
    const r = await pool.query(
      `SELECT mime_type, size_bytes, data FROM guide_media WHERE category=$1 AND kind=$2`,
      [category, kind]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });
    const { mime_type, data } = r.rows[0];
    res.setHeader('Content-Type', mime_type);
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.send(data);
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api/', (req, res) => res.status(404).json({ error: 'not_found' }));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async () => {
  try {
    await initSchema();
    await pool.query(`ALTER TABLE guide_media ADD COLUMN IF NOT EXISTS data BYTEA;`).catch(() => {});
    app.listen(PORT, () => console.log(`[server] MAX SHOP listening on :${PORT}`));
  } catch (e) {
    console.error('[boot]', e);
    process.exit(1);
  }
})();