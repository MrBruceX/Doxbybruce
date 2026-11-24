// db.js — pool + schema init
'use strict';
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS owner_config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS license_keys (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash             TEXT UNIQUE NOT NULL,
  tier                 TEXT NOT NULL DEFAULT 'weekly',
  label                TEXT NOT NULL DEFAULT 'Weekly',
  pc_id                TEXT,
  discord_id_preset    TEXT,
  locked_discord       TEXT,
  rockstar_code_access BOOLEAN NOT NULL DEFAULT FALSE,
  revoked              BOOLEAN NOT NULL DEFAULT FALSE,
  uses                 INTEGER NOT NULL DEFAULT 0,
  last_used_at         TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stock (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type       TEXT NOT NULL,
  value      TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(type, value)
);
CREATE INDEX IF NOT EXISTS idx_stock_type ON stock(type);

CREATE TABLE IF NOT EXISTS daily_usage (
  discord_id  TEXT NOT NULL,
  date        DATE NOT NULL DEFAULT CURRENT_DATE,
  count       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (discord_id, date)
);

CREATE TABLE IF NOT EXISTS announcements (
  id         SERIAL PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('announcement','stock_update')),
  body       TEXT NOT NULL,
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bug_reports (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  discord_id  TEXT,
  username    TEXT,
  category    TEXT NOT NULL DEFAULT 'Other',
  title       TEXT NOT NULL,
  body        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','closed')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS guide_media (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category    TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('video','picture')),
  filename    TEXT NOT NULL,
  mime_type   TEXT NOT NULL,
  size_bytes  BIGINT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(category, kind)
);
`;

async function initSchema() {
  const client = await pool.connect();
  try {
    await client.query(SCHEMA);
    console.log('[db] schema ready');
  } finally {
    client.release();
  }
}

module.exports = { pool, initSchema };