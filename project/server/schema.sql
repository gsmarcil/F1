-- Sentinel service schema (Cloudflare D1 / SQLite).
-- Upgrading a database created before the fleet mesh: add the three device columns by hand, then run this file.
--   ALTER TABLE devices ADD COLUMN addresses TEXT NOT NULL DEFAULT '[]';
--   ALTER TABLE devices ADD COLUMN peers TEXT NOT NULL DEFAULT '[]';
--   ALTER TABLE devices ADD COLUMN coverage TEXT NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  platform TEXT NOT NULL,
  token_hash TEXT UNIQUE,
  respond INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '{}',
  addresses TEXT NOT NULL DEFAULT '[]',
  peers TEXT NOT NULL DEFAULT '[]',
  coverage TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  case_key TEXT NOT NULL,
  level TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open',
  detail TEXT NOT NULL,
  response TEXT,
  analysis TEXT,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  UNIQUE(device_id, case_key)
);
CREATE INDEX IF NOT EXISTS cases_open ON cases(state, last_seen_at);
-- Addresses one machine was attacked through, shared with every other machine for a week.
CREATE TABLE IF NOT EXISTS fleet_indicators (
  address TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  case_id TEXT,
  added_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS learning (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  history TEXT NOT NULL DEFAULT '[]',
  policy TEXT NOT NULL DEFAULT '{}',
  revision INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
-- Marks of requests seen by edge systems that cannot run the agent (see src/edge.mjs). Kept for fifteen minutes.
-- No request text is ever stored here: values are labels and short marks.
CREATE TABLE IF NOT EXISTS edge_marks (
  system TEXT NOT NULL,
  client TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL DEFAULT '',
  extra TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS edge_marks_client ON edge_marks(system, client, at);
