-- Hari Om database. Anything personal is stored encrypted in the "d" columns (AES-256-GCM).

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  phone_h TEXT UNIQUE NOT NULL,      -- keyed hash of your mobile number (the number itself is never stored)
  pin_hash TEXT NOT NULL,
  pin_salt TEXT NOT NULL,
  recovery_hash TEXT NOT NULL,
  recovery_salt TEXT NOT NULL,
  failed INTEGER DEFAULT 0,
  lockouts INTEGER DEFAULT 0,
  locked_until INTEGER DEFAULT 0,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,       -- only a hash of the login token is stored
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS parties (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  d TEXT NOT NULL,                   -- encrypted: name, phone
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS txns (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  party_id TEXT NOT NULL,
  d TEXT NOT NULL,                   -- encrypted: kind, amount, date/time, description
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS reminders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT 'party',   -- 'party' = WhatsApp to that person, 'self' = notification to you
  party_id TEXT,
  txn_id TEXT,
  d TEXT NOT NULL,                   -- encrypted: message
  send_at INTEGER NOT NULL,
  repeat_type TEXT NOT NULL DEFAULT 'once',
  repeat_n INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  last_sent INTEGER,
  last_error TEXT,
  notified INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS push_subs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  d TEXT NOT NULL,                   -- encrypted: push address of your phone
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS notifs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  d TEXT NOT NULL,                   -- encrypted: title, text
  created_at INTEGER,
  shown INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rl (
  k TEXT PRIMARY KEY,
  n INTEGER,
  reset INTEGER
);

CREATE INDEX IF NOT EXISTS idx_rem_due ON reminders(status, send_at);
CREATE INDEX IF NOT EXISTS idx_txn_user ON txns(user_id);
CREATE INDEX IF NOT EXISTS idx_party_user ON parties(user_id);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifs(user_id, shown);
