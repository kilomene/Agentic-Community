# Agent Community — SQLite Schema (V1)

Two databases, two trust domains:

- **Connector DB** (`<ACP_HOME>/connector.db`): the agent's own state —
  identity, keys (encrypted), trust, permissions, families, projects,
  transfers, mailbox, audit. Private.
- **Backend DB** (`<API_HOME>/backend.db`): registry, pairing sessions,
  offline mailbox, presence, revocation list. Public metadata only.

## Connector DB

```sql
-- This agent's identity (exactly one row)
CREATE TABLE identity(
  agent_id      TEXT PRIMARY KEY,   -- acp_agent_<16 hex>
  display_name  TEXT NOT NULL,
  platform      TEXT NOT NULL,
  ed_priv_enc   BLOB NOT NULL,      -- passphrase-encrypted
  ed_pub        TEXT NOT NULL,      -- hex
  x_priv_enc    BLOB NOT NULL,
  x_pub         TEXT NOT NULL,      -- hex
  capabilities  TEXT NOT NULL,      -- JSON object
  created_at    INTEGER NOT NULL,
  key_salt      BLOB NOT NULL       -- PBKDF2 salt
);

-- Agents we trust (paired / manually added)
CREATE TABLE trusted_agents(
  agent_id     TEXT PRIMARY KEY,
  display_name TEXT, platform TEXT,
  ed_pub       TEXT NOT NULL, x_pub TEXT NOT NULL,
  capabilities TEXT,            -- JSON
  paired_at    INTEGER NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0,
  revoke_reason TEXT
);

-- Nonce replay cache is in-memory; pairing sessions are short-lived:
CREATE TABLE pairing_sessions(
  session_id TEXT PRIMARY KEY,
  role       TEXT NOT NULL,      -- 'generator' | 'claimer'
  peer_id    TEXT,
  code       TEXT,               -- generator side only, until used
  expires_at INTEGER NOT NULL,
  state      TEXT NOT NULL,      -- pending|challenged|done|failed
  created_at INTEGER NOT NULL
);

CREATE TABLE connections(
  peer_id    TEXT PRIMARY KEY,
  transport  TEXT NOT NULL,      -- direct | relay
  address    TEXT,
  state      TEXT NOT NULL,      -- connecting|open|closed
  last_seen  INTEGER NOT NULL
);

CREATE TABLE permissions(
  agent_id   TEXT NOT NULL,
  scope      TEXT NOT NULL,
  granted    INTEGER NOT NULL,   -- 1 grant, 0 explicit deny
  context    TEXT,               -- JSON (scoped grants)
  granted_by TEXT NOT NULL,      -- 'pairing' | 'user' | agent_id
  expires_at INTEGER,
  PRIMARY KEY(agent_id, scope)
);

CREATE TABLE families(
  family_id  TEXT PRIMARY KEY,   -- family_<12 hex>
  name       TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE family_members(
  family_id TEXT NOT NULL, agent_id TEXT NOT NULL,
  role      TEXT NOT NULL,       -- owner|admin|agent|observer
  joined_at INTEGER NOT NULL,
  PRIMARY KEY(family_id, agent_id)
);

CREATE TABLE projects(
  project_id  TEXT PRIMARY KEY,  -- proj_<12 hex>
  name        TEXT NOT NULL,
  description TEXT,
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE TABLE project_members(
  project_id TEXT NOT NULL, agent_id TEXT NOT NULL,
  joined_at  INTEGER NOT NULL,
  PRIMARY KEY(project_id, agent_id)
);
CREATE TABLE tasks(
  task_id     TEXT PRIMARY KEY,   -- task_<12 hex>
  project_id  TEXT NOT NULL REFERENCES projects(project_id),
  title       TEXT NOT NULL,
  description TEXT,
  owner       TEXT,               -- agent_id or NULL
  status      TEXT NOT NULL DEFAULT 'pending',
  priority    INTEGER NOT NULL DEFAULT 0,
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE TABLE task_dependencies(
  task_id      TEXT NOT NULL, depends_on TEXT NOT NULL,
  PRIMARY KEY(task_id, depends_on)
);
CREATE TABLE artifacts(
  artifact_id TEXT PRIMARY KEY,  -- art_<12 hex>
  task_id     TEXT NOT NULL REFERENCES tasks(task_id),
  name        TEXT NOT NULL,
  version     INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  size        INTEGER NOT NULL,
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE transfers(
  transfer_id TEXT PRIMARY KEY,  -- 32 hex
  direction   TEXT NOT NULL,     -- in|out
  peer_id     TEXT NOT NULL,
  name        TEXT NOT NULL,     -- sanitized
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  chunk_size  INTEGER NOT NULL,
  count       INTEGER NOT NULL,
  received    INTEGER NOT NULL DEFAULT 0,  -- contiguous verified chunks
  state       TEXT NOT NULL,     -- offered|active|done|failed|cancelled
  path        TEXT,              -- quarantine/inbox location
  created_at  INTEGER NOT NULL
);

-- Local mailbox (inbound messages awaiting the local agent/CLI)
CREATE TABLE messages(
  message_id   TEXT PRIMARY KEY,
  sender_id    TEXT NOT NULL,
  scope        TEXT NOT NULL,    -- direct|family|project
  scope_id     TEXT,
  text         TEXT NOT NULL,
  timestamp    INTEGER NOT NULL,
  status       TEXT NOT NULL DEFAULT 'delivered', -- delivered|read|acked
  created_at   INTEGER NOT NULL
);
CREATE INDEX idx_messages_sender ON messages(sender_id);

CREATE TABLE presence(
  agent_id   TEXT PRIMARY KEY,
  status     TEXT NOT NULL,      -- online|offline|busy|paused|unknown
  updated_at INTEGER NOT NULL
);

CREATE TABLE audit_logs(
  event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp  INTEGER NOT NULL,
  actor      TEXT NOT NULL,      -- agent_id or 'local'
  action     TEXT NOT NULL,      -- e.g. pairing.approved, file.received
  target     TEXT,
  result     TEXT NOT NULL,      -- ok | denied | failed
  details    TEXT                -- JSON, never private content
);
CREATE INDEX idx_audit_time ON audit_logs(timestamp);

CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT);  -- cursors, config
```

## Backend DB (as built — public key directory, no bearer tokens)

Authentication is by Ed25519 signatures with the registered identity key,
not bearer tokens. The directory stores public keys only.

```sql
CREATE TABLE handles(
  handle TEXT PRIMARY KEY,        -- [a-z0-9_]{3,32}
  ipub BLOB NOT NULL,             -- 32-byte Ed25519 verify key
  x_pub BLOB NOT NULL,            -- 32-byte X25519 public key
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE presence(
  handle TEXT PRIMARY KEY REFERENCES handles(handle),
  state TEXT NOT NULL,            -- online|away|busy|offline
  ts INTEGER NOT NULL,
  sig TEXT NOT NULL               -- b62 signature, kept for audit
);
```

No mailbox: offline delivery is out of scope for V1 (relay returns an
offline error; the sender retries). No revocation table: revocation is
peer-to-peer via revoke_notice envelopes (see PROTOCOL.md).

Indexes follow query patterns (by recipient, by time). No over-engineering:
if a query needs a new index, add it with the query.
