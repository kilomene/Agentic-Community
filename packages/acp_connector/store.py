"""SQLite persistence for acp_connector.

Follows docs/SCHEMA.md (connector DB) with two deliberate deviations,
both required by the connector build spec:
  - no ``identity`` table: private keys live in home_dir/identity.key
    (see identity.py), encrypted at rest.
  - ``families`` carries the family.py model directly (relation, notes,
    visible_to JSON) instead of the families/family_members join.

Thread-safe: every method serializes on a single re-entrant lock.
"""
import json
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trusted_agents(
  agent_id     TEXT PRIMARY KEY,
  display_name TEXT, platform TEXT,
  ed_pub       TEXT, x_pub TEXT,
  capabilities TEXT,
  paired_at    INTEGER NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0,
  revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS pairing_sessions(
  session_id TEXT PRIMARY KEY,
  role       TEXT NOT NULL,
  peer_id    TEXT,
  code_hash  TEXT,
  expires_at INTEGER NOT NULL,
  state      TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connections(
  peer_id    TEXT PRIMARY KEY,
  transport  TEXT NOT NULL,
  address    TEXT,
  state      TEXT NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS permissions(
  agent_id   TEXT NOT NULL,
  scope      TEXT NOT NULL,
  granted    INTEGER NOT NULL,
  context    TEXT,
  granted_by TEXT NOT NULL,
  expires_at INTEGER,
  PRIMARY KEY(agent_id, scope)
);
CREATE TABLE IF NOT EXISTS families(
  family_id  TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  relation   TEXT NOT NULL DEFAULT '',
  notes      TEXT NOT NULL DEFAULT '',
  visible_to TEXT NOT NULL DEFAULT '[]',
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS projects(
  project_id  TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT,
  created_by  TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks(
  task_id     TEXT PRIMARY KEY,
  project_id  TEXT NOT NULL,
  title       TEXT NOT NULL,
  description TEXT,
  owner       TEXT,
  status      TEXT NOT NULL DEFAULT 'pending',
  priority    INTEGER NOT NULL DEFAULT 0,
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transfers(
  transfer_id TEXT PRIMARY KEY,
  direction   TEXT NOT NULL,
  peer_id     TEXT NOT NULL,
  name        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  chunk_size  INTEGER NOT NULL,
  count       INTEGER NOT NULL,
  received    INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL,
  path        TEXT,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages(
  message_id   TEXT PRIMARY KEY,
  sender_id    TEXT NOT NULL,
  scope        TEXT NOT NULL,
  scope_id     TEXT,
  text         TEXT NOT NULL,
  timestamp    INTEGER NOT NULL,
  status       TEXT NOT NULL DEFAULT 'delivered',
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE TABLE IF NOT EXISTS presence(
  agent_id   TEXT PRIMARY KEY,
  status     TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs(
  event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp  INTEGER NOT NULL,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  target     TEXT,
  result     TEXT NOT NULL,
  details    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
"""


def _row(r):
    return dict(r) if r is not None else None


class Store:
    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def close(self):
        with self._lock:
            self._db.commit()
            self._db.close()

    # ---------------------------------------------------------------- peers
    def add_peer(self, agent_id, display_name, ed_pub, x_pub, platform="",
                 capabilities=None, paired_at=None):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO trusted_agents(agent_id, display_name,"
                " platform, ed_pub, x_pub, capabilities, paired_at, revoked,"
                " revoke_reason) VALUES (?,?,?,?,?,?,?,0,NULL)",
                (agent_id, display_name, platform, ed_pub, x_pub,
                 json.dumps(capabilities or {}), paired_at or int(time.time())))
            self._db.commit()

    def get_peer(self, agent_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM trusted_agents WHERE agent_id=?",
                (agent_id,)).fetchone())

    def list_peers(self, include_revoked=False):
        with self._lock:
            q = "SELECT * FROM trusted_agents"
            if not include_revoked:
                q += " WHERE revoked=0"
            return [_row(r) for r in self._db.execute(q).fetchall()]

    def update_peer_keys(self, agent_id, ed_pub, x_pub):
        with self._lock:
            self._db.execute(
                "UPDATE trusted_agents SET ed_pub=?, x_pub=? WHERE agent_id=?",
                (ed_pub, x_pub, agent_id))
            self._db.commit()

    def set_peer_revoked(self, agent_id, reason):
        """Tombstone: keep the row, drop the keys."""
        with self._lock:
            self._db.execute(
                "UPDATE trusted_agents SET revoked=1, revoke_reason=?,"
                " ed_pub=NULL, x_pub=NULL WHERE agent_id=?",
                (reason, agent_id))
            self._db.commit()

    # ---------------------------------------------------------- connections
    def set_connection(self, peer_id, transport, address, state):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO connections(peer_id, transport,"
                " address, state, last_seen) VALUES (?,?,?,?,?)",
                (peer_id, transport, address, state, int(time.time())))
            self._db.commit()

    def get_connection(self, peer_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM connections WHERE peer_id=?",
                (peer_id,)).fetchone())

    def del_connection(self, peer_id):
        with self._lock:
            self._db.execute("DELETE FROM connections WHERE peer_id=?",
                             (peer_id,))
            self._db.commit()

    # ----------------------------------------------------- pairing sessions
    def save_pairing_session(self, session_id, role, peer_id, code_hash,
                             expires_at, state, created_at):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO pairing_sessions(session_id, role,"
                " peer_id, code_hash, expires_at, state, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (session_id, role, peer_id, code_hash, expires_at, state,
                 created_at))
            self._db.commit()

    def get_pairing_session(self, session_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM pairing_sessions WHERE session_id=?",
                (session_id,)).fetchone())

    def update_pairing_session(self, session_id, **fields):
        allowed = {"peer_id", "code_hash", "expires_at", "state"}
        sets = [f"{k}=?" for k in fields if k in allowed]
        if not sets:
            return
        with self._lock:
            self._db.execute(
                f"UPDATE pairing_sessions SET {', '.join(sets)}"
                " WHERE session_id=?",
                [fields[k] for k in fields if k in allowed] + [session_id])
            self._db.commit()

    def delete_pairing_session(self, session_id):
        with self._lock:
            self._db.execute("DELETE FROM pairing_sessions WHERE session_id=?",
                             (session_id,))
            self._db.commit()

    def find_pairing_session_by_peer(self, peer_id):
        """Latest non-failed session for a peer (any terminal state ok)."""
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM pairing_sessions WHERE peer_id=?"
                " AND state != 'failed' ORDER BY created_at DESC LIMIT 1",
                (peer_id,)).fetchone())

    def list_pairing_sessions(self):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM pairing_sessions ORDER BY created_at DESC"
            ).fetchall()]

    # ------------------------------------------------------------ permissions
    def set_permission(self, agent_id, scope, granted, context=None,
                       granted_by="local", expires_at=None):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO permissions(agent_id, scope, granted,"
                " context, granted_by, expires_at) VALUES (?,?,?,?,?,?)",
                (agent_id, scope, 1 if granted else 0,
                 json.dumps(context) if context is not None else None,
                 granted_by, expires_at))
            self._db.commit()

    def del_permission(self, agent_id, scope):
        with self._lock:
            self._db.execute(
                "DELETE FROM permissions WHERE agent_id=? AND scope=?",
                (agent_id, scope))
            self._db.commit()

    def del_permissions_for_agent(self, agent_id):
        with self._lock:
            self._db.execute("DELETE FROM permissions WHERE agent_id=?",
                             (agent_id,))
            self._db.commit()

    def get_permission(self, agent_id, scope):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM permissions WHERE agent_id=? AND scope=?",
                (agent_id, scope)).fetchone())

    def list_permissions(self, agent_id):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM permissions WHERE agent_id=?", (agent_id,)
            ).fetchall()]

    # ---------------------------------------------------------------- family
    def add_family(self, family_id, name, relation, notes, visible_to,
                   created_by, created_at):
        with self._lock:
            self._db.execute(
                "INSERT INTO families(family_id, name, relation, notes,"
                " visible_to, created_by, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (family_id, name, relation, notes, json.dumps(visible_to),
                 created_by, created_at))
            self._db.commit()

    def get_family(self, family_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM families WHERE family_id=?",
                (family_id,)).fetchone())

    def list_families(self):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM families ORDER BY created_at").fetchall()]

    def update_family(self, family_id, **fields):
        allowed = {"name", "relation", "notes", "visible_to"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            sets.append(f"{k}=?")
            vals.append(json.dumps(v) if k == "visible_to" else v)
        if not sets:
            return
        with self._lock:
            self._db.execute(
                f"UPDATE families SET {', '.join(sets)} WHERE family_id=?",
                vals + [family_id])
            self._db.commit()

    def delete_family(self, family_id):
        with self._lock:
            self._db.execute("DELETE FROM families WHERE family_id=?",
                             (family_id,))
            self._db.commit()

    # --------------------------------------------------------------- projects
    def add_project(self, project_id, name, description, created_by,
                    created_at):
        with self._lock:
            self._db.execute(
                "INSERT INTO projects(project_id, name, description,"
                " created_by, created_at) VALUES (?,?,?,?,?)",
                (project_id, name, description, created_by, created_at))
            self._db.commit()

    def get_project(self, project_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM projects WHERE project_id=?",
                (project_id,)).fetchone())

    def add_task(self, task_id, project_id, title, description, owner,
                 status, priority, created_by, created_at, updated_at):
        with self._lock:
            self._db.execute(
                "INSERT INTO tasks(task_id, project_id, title, description,"
                " owner, status, priority, created_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (task_id, project_id, title, description, owner, status,
                 priority, created_by, created_at, updated_at))
            self._db.commit()

    def get_task(self, task_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone())

    def list_tasks(self, project_id):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM tasks WHERE project_id=? ORDER BY created_at",
                (project_id,)).fetchall()]

    def update_task(self, task_id, **fields):
        allowed = {"title", "description", "owner", "status", "priority"}
        sets = [f"{k}=?" for k in fields if k in allowed]
        if not sets:
            return
        vals = [fields[k] for k in fields if k in allowed]
        with self._lock:
            self._db.execute(
                f"UPDATE tasks SET {', '.join(sets)}, updated_at=?"
                " WHERE task_id=?",
                vals + [int(time.time()), task_id])
            self._db.commit()

    # -------------------------------------------------------------- transfers
    def add_transfer(self, transfer_id, direction, peer_id, name, size,
                     sha256, chunk_size, count, state, path, created_at):
        with self._lock:
            self._db.execute(
                "INSERT INTO transfers(transfer_id, direction, peer_id, name,"
                " size, sha256, chunk_size, count, received, state, path,"
                " created_at) VALUES (?,?,?,?,?,?,?,?,0,?,?,?)",
                (transfer_id, direction, peer_id, name, size, sha256,
                 chunk_size, count, state, path, created_at))
            self._db.commit()

    def get_transfer(self, transfer_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM transfers WHERE transfer_id=?",
                (transfer_id,)).fetchone())

    def update_transfer(self, transfer_id, **fields):
        allowed = {"received", "state", "path", "name"}
        sets = [f"{k}=?" for k in fields if k in allowed]
        if not sets:
            return
        with self._lock:
            self._db.execute(
                f"UPDATE transfers SET {', '.join(sets)} WHERE transfer_id=?",
                [fields[k] for k in fields if k in allowed] + [transfer_id])
            self._db.commit()

    # --------------------------------------------------------------- messages
    def add_message(self, message_id, sender_id, scope, scope_id, text,
                    timestamp, status, created_at):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO messages(message_id, sender_id, scope,"
                " scope_id, text, timestamp, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (message_id, sender_id, scope, scope_id, text, timestamp,
                 status, created_at))
            self._db.commit()

    def get_message(self, message_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM messages WHERE message_id=?",
                (message_id,)).fetchone())

    def update_message(self, message_id, **fields):
        allowed = {"status", "text"}
        sets = [f"{k}=?" for k in fields if k in allowed]
        if not sets:
            return
        with self._lock:
            self._db.execute(
                f"UPDATE messages SET {', '.join(sets)} WHERE message_id=?",
                [fields[k] for k in fields if k in allowed] + [message_id])
            self._db.commit()

    def list_messages(self, limit=100):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM messages ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()]

    # --------------------------------------------------------------- presence
    def set_presence(self, agent_id, status, updated_at):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO presence(agent_id, status, updated_at)"
                " VALUES (?,?,?)", (agent_id, status, updated_at))
            self._db.commit()

    def get_presence(self, agent_id):
        with self._lock:
            return _row(self._db.execute(
                "SELECT * FROM presence WHERE agent_id=?",
                (agent_id,)).fetchone())

    def list_presence(self):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM presence").fetchall()]

    # ------------------------------------------------------------------ audit
    def add_audit(self, timestamp, actor, action, target, result, details):
        with self._lock:
            self._db.execute(
                "INSERT INTO audit_logs(timestamp, actor, action, target,"
                " result, details) VALUES (?,?,?,?,?,?)",
                (timestamp, actor, action, target, result, details))
            self._db.commit()

    def list_audit(self, limit=200):
        with self._lock:
            return [_row(r) for r in self._db.execute(
                "SELECT * FROM audit_logs ORDER BY event_id DESC LIMIT ?",
                (limit,)).fetchall()]

    # --------------------------------------------------------------------- kv
    def kv_get(self, key):
        with self._lock:
            r = self._db.execute("SELECT value FROM kv WHERE key=?",
                                 (key,)).fetchone()
            return r["value"] if r else None

    def kv_set(self, key, value):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO kv(key, value)"
                             " VALUES (?,?)", (key, value))
            self._db.commit()
