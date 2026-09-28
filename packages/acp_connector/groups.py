"""E2E group chat for ACP 1.0 (sender-key style, V2 extension).

Protocol (all kinds registered via acp_proto.register_kind):

  group_create        plaintext signed  {group_id, name, members[]}  (admin -> each member)
  group_key           E2E pairwise      {group_id, epoch, key}       (admin -> each current member)
  group_msg           plaintext signed  {group_id, epoch, seq, nonce, ct}
  group_member_add    plaintext signed  {group_id, member_id, name, admin, members}
  group_member_remove plaintext signed  {group_id, member_id}
  group_leave         plaintext signed  {group_id}
  group_admin_transfer plaintext signed {group_id, new_admin}

Message encryption (group_msg): the envelope is signed plaintext; the
payload carries the ciphertext. Encryption is ChaCha20-Poly1305 under
the 32-byte group epoch key:

    pt  = canonical({text, sender, seq})
    aad = canonical({group_id, epoch, seq})
    ct  = aead_encrypt(group_epoch_key, nonce12, pt, aad)

The receiver verifies the envelope signature (connector receive path),
checks the sender is a *current* member, looks up the epoch key,
decrypts, confirms the inner sender matches the envelope sender, and
enforces a per-(group, sender, seq) replay cache.

Key rotation: the admin generates a fresh 32-byte epoch key whenever
membership changes (add / remove / leave) and distributes it via E2E
group_key to the *current* members only. A removed member never receives
the new key (forward secrecy for future messages); a new member never
receives old epoch keys (no history access). Old epoch keys are kept
locally by continuing members so in-flight messages sent just before a
rotation still decrypt; they are never re-distributed.

Admin control: only the current admin may add/remove members or
transfer admin. Violations are rejected with an audit entry.
"""
import json
import threading
import time

from acp_crypto import aead_encrypt, aead_decrypt, random_bytes
from acp_proto import (
    AcpError, b62encode, b62encode_fixed, b62decode_fixed, canonical,
    register_kind,
)

GROUP_CREATE = register_kind(
    "group_create", e2e=False, schema=("group_id", "name", "members"))
GROUP_KEY = register_kind(
    "group_key", e2e=True, schema=("group_id", "epoch", "key"))
GROUP_MSG = register_kind(
    "group_msg", e2e=False,
    schema=("group_id", "epoch", "seq", "nonce", "ct"))
GROUP_MEMBER_ADD = register_kind(
    "group_member_add", e2e=False, schema=("group_id", "member_id"))
GROUP_MEMBER_REMOVE = register_kind(
    "group_member_remove", e2e=False, schema=("group_id", "member_id"))
GROUP_LEAVE = register_kind(
    "group_leave", e2e=False, schema=("group_id",))
GROUP_ADMIN_TRANSFER = register_kind(
    "group_admin_transfer", e2e=False, schema=("group_id", "new_admin"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS group_chats(
  group_id   TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  admin_id   TEXT NOT NULL,
  epoch      INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members(
  group_id  TEXT NOT NULL,
  member_id TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, member_id)
);
CREATE TABLE IF NOT EXISTS group_epoch_keys(
  group_id    TEXT NOT NULL,
  epoch       INTEGER NOT NULL,
  key_hex     TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  PRIMARY KEY(group_id, epoch)
);
CREATE TABLE IF NOT EXISTS group_history(
  message_id TEXT PRIMARY KEY,
  group_id   TEXT NOT NULL,
  epoch      INTEGER NOT NULL,
  seq        INTEGER NOT NULL,
  sender_id  TEXT NOT NULL,
  text       TEXT NOT NULL,
  ts         INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_group_history_group
  ON group_history(group_id, created_at);
CREATE TABLE IF NOT EXISTS group_seq(
  group_id  TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  last_seq  INTEGER NOT NULL,
  PRIMARY KEY(group_id, sender_id)
);
CREATE TABLE IF NOT EXISTS group_replay(
  group_id  TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  seq       INTEGER NOT NULL,
  PRIMARY KEY(group_id, sender_id, seq)
);
"""


def _new_group_id():
    return "g-" + b62encode(random_bytes(16))


class GroupChat:
    """Sender-key E2E group messaging bound to a Connector."""

    def __init__(self, connector):
        self._c = connector
        self._lock = threading.RLock()
        self._cbs = []
        store = connector.store
        with store._lock:
            store._db.executescript(_SCHEMA)
            store._db.commit()
        c = connector
        c.register_kind_handler(GROUP_CREATE, self._on_group_create)
        c.register_kind_handler(GROUP_KEY, self._on_group_key)
        c.register_kind_handler(GROUP_MSG, self._on_group_msg)
        c.register_kind_handler(GROUP_MEMBER_ADD, self._on_member_add)
        c.register_kind_handler(GROUP_MEMBER_REMOVE, self._on_member_remove)
        c.register_kind_handler(GROUP_LEAVE, self._on_leave)
        c.register_kind_handler(GROUP_ADMIN_TRANSFER,
                                 self._on_admin_transfer)

    # ------------------------------------------------------------ callbacks
    def on_group_message(self, cb):
        """cb(group_id, sender_pid, text, seq)."""
        self._cbs.append(cb)

    # ------------------------------------------------------------ DB helpers
    def _db(self):
        return self._c.store._db

    def _get_group(self, group_id):
        r = self._db().execute(
            "SELECT * FROM group_chats WHERE group_id=?",
            (group_id,)).fetchone()
        return dict(r) if r else None

    def _members(self, group_id):
        return [r["member_id"] for r in self._db().execute(
            "SELECT member_id FROM group_members WHERE group_id=?"
            " ORDER BY joined_at", (group_id,)).fetchall()]

    def _is_member(self, group_id, pid):
        return self._db().execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND member_id=?",
            (group_id, pid)).fetchone() is not None

    def _get_epoch_key(self, group_id, epoch):
        r = self._db().execute(
            "SELECT key_hex FROM group_epoch_keys WHERE group_id=?"
            " AND epoch=?", (group_id, epoch)).fetchone()
        return bytes.fromhex(r["key_hex"]) if r else None

    def _store_epoch_key(self, group_id, epoch, key):
        with self._c.store._lock:
            self._db().execute(
                "INSERT OR REPLACE INTO group_epoch_keys(group_id, epoch,"
                " key_hex, received_at) VALUES (?,?,?,?)",
                (group_id, epoch, key.hex(), int(time.time())))
            self._db().commit()

    def _next_seq(self, group_id, sender_id):
        with self._c.store._lock:
            r = self._db().execute(
                "SELECT last_seq FROM group_seq WHERE group_id=?"
                " AND sender_id=?", (group_id, sender_id)).fetchone()
            seq = (r["last_seq"] if r else 0) + 1
            self._db().execute(
                "INSERT OR REPLACE INTO group_seq(group_id, sender_id,"
                " last_seq) VALUES (?,?,?)", (group_id, sender_id, seq))
            self._db().commit()
            return seq

    def _replay_seen(self, group_id, sender_id, seq):
        """True if (group, sender, seq) was already processed."""
        with self._c.store._lock:
            try:
                self._db().execute(
                    "INSERT INTO group_replay(group_id, sender_id, seq)"
                    " VALUES (?,?,?)", (group_id, sender_id, seq))
                self._db().commit()
                return False
            except Exception:
                self._db().rollback()
                return True

    # ------------------------------------------------------------ API: create
    def create_group(self, name, member_pids):
        """Create a group; the creator becomes admin. Returns group_id."""
        c = self._c
        if not isinstance(name, str) or not name:
            raise AcpError("INTERNAL", "name must be a non-empty string")
        members = []
        for pid in member_pids or []:
            c._require_peer(pid)  # unknown/revoked peer -> raise
            if pid != c.peer_id and pid not in members:
                members.append(pid)
        group_id = _new_group_id()
        epoch = 1
        key = random_bytes(32)
        now = int(time.time())
        with self._lock:
            with c.store._lock:
                self._db().execute(
                    "INSERT INTO group_chats(group_id, name, admin_id, epoch,"
                    " created_by, created_at) VALUES (?,?,?,?,?,?)",
                    (group_id, name, c.peer_id, epoch, c.peer_id, now))
                self._db().execute(
                    "INSERT INTO group_members(group_id, member_id, joined_at)"
                    " VALUES (?,?,?)", (group_id, c.peer_id, now))
                for pid in members:
                    self._db().execute(
                        "INSERT INTO group_members(group_id, member_id,"
                        " joined_at) VALUES (?,?,?)", (group_id, pid, now))
                self._db().commit()
            self._store_epoch_key(group_id, epoch, key)
        all_members = [c.peer_id] + members
        # Plaintext control: tell everyone the group exists...
        for pid in members:
            try:
                c._send_plain(GROUP_CREATE, pid, {
                    "group_id": group_id, "name": name,
                    "members": all_members})
            except AcpError as e:
                c.audit.log("group.create_failed", actor=pid,
                            target=group_id, result="failed",
                            details={"error": e.code})
        # ...then distribute the epoch key pairwise-E2E.
        self._distribute_key(group_id, epoch, key, members)
        c.audit.log("group.created", target=group_id, result="ok",
                    details={"name": name, "members": len(all_members)})
        return group_id

    def _distribute_key(self, group_id, epoch, key, members):
        c = self._c
        key_b62 = b62encode_fixed(key)
        for pid in members:
            try:
                c._send_e2e(GROUP_KEY, pid, {
                    "group_id": group_id, "epoch": epoch, "key": key_b62})
            except AcpError as e:
                c.audit.log("group.key_failed", actor=pid,
                            target=group_id, result="failed",
                            details={"epoch": epoch, "error": e.code})

    def _rotate_epoch(self, group_id):
        """Admin-only: new epoch key, distributed to current members."""
        c = self._c
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                raise AcpError("INTERNAL", "unknown group")
            if g["admin_id"] != c.peer_id:
                raise AcpError("POLICY_DENIED", "only the admin rotates keys")
            epoch = int(g["epoch"]) + 1
            key = random_bytes(32)
            with c.store._lock:
                self._db().execute(
                    "UPDATE group_chats SET epoch=? WHERE group_id=?",
                    (epoch, group_id))
                self._db().commit()
            self._store_epoch_key(group_id, epoch, key)
            members = [m for m in self._members(group_id)
                       if m != c.peer_id]
        self._distribute_key(group_id, epoch, key, members)
        c.audit.log("group.key_rotated", target=group_id, result="ok",
                    details={"epoch": epoch, "members": len(members) + 1})
        return epoch

    # ------------------------------------------------------------ API: send
    def send_group_message(self, group_id, text):
        """Encrypt under the current epoch key and fan out to members.

        Best-effort delivery: every reachable member is sent to; failures
        are audit-logged. Returns the message id.
        """
        c = self._c
        if not isinstance(text, str) or not text:
            raise AcpError("INTERNAL", "text must be a non-empty string")
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                raise AcpError("INTERNAL", "unknown group")
            if not self._is_member(group_id, c.peer_id):
                raise AcpError("POLICY_DENIED", "not a group member")
            epoch = int(g["epoch"])
            key = self._get_epoch_key(group_id, epoch)
            if key is None:
                raise AcpError("INTERNAL", "no epoch key for current epoch")
            seq = self._next_seq(group_id, c.peer_id)
            nonce = random_bytes(12)
            pt = canonical({"text": text, "sender": c.peer_id, "seq": seq})
            aad = canonical({"group_id": group_id, "epoch": epoch,
                             "seq": seq})
            ct = aead_encrypt(key, nonce, pt, aad)
            payload = {
                "group_id": group_id, "epoch": epoch, "seq": seq,
                "nonce": b62encode_fixed(nonce), "ct": b62encode_fixed(ct),
            }
            msg_id = "gm-" + b62encode(random_bytes(12))
            now = int(time.time())
            with c.store._lock:
                self._db().execute(
                    "INSERT OR REPLACE INTO group_history(message_id,"
                    " group_id, epoch, seq, sender_id, text, ts, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (msg_id, group_id, epoch, seq, c.peer_id, text, now,
                     now))
                self._db().commit()
            self._replay_seen(group_id, c.peer_id, seq)  # own send counts
            members = [m for m in self._members(group_id)
                       if m != c.peer_id]
        for pid in members:
            try:
                c._send_plain(GROUP_MSG, pid, payload)
            except AcpError as e:
                c.audit.log("group.msg_failed", actor=pid,
                            target=group_id, result="failed",
                            details={"seq": seq, "error": e.code})
        c.audit.log("group.msg_sent", target=group_id, result="ok",
                    details={"seq": seq, "epoch": epoch,
                             "bytes": len(text.encode("utf-8"))})
        return msg_id

    # ------------------------------------------------------------ API: admin
    def _require_admin(self, group_id):
        c = self._c
        g = self._get_group(group_id)
        if g is None:
            raise AcpError("INTERNAL", "unknown group")
        if g["admin_id"] != c.peer_id:
            raise AcpError("POLICY_DENIED",
                           "only the group admin may do that")
        return g

    def add_member(self, group_id, member_pid):
        """Admin adds a member; rotates the epoch key (new member gets only
        the new key -> no history access)."""
        c = self._c
        c._require_peer(member_pid)
        with self._lock:
            self._require_admin(group_id)
            if self._is_member(group_id, member_pid):
                raise AcpError("INTERNAL", "already a member")
            now = int(time.time())
            with c.store._lock:
                self._db().execute(
                    "INSERT INTO group_members(group_id, member_id, joined_at)"
                    " VALUES (?,?,?)", (group_id, member_pid, now))
                self._db().commit()
            g = self._get_group(group_id)
            members = self._members(group_id)
            payload = {"group_id": group_id, "member_id": member_pid,
                       "name": g["name"], "admin": g["admin_id"],
                       "members": members}
            for pid in members:
                if pid == c.peer_id:
                    continue
                try:
                    c._send_plain(GROUP_MEMBER_ADD, pid, payload)
                except AcpError as e:
                    c.audit.log("group.member_add_failed", actor=pid,
                                target=group_id, result="failed",
                                details={"error": e.code})
        # Rotation AFTER the add broadcast: the new member only ever
        # receives the new epoch key.
        self._rotate_epoch(group_id)
        c.audit.log("group.member_added", actor=member_pid,
                    target=group_id, result="ok", details={})

    def remove_member(self, group_id, member_pid):
        """Admin removes a member; rotates the epoch key (removed member
        never receives the new key -> cannot read future messages)."""
        c = self._c
        with self._lock:
            self._require_admin(group_id)
            if member_pid == c.peer_id:
                raise AcpError("INTERNAL",
                               "admin cannot remove self; transfer admin or"
                               " leave instead")
            if not self._is_member(group_id, member_pid):
                raise AcpError("INTERNAL", "not a member")
            with c.store._lock:
                self._db().execute(
                    "DELETE FROM group_members WHERE group_id=?"
                    " AND member_id=?", (group_id, member_pid))
                self._db().commit()
            members = self._members(group_id)
            for pid in members:
                if pid == c.peer_id:
                    continue
                try:
                    c._send_plain(GROUP_MEMBER_REMOVE, pid,
                                  {"group_id": group_id,
                                   "member_id": member_pid})
                except AcpError as e:
                    c.audit.log("group.member_remove_failed", actor=pid,
                                target=group_id, result="failed",
                                details={"error": e.code})
            # Tell the removed member too (signed by admin = proof).
            try:
                c._send_plain(GROUP_MEMBER_REMOVE, member_pid,
                              {"group_id": group_id,
                               "member_id": member_pid})
            except AcpError:
                pass
        self._rotate_epoch(group_id)
        c.audit.log("group.member_removed", actor=member_pid,
                    target=group_id, result="ok", details={})

    def transfer_admin(self, group_id, new_admin_pid):
        c = self._c
        with self._lock:
            self._require_admin(group_id)
            if not self._is_member(group_id, new_admin_pid):
                raise AcpError("INTERNAL", "new admin must be a member")
            with c.store._lock:
                self._db().execute(
                    "UPDATE group_chats SET admin_id=? WHERE group_id=?",
                    (new_admin_pid, group_id))
                self._db().commit()
            for pid in self._members(group_id):
                if pid == c.peer_id:
                    continue
                try:
                    c._send_plain(GROUP_ADMIN_TRANSFER, pid,
                                  {"group_id": group_id,
                                   "new_admin": new_admin_pid})
                except AcpError as e:
                    c.audit.log("group.admin_transfer_failed", actor=pid,
                                target=group_id, result="failed",
                                details={"error": e.code})
        c.audit.log("group.admin_transferred", actor=new_admin_pid,
                    target=group_id, result="ok", details={})

    def leave_group(self, group_id):
        """Leave a group. If the admin leaves, admin passes to the
        lexicographically smallest remaining member; the (new) admin
        rotates the epoch key on seeing the leave."""
        c = self._c
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                raise AcpError("INTERNAL", "unknown group")
            if not self._is_member(group_id, c.peer_id):
                raise AcpError("INTERNAL", "not a member")
            members = self._members(group_id)
            new_admin = None
            if g["admin_id"] == c.peer_id:
                remaining = sorted(m for m in members if m != c.peer_id)
                new_admin = remaining[0] if remaining else None
                if new_admin is not None:
                    with c.store._lock:
                        self._db().execute(
                            "UPDATE group_chats SET admin_id=?"
                            " WHERE group_id=?", (new_admin, group_id))
                        self._db().commit()
            with c.store._lock:
                self._db().execute(
                    "DELETE FROM group_members WHERE group_id=?"
                    " AND member_id=?", (group_id, c.peer_id))
                self._db().commit()
            for pid in members:
                if pid == c.peer_id:
                    continue
                try:
                    c._send_plain(GROUP_LEAVE, pid, {"group_id": group_id})
                except AcpError:
                    pass
                if new_admin is not None:
                    try:
                        c._send_plain(GROUP_ADMIN_TRANSFER, pid,
                                      {"group_id": group_id,
                                       "new_admin": new_admin})
                    except AcpError:
                        pass
        c.audit.log("group.left", target=group_id, result="ok",
                    details={"admin_passed_to": new_admin})

    # ------------------------------------------------------------ API: read
    def list_groups(self):
        return [dict(r) for r in self._db().execute(
            "SELECT group_id, name, admin_id, epoch, created_by, created_at"
            " FROM group_chats ORDER BY created_at").fetchall()]

    def get_group(self, group_id):
        g = self._get_group(group_id)
        if g is None:
            return None
        g["members"] = self._members(group_id)
        return g

    def get_history(self, group_id, limit=100):
        return [dict(r) for r in self._db().execute(
            "SELECT message_id, epoch, seq, sender_id, text, ts"
            " FROM group_history WHERE group_id=?"
            " ORDER BY created_at LIMIT ?", (group_id, limit)).fetchall()]

    # ------------------------------------------------------------ inbound
    def _on_group_create(self, conn, env, payload):
        c = self._c
        sender = env["from"]
        group_id = payload["group_id"]
        with self._lock:
            if self._get_group(group_id) is not None:
                return  # idempotent re-delivery
            now = int(time.time())
            members = payload["members"]
            if not isinstance(members, list) or not all(
                    isinstance(m, str) for m in members):
                raise AcpError("BAD_ENVELOPE", "group_create members not a"
                                               " list of peer ids")
            if sender not in members:
                members = [sender] + members
            with c.store._lock:
                self._db().execute(
                    "INSERT INTO group_chats(group_id, name, admin_id, epoch,"
                    " created_by, created_at) VALUES (?,?,?,?,?,?)",
                    (group_id, payload["name"], sender, 0, sender, now))
                for pid in members:
                    self._db().execute(
                        "INSERT OR IGNORE INTO group_members(group_id,"
                        " member_id, joined_at) VALUES (?,?,?)",
                        (group_id, pid, now))
                self._db().commit()
        c.audit.log("group.created_remote", actor=sender,
                    target=group_id, result="ok",
                    details={"name": payload["name"]})

    def _on_group_key(self, conn, env, payload):
        c = self._c
        sender = env["from"]
        group_id = payload["group_id"]
        try:
            epoch = int(payload["epoch"])
        except (ValueError, TypeError):
            raise AcpError("BAD_ENVELOPE", "group_key epoch not an integer")
        try:
            key = b62decode_fixed(payload["key"])
        except (ValueError, KeyError, AttributeError):
            c.audit.log("group.key_bad", actor=sender, target=group_id,
                        result="denied", details={"reason": "bad key bytes"})
            return
        if len(key) != 32:
            c.audit.log("group.key_bad", actor=sender, target=group_id,
                        result="denied", details={"reason": "bad key length"})
            return
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                c.audit.log("group.key_unknown_group", actor=sender,
                            target=group_id, result="denied", details={})
                return
            if sender != g["admin_id"]:
                # Only the admin distributes epoch keys.
                c.audit.log("group.key_not_admin", actor=sender,
                            target=group_id, result="denied",
                            details={"epoch": epoch})
                return
            self._store_epoch_key(group_id, epoch, key)
            if epoch > int(g["epoch"]):
                with c.store._lock:
                    self._db().execute(
                        "UPDATE group_chats SET epoch=? WHERE group_id=?",
                        (epoch, group_id))
                    self._db().commit()
        c.audit.log("group.key_received", actor=sender, target=group_id,
                    result="ok", details={"epoch": epoch})

    def _on_group_msg(self, conn, env, payload):
        c = self._c
        sender = env["from"]
        group_id = payload["group_id"]
        try:
            epoch = int(payload["epoch"])
            seq = int(payload["seq"])
        except (ValueError, TypeError):
            raise AcpError("BAD_ENVELOPE", "group_msg epoch/seq not integers")
        if epoch < 0 or seq < 0:
            raise AcpError("BAD_ENVELOPE", "group_msg epoch/seq negative")
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                c.audit.log("group.msg_unknown_group", actor=sender,
                            target=group_id, result="denied", details={})
                return
            if not self._is_member(group_id, sender):
                c.audit.log("group.msg_not_member", actor=sender,
                            target=group_id, result="denied",
                            details={"seq": seq})
                return
            key = self._get_epoch_key(group_id, epoch)
            if key is None:
                # No key for this epoch (e.g. joined later, or removed
                # before rotation): cannot read, drop.
                c.audit.log("group.msg_no_key", actor=sender,
                            target=group_id, result="denied",
                            details={"epoch": epoch, "seq": seq})
                return
            try:
                nonce = b62decode_fixed(payload["nonce"])
                ct = b62decode_fixed(payload["ct"])
            except (ValueError, KeyError, AttributeError):
                c.audit.log("group.msg_bad_fields", actor=sender,
                            target=group_id, result="denied", details={})
                return
            aad = canonical({"group_id": group_id, "epoch": epoch,
                             "seq": seq})
            try:
                pt = aead_decrypt(key, nonce, ct, aad)
                inner = json.loads(pt.decode("utf-8"))
                if not isinstance(inner, dict):
                    raise ValueError("inner payload not a dict")
                inner_seq = int(inner.get("seq", -1))
            except Exception:
                c.audit.log("group.msg_decrypt_fail", actor=sender,
                            target=group_id, result="denied",
                            details={"epoch": epoch, "seq": seq})
                return
            if inner.get("sender") != sender or inner_seq != seq:
                c.audit.log("group.msg_inner_mismatch", actor=sender,
                            target=group_id, result="denied",
                            details={"seq": seq})
                return
            text = inner.get("text")
            if not isinstance(text, str):
                c.audit.log("group.msg_bad_text", actor=sender,
                            target=group_id, result="denied", details={})
                return
            if self._replay_seen(group_id, sender, seq):
                c.audit.log("group.msg_replay_dropped", actor=sender,
                            target=group_id, result="denied",
                            details={"seq": seq})
                return
            msg_id = "gm-" + b62encode(random_bytes(12))
            now = int(time.time())
            with c.store._lock:
                self._db().execute(
                    "INSERT OR REPLACE INTO group_history(message_id,"
                    " group_id, epoch, seq, sender_id, text, ts, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (msg_id, group_id, epoch, seq, sender, text,
                     int(env["ts"]), now))
                self._db().commit()
        c.audit.log("group.msg_received", actor=sender, target=group_id,
                    result="ok", details={"seq": seq, "epoch": epoch})
        for cb in list(self._cbs):
            try:
                cb(group_id, sender, text, seq)
            except Exception as e:
                c.audit.log("group.callback_error", actor=sender,
                            target=group_id, result="failed",
                            details={"error": str(e)})

    def _check_admin_sender(self, env, payload, action):
        """Inbound admin-only control: sender must be the current admin."""
        c = self._c
        sender = env["from"]
        group_id = payload["group_id"]
        g = self._get_group(group_id)
        if g is None:
            c.audit.log(action, actor=sender, target=group_id,
                        result="denied",
                        details={"reason": "unknown group"})
            return None
        if sender != g["admin_id"]:
            c.audit.log(action, actor=sender, target=group_id,
                        result="denied",
                        details={"reason": "not admin",
                                 "admin": g["admin_id"]})
            return None
        return g

    def _on_member_add(self, conn, env, payload):
        c = self._c
        sender = env["from"]
        group_id = payload["group_id"]
        member_id = payload["member_id"]
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                # First contact: I am being added to a group I have
                # never seen. The announcer must be the admin it
                # claims to be, otherwise this is a forgery.
                if payload.get("admin") != sender:
                    c.audit.log("group.member_add_denied", actor=sender,
                                target=group_id, result="denied",
                                details={"reason": "unknown group,"
                                         " announcer not claimed admin"})
                    return
                now = int(time.time())
                members = payload.get("members") or []
                if not isinstance(members, list) or not all(
                        isinstance(m, str) for m in members):
                    raise AcpError("BAD_ENVELOPE", "group_member_add members"
                                                   " not a list of peer ids")
                if sender not in members:
                    members = [sender] + members
                with c.store._lock:
                    self._db().execute(
                        "INSERT INTO group_chats(group_id, name, admin_id,"
                        " epoch, created_by, created_at)"
                        " VALUES (?,?,?,?,?,?)",
                        (group_id, payload.get("name", group_id), sender,
                         0, sender, now))
                    for pid in members:
                        self._db().execute(
                            "INSERT OR IGNORE INTO group_members(group_id,"
                            " member_id, joined_at) VALUES (?,?,?)",
                            (group_id, pid, now))
                    self._db().commit()
                c.audit.log("group.joined", actor=sender,
                            target=group_id, result="ok", details={})
            else:
                if sender != g["admin_id"]:
                    c.audit.log("group.member_add_denied", actor=sender,
                                target=group_id, result="denied",
                                details={"reason": "not admin",
                                         "admin": g["admin_id"]})
                    return
            now = int(time.time())
            with c.store._lock:
                self._db().execute(
                    "INSERT OR IGNORE INTO group_members(group_id, member_id,"
                    " joined_at) VALUES (?,?,?)",
                    (group_id, member_id, now))
                self._db().commit()
        c.audit.log("group.member_added_remote", actor=sender,
                    target=group_id, result="ok",
                    details={"member": member_id})

    def _on_member_remove(self, conn, env, payload):
        c = self._c
        with self._lock:
            g = self._check_admin_sender(env, payload,
                                         "group.member_remove_denied")
            if g is None:
                return
            member_id = payload["member_id"]
            with c.store._lock:
                self._db().execute(
                    "DELETE FROM group_members WHERE group_id=?"
                    " AND member_id=?",
                    (payload["group_id"], member_id))
                self._db().commit()
        c.audit.log("group.member_removed_remote", actor=env["from"],
                    target=payload["group_id"], result="ok",
                    details={"member": member_id})

    def _on_leave(self, conn, env, payload):
        c = self._c
        sender = env["from"]
        group_id = payload["group_id"]
        with self._lock:
            g = self._get_group(group_id)
            if g is None:
                return
            with c.store._lock:
                self._db().execute(
                    "DELETE FROM group_members WHERE group_id=?"
                    " AND member_id=?", (group_id, sender))
                self._db().commit()
            c.audit.log("group.member_left", actor=sender,
                        target=group_id, result="ok", details={})
            # A member leaving is a removal: if I am the admin, rotate
            # so the leaver cannot read future messages. (If the leaver
            # was the admin, rotation happens in _on_admin_transfer
            # when the successor takes over.)
            g = self._get_group(group_id)
            if g is not None and g["admin_id"] == c.peer_id:
                try:
                    self._rotate_epoch(group_id)
                except AcpError as e:
                    c.audit.log("group.rotate_failed", target=group_id,
                                result="failed",
                                details={"error": e.code})

    def _on_admin_transfer(self, conn, env, payload):
        c = self._c
        with self._lock:
            g = self._check_admin_sender(env, payload,
                                         "group.admin_transfer_denied")
            if g is None:
                return
            new_admin = payload["new_admin"]
            if not self._is_member(payload["group_id"], new_admin):
                c.audit.log("group.admin_transfer_denied", actor=env["from"],
                            target=payload["group_id"], result="denied",
                            details={"reason": "new admin not a member"})
                return
            with c.store._lock:
                self._db().execute(
                    "UPDATE group_chats SET admin_id=? WHERE group_id=?",
                    (new_admin, payload["group_id"]))
                self._db().commit()
            became_admin = (new_admin == c.peer_id)
        c.audit.log("group.admin_transferred_remote", actor=env["from"],
                    target=payload["group_id"], result="ok",
                    details={"new_admin": new_admin})
        if became_admin:
            # I am the new admin (e.g. previous admin left): rotate so
            # the departed admin cannot read future messages.
            try:
                self._rotate_epoch(payload["group_id"])
            except AcpError as e:
                c.audit.log("group.rotate_failed",
                            target=payload["group_id"], result="failed",
                            details={"error": e.code})
