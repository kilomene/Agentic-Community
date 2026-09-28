# Group Chat (ACP 1.0 V2 extension)

`packages/acp_connector/groups.py` — class `GroupChat(connector)`.

Sender-key style end-to-end encrypted group messaging. Every member
holds the same 32-byte **group epoch key**; messages are encrypted with
it (ChaCha20-Poly1305, pure-Python `acp_crypto` — no new crypto
invented). The admin rotates the epoch key on every membership change.

## Protocol kinds

All registered at import via `acp_proto.register_kind` (see
`register_kind(name, e2e=False, schema=())` in `packages/acp_proto`):

| kind                 | protection       | payload |
|----------------------|------------------|---------|
| `group_create`       | signed plaintext | `{group_id, name, members[]}` — admin → each member |
| `group_key`          | E2E pairwise     | `{group_id, epoch, key}` — `key` is b62 of 32 random bytes, admin → each current member |
| `group_msg`          | signed plaintext | `{group_id, epoch, seq, nonce, ct}` — see encryption below |
| `group_member_add`   | signed plaintext | `{group_id, member_id}` (+`name`, `admin`, `members` so a newcomer learns the group) |
| `group_member_remove`| signed plaintext | `{group_id, member_id}` |
| `group_leave`        | signed plaintext | `{group_id}` |
| `group_admin_transfer` | signed plaintext | `{group_id, new_admin}` |

`group_msg` envelopes are signed plaintext (the kind is registered
non-E2E); confidentiality comes from the payload ciphertext, exactly as
specified. Handlers are wired with
`connector.register_kind_handler(kind, fn)` and run after the
connector's signature + replay checks.

## Message encryption

For a message at `(group_id, epoch, seq)` from `sender`:

```
pt  = canonical({text, sender, seq})
aad = canonical({group_id, epoch, seq})
ct  = ChaCha20-Poly1305(group_epoch_key, nonce12, pt, aad)
```

`canonical` is the protocol's deterministic JSON. The AAD binds the
ciphertext to its group, epoch and sequence number, so a ciphertext
cannot be replayed into another group or epoch. `seq` is a per-sender
per-group monotonic counter.

Receiver checks, in order: envelope signature (connector), sender is a
**current** member, epoch key known, AEAD decrypt succeeds, inner
`sender`/`seq` match the envelope, per-`(group, sender, seq)` replay
cache (persistent SQLite table — survives restarts). Any failure is
dropped with an audit entry (`group.msg_*`).

## Key rotation

- `create_group`: epoch 1 key generated locally, sent E2E to each member.
- `add_member` / `remove_member` / member `leave_group`: the admin
  generates a fresh epoch key and distributes it E2E to the **current**
  members only.
  - Removed member: never receives the new key → cannot read future
    messages (forward secrecy for new traffic).
  - New member: never receives old epoch keys → cannot read history.
- Continuing members keep old epoch keys locally so in-flight messages
  sent just before a rotation still decrypt. Old keys are never
  re-distributed.
- If the admin leaves, admin passes to the lexicographically smallest
  remaining member, who rotates on taking over.

Only the current admin may add/remove members or transfer admin.
Inbound control messages from anyone else are rejected
(`group.member_add_denied`, …) and audited. `add_member` to an unknown
or revoked peer raises before anything is sent.

## Persistence (SQLite, `CREATE TABLE IF NOT EXISTS`)

`group_chats` (group_id, name, admin_id, epoch), `group_members`,
`group_epoch_keys` (per-epoch keys), `group_history` (decrypted text,
same convention as V1's `messages` table), `group_seq` (send counters),
`group_replay` (replay cache).

## API

```python
from acp_connector.groups import GroupChat
g = GroupChat(connector)

gid = g.create_group("ops", [bob_pid, carol_pid])
g.send_group_message(gid, "hello all")
g.add_member(gid, dave_pid)
g.remove_member(gid, bob_pid)
g.transfer_admin(gid, carol_pid)
g.leave_group(gid)
g.list_groups()          # [{group_id, name, admin_id, epoch, ...}]
g.get_group(gid)         # + members[]
g.get_history(gid)       # [{epoch, seq, sender_id, text, ts}]
g.on_group_message(lambda gid, sender, text, seq: ...)
```

`send_group_message` fans out best-effort: every reachable member is
sent to, failures are audit-logged (`group.msg_failed`).

## Security properties & honest limitations

- A removed member keeps old epoch keys and can still read **old**
  messages they received — rotation gives forward secrecy for future
  traffic, not retroactive deletion. This is inherent to sender-key
  designs.
- Delivery is best-effort: a member offline during a rotation misses
  the new epoch key and cannot read subsequent messages until the
  admin re-sends their key (re-key request flow is not in V1 — the
  admin can trigger it by re-adding).
- Members need pairwise connectivity (each sender transmits directly
  to each member); there is no store-and-forward relay in V1.
- Group membership is by peer id; a peer that re-pairs under a new
  identity is a stranger to the group.

## CLI wiring (for the final wiring pass — `apps/acp_cli/cli.py` untouched)

Suggested commands; handlers already exist on `GroupChat`:

```
acp group create <name> <peer>...        -> GroupChat.create_group
acp group send <group-id> <text>         -> send_group_message
acp group add <group-id> <peer>          -> add_member        (admin only)
acp group remove <group-id> <peer>       -> remove_member     (admin only)
acp group leave <group-id>               -> leave_group
acp group transfer <group-id> <peer>     -> transfer_admin   (admin only)
acp group list                           -> list_groups
acp group history <group-id> [--limit N] -> get_history
acp group watch                          -> on_group_message print loop
```

`<peer>` is the b62 peer id (or a handle resolved via the directory).
`group watch` should register `on_group_message` and block printing
`[<group>] <sender-short>: <text>`.
