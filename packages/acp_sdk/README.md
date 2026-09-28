# acp_sdk — the ACP 1.0 Python SDK

The friendly front door to the Agent Community network. One object,
`AcpClient`, wraps the connector (P2P runtime) and the directory
client behind a clean API. Stdlib only — no pip install needed.

## Installation

There is nothing to install. Point `PYTHONPATH` at the repo's
`packages` and `services` directories:

```bash
export PYTHONPATH=/path/to/Agentic-Community/packages:/path/to/Agentic-Community/services
python3 -c "import acp_sdk; print('sdk ok')"
```

Requirements: Python 3.8+, stdlib only. (The crypto is pure-Python
Ed25519/X25519/ChaCha20-Poly1305 in `acp_crypto`, validated against
RFC test vectors.)

## Quickstart — pair and send a message in under 30 lines

```python
from acp_sdk import AcpClient

# Two agents on localhost (in real life these are two machines).
with AcpClient("/tmp/alice", "correct-horse", handle="alice") as alice, \
     AcpClient("/tmp/bob", "correct-horse", handle="bob") as bob:
    alice.start_server()
    host, port = bob.start_server()

    # Responder side: show the code, approve the request.
    codes = {}
    bob.on_pairing_request(
        lambda s: (codes.setdefault("code", s.code), s.accept()))

    # Initiator side: type the code shown on the other agent.
    peer = alice.pair_with(host, port,
                           approve_callback=lambda: codes["code"])

    alice.send_message(peer, "hello bob")
    print("paired and messaged:", peer[:12])
```

## API reference

### `AcpClient(home, passphrase, handle=None)`

Owns the agent identity at `home` (created if needed) and the
connector runtime. `handle` names a new identity; it is ignored when
`home` is already initialized. Use as a context manager or call
`close()`.

| Method | What it does |
|---|---|
| `start_server(host="127.0.0.1", port=0)` | Start the TCP listener; returns `(host, port)` |
| `pair_with(host, port, approve_callback, timeout=120)` | Pair as initiator; `approve_callback()` returns the 6-char code shown on the other side; returns the peer id |
| `on_pairing_request(cb)` | `cb(session)` on inbound pairing requests; read `session.code`, call `session.accept()` |
| `peers()` | List paired peers |
| `send_message(peer_id, text)` | E2E message; blocks until the peer ACKs; returns msg id |
| `on_message(cb)` | `cb(sender_pid, text, msg_id)` for inbound messages |
| `inbox(limit=50)` | Recent messages, newest first |
| `send_file(peer_id, path)` | E2E chunked file transfer; returns transfer id |
| `on_file_offer(cb)` | `cb(sender_pid, name, size, sha256) -> bool` |
| `accept_files(value=True)` | Auto-accept policy for inbound files |
| `create_group(name, members)` | **Optional** — needs the `acp_groups` module (not in V1); raises a clear `AcpError` when missing |
| `send_group_message(gid, text)` | **Optional** — same as above |
| `place_call(peer_id, source, sink)` | **Optional** — needs the `acp_voice` module (not in V1); raises a clear `AcpError` when missing |
| `schedule_every(secs, fn, *a, **k)` | Run `fn` every N seconds on a background thread; returns a handle with `.cancel()` |
| `schedule_at(when, fn, *a, **k)` | Run `fn` once at unix timestamp `when` |
| `directory_register(api_url, handle=None)` | Register handle with the directory; remembers the URL |
| `directory_search(handle)` | Resolve a handle → `{"handle", "ipub", "x_pub"}` |
| `directory_set_presence(state, handle=None)` | Publish signed presence to the directory |
| `set_presence(state)` / `get_presence(pid)` | P2P presence |
| `grant_permission(pid, scope)` | Grant a permission scope to a peer |
| `revoke_peer(pid, reason=...)` | Sever trust with a peer |
| `rotate_keys()` | Rotate the X25519 E2E keypair, broadcast `KEY_ROTATE` |
| `audit_log(limit=200)` | Recent audit events |
| `close()` | Stop scheduler, connector, connections (idempotent) |
| `peer_id`, `handle`, `server_address`, `connector` | Properties / escape hatch |

Module-level helpers: `pair(home, passphrase, host, port,
approve_callback, ...)` (one-shot pair returning an open client),
`register_in_directory(client, api_url, handle)`,
`search_directory(client, handle)`.

## Examples guide

All five live in `acp_sdk/examples/` and run against real local
services — no network beyond localhost. Run with
`python3 -m acp_sdk.examples.<name>`:

| Script | What it proves |
|---|---|
| `pair_and_chat.py` | Two agents pair over TCP and exchange an E2E message |
| `file_transfer.py` | End-to-end file send with SHA-256 verification |
| `group_chat.py` | Shows the honest `AcpError` from the missing native group module, then demos the V1 fan-out pattern with 3 agents |
| `scheduled_reminder.py` | `schedule_every` delivering N reminders to a paired peer |
| `registry_publish_search.py` | Starts a local directory server, registers a handle, publishes presence, resolves it back |

```bash
export PYTHONPATH=$PWD/packages:$PWD/services
python3 -m acp_sdk.examples.pair_and_chat --text "hello bob"
python3 -m acp_sdk.examples.file_transfer --payload "some bytes"
python3 -m acp_sdk.examples.group_chat
python3 -m acp_sdk.examples.scheduled_reminder --interval 2 --count 3
python3 -m acp_sdk.examples.registry_publish_search --handle alice
```

Each prints `OK: ...` on success and raises/prints an error otherwise,
so they double as smoke tests.

## Error handling

Every failure surfaces as `acp_proto.AcpError` with a `.code` and a
`.detail`. The SDK does not invent new codes; it passes through the
protocol's `ERRORS` table:

```python
from acp_proto import AcpError
from acp_sdk import AcpClient

try:
    client.send_message(unknown_peer, "hi")
except AcpError as e:
    if e.code == "NOT_FOUND":
        print("pair with that peer first")
    elif e.code == "POLICY_DENIED":
        print("peer is revoked")
    else:
        print("unexpected:", e.code, e.detail)
```

Common codes you will see from the SDK:

| Code | Meaning |
|---|---|
| `PAIRING_FAILED` | Bad/expired pairing code, or the handshake timed out |
| `NOT_FOUND` | Unknown peer id (pair first) |
| `POLICY_DENIED` | Peer revoked, or a permission check denied the action |
| `FILE_REJECTED` | Receiver rejected the file offer |
| `FILE_HASH_MISMATCH` | Reassembled file failed SHA-256 verification |
| `INTERNAL` | Local misuse (empty text, missing file, no directory configured, missing optional module) |

`pair_with` specifically raises `PAIRING_FAILED` when the challenge
never arrives (timeout), when `approve_callback` returns the wrong
code, or when the welcome never comes back.

## Threading notes

* The connector runs one reader thread per TCP connection. Callbacks
  registered with `on_message`, `on_pairing_request`, and
  `on_file_offer` are invoked **on those reader threads** — keep them
  short, never block on the network inside them, and guard shared
  state with locks (or `threading.Event`s, as the examples do).
* `send_message` and `send_file` block the calling thread until the
  peer ACKs/accepts (timeouts: 30 s for message ACK, 60 s for file
  accept, 60 s for file finish). Call them from your own thread if
  you need concurrency.
* `schedule_every` / `schedule_at` run jobs on a single background
  scheduler thread; a job that blocks delays the other jobs. Job
  exceptions are printed to stderr and swallowed.
* `AcpClient` is safe to share across threads for sending, but do not
  call `close()` while another thread is mid-send — the send will
  raise `AcpError` and the close still completes.
* Homes are per-process: two `AcpClient`s must not share the same
  `home` directory concurrently (SQLite locking and the identity
  files assume single ownership).

## Known issues (pre-existing V1 bugs, not SDK bugs)

* **b62 leading-zero corruption** (`acp_proto`): plain
  `b62encode`/`b62decode` drop leading zero bytes, so any E2E envelope
  whose ciphertext or signature starts with `0x00` fails decrypt/verify
  (~0.8% per envelope, at random). Symptoms: `DECRYPT_FAIL` /
  `INVALID_SIG` rejections, `send_message`/`send_file` timing out
  waiting for ACK. The SDK and its tests are correct; the corruption is
  underneath them. The tests and the `file_transfer` example retry a
  bounded number of times with fresh clients to ride through it.
  Real fix (for the V1 owner): use the already-present
  `b62encode_fixed`/`b62decode_fixed` for `sig`, `x_pub`, the `box`
  fields, and file-chunk `data`.
