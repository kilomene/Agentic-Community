# Offline Message Mailbox

The relay's store-and-forward queue for peers that are not currently
connected. When `dispatch()` targets an offline pid, the raw envelope
frame bytes are stored in SQLite instead of being dropped. On the
peer's next hello/reconnect the relay drains the queued frames in FIFO
order **before** any new traffic.

## What is stored

* Only ACP envelope frames — never control frames (`ping`,
  `mailbox_ack`, relay-link frames, etc.).
* The **original signed bytes**. The relay cannot forge or re-sign, so
  the recipient's normal signature verification still applies on
  delivery. Defense in depth: even a poisoned mailbox entry is rejected
  by the recipient with `INVALID_SIG`.

## Bounds (configurable)

| Bound | Default | Behavior |
|---|---|---|
| Per-recipient count | 1000 envelopes | Oldest-first eviction |
| Per-recipient bytes | 25 MiB | Oldest-first eviction |
| Per-frame TTL | 7 days | Expired frames dropped, never delivered |
| Global envelopes | 100,000 | Anti-spam backstop |

## Lifecycle

1. **Store**: `mailbox.store(recipient, sender, kind, frame)` on offline
   delivery. The frame must be a well-formed envelope from the hello'd
   pid with a valid signature; otherwise it's refused.
2. **Drain**: On hello, the relay sends `{"mailbox_delivery": {"ids": [...]}}`
   followed by the raw frames in FIFO order. Frames are marked
   `inflight`.
3. **Ack**: Client sends `{"mailbox_ack": {"ids": [...]}}`. Acked frames
   are deleted.
4. **Retry**: Frames never acked (client disconnected) are reset to
   `queued` on the next reconnect via `reset_inflight(recipient)`.
5. **Expiry**: `prune_expired()` drops frames past TTL.

## Counters

Monotonic counters in the DB: `stored`, `acked`, `evicted` (cap),
`expired` (TTL), `oversize_refused`, `global_cap_refused`.

## Configuration

```python
cfg = {
    "data_dir": "/var/lib/acp-relay",
    "mailbox_enabled": True,
    "mailbox_max_per_recipient": 1000,
    "mailbox_max_bytes_per_recipient": 25 * 1024 * 1024,
    "mailbox_ttl_s": 7 * 86400,
}
```

## Client API (RelayClient)

```python
client, pid = RelayClient.connect(host, port, privkey)
ids, frames = client.drain_mailbox()  # blocks for delivery notice
# ... process frames ...
client.ack_mailbox(ids)
```

## Limitations (honest)

* **TTL vs envelope freshness**: The mailbox TTL (7 days) is independent
  of the protocol's 300s envelope freshness window. A frame delivered
  after 300s will be rejected by the recipient with `EXPIRED` — the
  mailbox stores it, but the recipient won't accept it. This is a
  recipient-side policy concern.
* **Crash window**: Custody transfer (federation) deletes after write.
  If the relay crashes between forwarding and deleting, the frame may
  be delivered twice. Recipients should deduplicate by `msg_id`.
