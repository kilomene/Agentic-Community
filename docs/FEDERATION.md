# Relay Federation

Relay-to-relay linking for the Agent Community network. Federated
relays exchange pid reachability announcements and forward envelope
frames for pids attached to other relays.

## Identity & Trust

Each relay has an Ed25519 identity (`relay_identity.key`, 0600
permissions) in its data directory. The `relay_id` is derived from the
public key.

**Allowlist (fail-closed)**: `trusted_relays.json` in the data directory
lists the relay IDs permitted to link. A relay with an empty or missing
allowlist refuses all inbound links. Both sides verify the peer is in
their allowlist before the link comes up.

## Link Handshake

1. Dialer connects to the peer's relay port and sends `RELAY_LINK`
   `{relay_id, ts, sig}`.
2. Acceptor verifies: signature, timestamp freshness (±60s), and
   allowlist membership.
3. Acceptor replies `RELAY_LINK_ACCEPT` with its own signed identity.
4. Dialer verifies the accept. Link is up.

Both sides verify signatures — a relay cannot impersonate another.

## Announcements

When a pid hellos (or disconnects), the relay announces to all linked
relays:

* `RELAY_ANNOUNCE` `{pid, relay_id, ts, sig}` — pid is reachable via
  this relay.
* `RELAY_WITHDRAW` `{pid, relay_id, ts, sig}` — pid is gone.

The `relay_id` is the **origin** relay (where the pid is attached), not
necessarily the immediate sender. Announcements are re-signed
transitively: each relay verifies the immediate sender's signature,
then re-signs with its own key when propagating, preserving the origin
ID so withdrawals can be matched.

Receiving relays verify the announcement signature against the link
peer's key (defense in depth). The pid→link routing table maps each
known pid to the link leading toward its origin relay.

* Route TTL: 2× the announce interval (default 600s).
* Periodic re-announce: every 300s (default) for all local pids.
* Keepalive: ping/pong; dead links are removed.

## Forwarding

To send to a federated pid, the relay wraps the **original envelope
bytes** (untouched, signatures stay verifiable) in:

```json
{"fed_forward": {"hops": 0, "frame": "<b62(raw envelope)>"}}
```

* `MAX_FED_HOPS = 3`: frames exceeding the hop limit are dropped with
  `fed.forward_dropped` audit.
* The receiving relay verifies the envelope signature via
  `vkey_from_pid` (the sender's key). E2E content stays opaque — the
  relay never decrypts.
* If the target is local, it's delivered (with the drain gate: queued
  mailbox frames go first).
* Otherwise, it's forwarded toward the route, incrementing hops. Never
  bounced back over the incoming link.

## Mailbox Custody Transfer

When a relay announces a pid for which it has queued mailbox frames,
and the pid is not locally attached, the frames are forwarded over the
federated link (custody transfer) and the local copies are deleted.
This lets an offline pid's mail follow it to whichever relay it
connects to.

## Configuration

```python
cfg = {
    "data_dir": "/var/lib/acp-relay",
    "federation_enabled": True,
    "fed_ping_interval_s": 30,
    "fed_pong_timeout_s": 90,
    "fed_announce_interval_s": 300,
    "fed_route_ttl_s": 600,
}
```

## Limitations (honest)

* **Custody-transfer crash window**: Delete-after-write means a crash
  between forwarding and deleting can cause duplicate delivery.
  Recipients deduplicate by `msg_id`.
* **No loop prevention beyond hop limit**: The 3-hop limit prevents
  infinite loops, but transient routing loops can cause duplicate
  deliveries during topology changes.
* **Allowlist management is manual**: There is no automated relay
  discovery or trust negotiation. Operators must exchange relay IDs
  out-of-band.
