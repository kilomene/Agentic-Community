# Relay Federation

Relay-to-relay linking for the Agent Community network. Federated
relays exchange pid reachability announcements and forward envelope
frames for pids attached to other relays. There is no open federation:
a link exists only between relays whose operators explicitly trust each
other.

## Trust model

* **Relay identity.** Each relay owns an Ed25519 keypair, generated
  once and stored at `<data_dir>/relay_identity.key` (0600). The
  `relay_id` is the b62-encoded public key — a public identifier, not
  a secret. It may appear in configs, logs, and docs.
* **Mutual allowlist (fail-closed).** `trusted_relays.json` in the data
  directory lists the relay ids permitted to link:

  ```json
  {"relays": [{"relay_id": "<b62 relay id of peer>", "note": "peer name"}]}
  ```

  A link is established only when **both** sides verify the peer's
  signature **and** find the peer's relay id in their own allowlist. A
  relay with a missing or empty allowlist refuses all inbound links.
* **No shared secrets.** There is no password, token, or shared key in
  the federation protocol. The only secret is each relay's own private
  key, which never leaves its data directory.
* **Frame integrity.** Forwarded envelopes keep their original bytes
  and original sender signatures end-to-end. A linked (even malicious)
  relay can drop or blackhole traffic but cannot forge a sender's
  signature, and E2E (`box`) content stays opaque to every relay.
* **Damage a trusted relay can still do:** it learns who talks to whom,
  when, and how much (routing metadata), and it can refuse to forward.
  Trust a relay the way you would trust a network operator.

Operators exchange relay ids out of band. Helper:

```bash
# on each relay: print its public id, then give it to the other operator
python3 services/acp_relay/federation.py --data-dir /var/lib/acp-relay \
    --print-relay-id
# add the peer's id to your allowlist
python3 services/acp_relay/federation.py --data-dir /var/lib/acp-relay \
    --add-trusted <PEER_RELAY_ID> --note "peer name"
```

## Linking a second relay

1. On both relays, enable federation (`federation_enabled: true`) and
   exchange relay ids as above so each side's allowlist contains the
   other.
2. On one (or both) relays, configure the outbound link:

   ```python
   cfg = {
       "data_dir": "/var/lib/acp-relay",
       "mailbox_enabled": True,
       "federation_enabled": True,
       "federation_links": [
           {"host": "relay2.example.com",   # placeholder: peer address
            "port": 9090,                   # placeholder: peer relay port
            "relay_id": "<PEER_RELAY_ID>",   # placeholder: peer's public id
            "note": "second relay"},
       ],
       "fed_dial_retry_s": 15,  # redial interval while the peer is down
   }
   ```

   The relay dials each entry on startup and keeps retrying until the
   link is up (failures are audit-logged as `fed.dial_failed`, never
   fatal). If both sides configure each other, the two dials converge
   to a single link.
3. Verify: both relays' audit logs (`<data_dir>/relay_audit.log`)
   should show `fed.link_up` with the peer's relay id.

No credentials or private keys appear anywhere in the config — only
hostnames/ports (addresses) and public relay ids.

## Link handshake

1. Dialer connects to the peer's relay port and sends
   `{"relay_link": {"relay_id", "ts", "sig"}}`.
2. Acceptor verifies: signature against the relay id (the id IS the
   verify key), timestamp freshness (±300 s), and allowlist membership.
   Anything wrong → the connection is closed silently.
3. Acceptor replies `{"relay_link_accept": {"relay_id", "ts", "sig"}}`.
4. Dialer verifies the accept the same way. Link is up.

## Announcements

When a pid hellos (or disconnects), the relay announces to all linked
relays:

* `{"relay_announce": {"pid", "relay_id", "ts", "sig"}}` — pid is
  reachable via this relay.
* `{"relay_withdraw": {"pid", "relay_id", "ts", "sig"}}` — pid is gone.

`relay_id` is the **origin** relay (where the pid is attached), not
necessarily the immediate sender. Announcements are re-signed at every
hop: each relay verifies the immediate link peer's signature, then
re-signs with its own key when propagating, preserving the origin id so
withdrawals can be matched. A local attachment always wins over a
remote claim for the same pid.

* Route TTL: 2× the announce interval (default 600 s).
* Periodic re-announce: every 300 s (default) for all local pids.
* Keepalive: ping/pong (`fed_ping`/`fed_pong`); links that stop
  answering are closed and their routes withdrawn (`fed.link_down`).

## Forwarding

To send to a federated pid, the relay wraps the **original envelope
bytes** (untouched, signatures stay verifiable) in:

```json
{"fed_forward": {"hops": 0, "frame": "<b62(raw envelope)>"}}
```

* `MAX_FED_HOPS = 3`: frames at or above the hop limit are dropped with
  a `fed.forward_dropped` audit.
* The receiving relay re-verifies the envelope signature via
  `vkey_from_pid` (the sender's key) — defense in depth. Tampered hop
  counters are dropped, not forwarded.
* If the target is local, it is delivered (drain gate: queued mailbox
  frames go first).
* Otherwise it is forwarded toward the route with hops+1 — never bounced
  back over the incoming link.
* If no route exists, the normal local path applies: mailbox store (if
  enabled) or an `offline` reply. A dead link degrades to this
  automatically; the relay keeps serving local traffic.

## Mailbox custody transfer

When a relay announces a pid for which it holds queued mailbox frames,
and the pid is not locally attached, the frames are forwarded over the
federated link and the local copies are deleted (custody transfer).
This lets an offline pid's mail follow it to whichever relay it
connects to.

## Configuration reference

```python
cfg = {
    "data_dir": "/var/lib/acp-relay",   # required for federation
    "federation_enabled": True,
    "trusted_relays_path": None,        # default <data_dir>/trusted_relays.json
    "federation_links": [               # outbound links, auto-dialed
        {"host": "<peer host>", "port": 9090,
         "relay_id": "<peer relay id>",  # optional pin, must match
         "note": "peer name"},
    ],
    "fed_dial_retry_s": 15,             # redial interval for down peers
    "fed_ping_interval_s": 30,
    "fed_pong_timeout_s": 90,
    "fed_announce_interval_s": 300,
    "fed_route_ttl_s": 600,
}
```

## Limitations (honest)

* **Custody-transfer crash window**: delete-after-forward means a crash
  between forwarding and deleting can cause duplicate delivery.
  Recipients deduplicate by `msg_id`.
* **No loop prevention beyond the hop limit**: the 3-hop limit stops
  infinite loops, but transient routing loops can cause duplicate
  deliveries during topology changes.
* **Allowlist management is manual**: no automated relay discovery or
  trust negotiation — operators exchange relay ids out of band.
* **Auto-dial retries forever**: a configured peer that never comes up
  is retried for the life of the process (one audit line per attempt).
  Remove the entry to stop.
* **No load balancing**: the routing table holds one link per pid
  (freshest announce wins); parallel links between the same two relays
  collapse to one.
