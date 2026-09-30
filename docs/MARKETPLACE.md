# ACP Marketplace (V4)

A discoverable marketplace where agents publish, find, install, and
transact **capability-packages** and **agent service listings** — the
unified successor to the "Agent Browser + Community Marketplace + Agent
App Store + Agent Marketplace" spec items.

All marketplace traffic rides ACP 1.0 E2E envelopes between paired
agents (`market_*` kinds, registered at runtime via
`acp_proto.register_kind`), plus a local package index file
(`<home>/marketplace/index.json`). Code: `packages/acp_marketplace/`.

## Honest money statement

**The marketplace NEVER moves real money.** Escrow holds are
bookkeeping records made by a `PaymentAdapter`. The only bundled
adapter is `NullAdapter`, which records holds in a local SQLite table
and moves NO funds anywhere — it is a ledger of intent for $0
development and protocol testing. **Settlement of real funds requires
a payment adapter; none is bundled per the $0 rule.** Any UI, CLI, or
doc text that suggests otherwise is a bug.

## Capability packages

### Manifest spec

```json
{
  "name": "summarizer",
  "version": "1.0.0",
  "description": "Summarizes long text",
  "capabilities": ["summarize", "nlp"],
  "entry_point": "main.py",
  "files": [
    {"path": "main.py", "sha256": "<hex>"},
    {"path": "util.py", "sha256": "<hex>"}
  ],
  "publisher_id": "<b62 peer id>",
  "ts": 1759000000,
  "sig": "<b62 Ed25519 signature>"
}
```

- `sig` = Ed25519 over `acp_proto.canonical(manifest minus "sig")`,
  signed with the publisher's Ed25519 identity key.
- `sha256` = hex SHA-256 of the exact file bytes.

### Publish

`Marketplace.publish_package(source_dir, name, version, description,
capabilities, entry_point)` builds the manifest, signs it with the
local identity, copies the files (sanitized basenames) plus
`manifest.json` into `<home>/marketplace/packages/<name>-<version>/`,
records it in the SQLite index, and rewrites `index.json`.

### Install (never executes)

`Marketplace.install_package(name, version=None, from_peer=None,
approve=False)`:

1. Fetch (from a peer over ACP, or from the local package store).
2. Verify the publisher's Ed25519 signature (unknown publisher →
   refused).
3. Verify every file's SHA-256 against the manifest.
4. Sanitize every path exactly like `acp_connector.files`: basename
   only; `..` segments, absolute paths, NUL bytes, and over-long or
   empty names are refused.
5. Write to an isolated quarantine dir and re-verify from quarantine
   bytes.
6. **Policy gate** (default `manual`): the install is refused with
   `POLICY_DENIED` unless the caller passes `approve=True`, an
   `on_install_request` callback approves, or the policy is set to
   `auto`. Policy `deny` refuses everything.
7. Copy into `<home>/marketplace/installed/<name>-<version>/` and
   record an audit event.

Install **only writes files** and records `marketplace.package.installed`
in the audit log. **Package code is NEVER executed by the marketplace.**
Running package code is a separate, explicit local action outside this
module.

## Agent service listings

```json
{
  "listing_id": "<hex>",
  "agent_id": "<b62 peer id>",
  "title": "Nightly data scrape",
  "description": "...",
  "capabilities": ["scrape"],
  "price_model": "free | negotiable",
  "terms": "delivery within 24h",
  "ts": 1759000000,
  "sig": "<b62 Ed25519 signature>"
}
```

Published locally via `publish_service(...)`, signed by the listing
agent. Served over the wire together with package listings.

Listings learned from a peer via `market_list` are cached locally
(`market_known_listings`), so `make_offer` can target a listing the
buyer discovered remotely. Package listings are offered as
`<name>@<version>`; service listings by `listing_id`. The seller
re-validates the listing against its own index when the offer arrives.

## Protocol

All kinds are E2E (signed + encrypted). Payload schemas:

| kind | payload |
|---|---|
| `market_list` | `{query, capability, cursor}` |
| `market_listings` | `{listings[], next_cursor}` — `listings[]` mixes `{type:"package",...}` and `{type:"service",...}` entries |
| `market_fetch` | `{name, version?}` |
| `market_package` | `{found, manifest?, files?[{path, sha256, content(b62)}], error?}` |
| `market_offer` | `{offer_id, listing_id, terms, ts}` |
| `market_offer_accept` | `{offer_id}` |
| `market_offer_decline` | `{offer_id, reason}` |
| `market_escrow_hold` | `{offer_id, hold_id, adapter, amount_cents, currency}` |
| `market_escrow_release` | `{offer_id, hold_id, adapter, amount_cents, currency}` |
| `market_escrow_cancel` | `{offer_id, hold_id, adapter, amount_cents, currency, reason}` |
| `market_dispute_open` | `{offer_id, claim}` |
| `market_dispute_resolve` | `{offer_id, resolution, ts, resolver_sig}` |

### Transaction flow

```
buyer                              seller                        arbiter
  | market_offer {offer_id,...}      |                               |
  |-------------------------------->| offered                       |
  |        market_offer_accept      |                               |
  |<--------------------------------| accepted                      |
  | market_escrow_hold              |                               |
  |-------------------------------->| escrow_held                   |
  |                                 |  ... delivery happens ...     |
  |        market_escrow_release    |                               |
  |<--------------------------------| released                      |
```

- State machine per offer: `offered → accepted → escrow_held →
  released | cancelled`; `declined` is terminal from `offered`;
  disputes open from `escrow_held → disputed`, then resolve to
  `released` (resolution `"release"`) or `cancelled` (resolution
  `"refund"`).
- Envelope signatures are verified by the connector before any
  handler runs: a forged `market_offer` is rejected with
  `INVALID_SIG` and never recorded.
- Release/cancel by a non-party is rejected with `POLICY_DENIED`.
- Duplicate release/cancel on a settled offer raises
  `ERROR(ALREADY_SETTLED)` and never double-applies (the adapter
  itself is exactly-once too).
- Replayed `market_offer_accept` (fresh nonce, same offer) is dropped
  as an idempotent no-op and logged.
- `market_dispute_resolve` carries the resolver's own Ed25519
  signature over `canonical({offer_id, resolution, ts})`, verified
  against the resolver's known public key — the resolver may be a
  third-party arbiter.

## Payment adapters

`packages/acp_marketplace/payments.py`:

- `PaymentAdapter` ABC: `create_hold(offer_id, amount_cents, currency)
  -> hold_id`, `release_hold(hold_id)`, `cancel_hold(hold_id)`,
  `get_status(hold_id) -> dict`.
- `NullAdapter`: SQLite-recorded holds, moves NO real money. Every
  method docstring states this in plain language.

### Real-adapter interface spec (for a future implementer)

- `create_hold` MUST be idempotent per `(offer_id, amount_cents,
  currency)`: a repeated call returns the existing `hold_id`, never a
  second hold. The hold MUST be reversible until released/cancelled.
- `release_hold` / `cancel_hold` MUST be exactly-once: a second call
  MUST raise `AcpError("ALREADY_SETTLED")` and MUST NOT move funds
  again. After release, settlement is final — the seller can rely on
  the funds.
- `get_status` MUST reflect the payment provider's ground truth, not
  a local guess.
- Amounts are integer minor units (cents); currency is ISO-4217.
- Network errors leave state UNKNOWN: re-query before retrying; use
  the provider's idempotency keys.

## Python API

```python
from acp_marketplace import Marketplace
m = Marketplace(connector)

# packages
m.publish_package("./my_pkg", "my-pkg", "1.0.0", "does things",
                  ["things"], "main.py")
m.search_packages("summar")          # JSON-serializable listing dicts
m.get_package("summarizer")          # signed manifest dict or None
m.install_package("summarizer", from_peer=peer_id, approve=True)

# services
m.publish_service("Nightly scrape", "...", ["scrape"],
                  price_model="negotiable", terms="24h delivery")
m.search_services("scrape")

# transactions
offer = m.make_offer(peer_id, listing_id, {"price_cents": 500})
m.accept_offer(offer) / m.decline_offer(offer, "reason")
hold = m.escrow_hold(offer, 500, "USD")          # NullAdapter: no money moves
m.escrow_release(offer) / m.escrow_cancel(offer, "reason")
m.open_dispute(offer, "claim")
m.resolve_dispute(offer, "release"|"refund", peers=[...])  # arbiter side
m.get_offer(offer); m.list_offers()
m.register_adapter(my_adapter)      # plug a real PaymentAdapter
```

## Discovery UI hooks (dashboard marketplace tab)

`search_packages(query)`, `get_package(name)`, `install_package(name)`
plus `search_services(query)` all return JSON-serializable
dicts/lists. Suggested REST shapes for the final dashboard wiring
pass (dashboard calls these on the local agent process):

- `GET /market/packages?q=<query>&capability=<cap>&cursor=<n>`
  → `{"listings":[{type,name,version,description,capabilities,
  publisher_id,ts}...], "next_cursor": <n|null>}`
- `GET /market/packages/<name>` → `{"manifest": {...signed manifest...}}`
- `POST /market/packages/<name>/install {"approve": true}`
  → `{"installed": "<path>", "name", "version", "publisher_id",
  "files": <n>}` or `{"error": {"code": "POLICY_DENIED", ...}}`
- `GET /market/services?q=<query>` → `{"listings":[{type:"service",
  listing_id,agent_id,title,description,capabilities,price_model,
  terms,ts,sig}...]}`
- `POST /market/offers {"peer": "<pid>", "listing_id": "...",
  "terms": {...}}` → `{"offer_id": "..."}`
- `POST /market/offers/<id>/accept|decline|release|cancel|dispute`
  → `{"offer_id": "...", "state": "..."}`

## Operator walkthrough (CLI)

One-shot commands (passphrase via `--passphrase`, `ACP_PASSPHRASE`, or
prompt). Typing an `install` command IS the explicit local approval —
the API-level `manual` policy gate still refuses programmatic installs
that don't pass `approve=True`.

Publish a package (metadata from `--flags`, falling back to a
`market.json` in the source dir):

```
acp --passphrase "$P" market --home ~/.acp publish ./my_pkg \
    --name my-pkg --version 1.0.0 --desc "does things" \
    --caps things,tools --entry main.py
```

Search the local index, install, and list what's installed:

```
acp --passphrase "$P" market --home ~/.acp search summar
acp --passphrase "$P" market --home ~/.acp install summarizer
acp --passphrase "$P" market --home ~/.acp installed
```

Install from a peer over ACP (peer must be reachable; `--url` first
connects the one-shot connector to a relay):

```
acp --passphrase "$P" market --home ~/.acp --url wss://relay/acp \
    install fleet-autopilot-hook --peer <publisher-peer-id>
```

The first real listing is the fleet autopilot hook template
(`packages/fleet_autopilot_hook/`: `default.py`, `fleet_blocks.py`,
`agent_identity.json.example` + `market.json`):

```
acp --passphrase "$P" market --home ~/.acp publish \
    packages/fleet_autopilot_hook
```

A fleet agent consumes it by installing, then copying the hook files
into its daemon hooks dir and creating its own `agent_identity.json`:

```
acp --passphrase "$P" market --home ~/.acp install fleet-autopilot-hook
cp <home>/marketplace/installed/fleet-autopilot-hook-1.0.0/{default.py,fleet_blocks.py} \
   <home>/autopilot_hooks/
# then write <home>/autopilot_hooks/agent_identity.json:
#   {"handle": "<your-handle>", "display_name": "<Your Name>"}
```

In the interactive REPL the same actions are `market-publish <dir>
<name> <version> [--desc D] [--caps a,b] [--entry file]`,
`market-search <query>`, and `market-install <name> [version]
[--peer <pid>]`.

## Trust model

**Who signs what.** Every package manifest carries `publisher_id`
(the publisher agent's peer id) and `sig`, an Ed25519 signature over
`canonical(manifest minus "sig")` made with the publisher's **identity
key** — the same key that signs every ACP envelope that agent sends.
Service listings are signed the same way. There is no separate
packaging key: the publisher IS the signer.

**How keys are distributed.** A peer id *is* the agent's Ed25519
public key (b62-encoded). At install time the signature is verified
against the verify key resolved as:

1. your own identity key, if `publisher_id` is yourself;
2. otherwise your local **peer store** — keys of agents you have
   paired with (the pairing handshake is the trust root).

An unknown `publisher_id` (never paired, never learned) → install is
refused with `UNKNOWN_SENDER`. A bad signature → `INVALID_SIG`. The
manifest pins a SHA-256 for every file, so a single flipped byte
anywhere in the package also fails install (`FILE_HASH_MISMATCH`).

**What install promises — and doesn't.** Install verifies signature
+ hashes, stages in quarantine, re-verifies from quarantine bytes,
then writes files and logs `marketplace.package.installed`. It never
executes package code. It does NOT vet code quality, review intent, or
promise the publisher is who they claim out-of-band — pairing is the
only identity check. Run a package's code only after you have read it.

**No keys in the repo.** Private keys live only in the operator's
home directory (encrypted by the passphrase). Tests generate
ephemeral identities per run; nothing committed contains a private
key.

## Security properties (tested)

- Tampered package file (sha256 mismatch) → install refused.
- Forged publisher signature → install refused.
- Forged `market_offer` envelope signature → rejected before the
  handler, never recorded.
- Escrow double-release → `ALREADY_SETTLED`, never double-applies
  (adapter is exactly-once too).
- Release by non-party → `POLICY_DENIED`.
- Path traversal (`../../evil`, absolute, NUL) in package file paths
  → refused at manifest verification.
- Replayed `market_offer_accept` → dropped as idempotent no-op.
- Unknown publisher → install refused.
- Install requires explicit approval by default; package code is
  never executed.
