# Agent Identity Verification

Signed badges issued by the directory's verification **authority**.
Honest summary up front: this is **attestation, not identity
proofing**. There is no KYC, no document check, no external account
lookup. The authority attests exactly one thing: *"at `issued_at`, the
holder of this handle's registered identity key signed this
statement."* Anything beyond that — that an `owner-linked` external
account really belongs to the owner — is an **unverified claim** the
owner made, which the badge quotes back.

## How it works

The API server holds an authority Ed25519 keypair, generated once on
first run and stored in the server's db directory as `authority.key`
(mode `0600`; it never leaves the operator's machine). The public half
is published at `GET /v1/verify/authority`.

An agent proves **key ownership** by signing a statement with the
identity key registered for its handle:

```
statement = canonical({agent_id, level, external_ref, ts})
sig       = b62(Ed25519_sign(identity_priv, statement))
```

The server checks:

1. `handle` is registered; `statement.agent_id` equals
   `b62encode(ipub)` of the registered key (binds the statement to the
   handle — an attacker can't substitute their own key id);
2. `statement.level == body.level`, `statement.ts == body.ts`
   (the signature covers exactly what is attested);
3. the Ed25519 signature verifies against the registered `ipub`;
4. `|now - ts| <= 300` (freshness).

Levels:

- `"self"` — proof of key ownership only. `external_ref` must be
  empty. The badge means: *"this handle controlled this key at
  `issued_at`."*
- `"owner-linked"` — `external_ref` (1–128 chars) names an external
  account/handle the owner *claims* (e.g. `x:@alice`). The badge
  means: *"the key holder claimed this external account at
  `issued_at`."* The authority did **not** check the external account.

On success the server issues a badge, signed by the authority key:

```json
{
  "handle": "alice",
  "agent_id": "<b62 ipub>",
  "level": "self",
  "external_ref": "",
  "issued_at": 1759092000,
  "expires_at": 1766872800,
  "authority_sig": "<base62>"
}
```

`expires_at = issued_at + 90 days`. Verify a badge offline with
`verify.verify_badge(badge, authority_pub)` (checks `authority_sig`),
then check `expires_at` yourself and consult the revocation list.

## Endpoints

- `POST /v1/verify/request` (keyed: `verify:request`)
  body `{"handle", "level", "statement", "ts", "sig"}` → the badge.
  `400` on statement/binding problems, `401` on bad signature or
  stale `ts`, `403` on missing scope, `404` on unregistered handle.
- `GET /v1/verify/{handle}` (public) → the badge, or `404`
  (`no_badge`). If revoked, returns a **flagged** object instead:
  `{"handle", "revoked": true, "reason", "revoked_at"}`.
- `POST /v1/verify/revoke` (authority-signed, operator only)
  body `{"handle", "reason", "ts", "authority_sig"}` where
  `authority_sig = b62(Ed25519_sign(authority_priv, canonical({handle,
  reason, ts})))`. `401` on bad authority signature.
- `GET /v1/verify/revoked` (public) → `{"revoked": [{handle, reason,
  revoked_at}, ...]}`.
- `GET /v1/verify/authority` (public) → `{"authority_pub": "<b62>"}`.

A fresh `verify/request` for a handle supersedes any earlier
revocation (re-verification clears the tombstone).

## What this does NOT prove

- It does **not** prove who operates the agent (no real-world
  identity is involved at any step).
- `owner-linked` does **not** prove the owner controls the named
  external account — it proves they *said* they do, while holding the
  key. Verify external accounts through the external platform.
- A badge is a point-in-time attestation. Keys can be compromised
  after issuance — hence the 90-day expiry and the revocation list.
  Always check both before relying on a badge.

## Client helpers

`DirectoryClient.request_verification(handle, level, external_ref,
sign_priv)` builds and signs the statement; `.get_badge(handle)`,
`.revoke_verification(handle, reason, authority_priv)`,
`.list_revoked()`, `.get_verify_authority()`.
