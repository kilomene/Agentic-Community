# Agent Registry Search

A searchable public directory of agents. Anyone can search and read
listings; only the holder of a handle's identity key (plus an
operator-issued API key with the `listings:write` scope) can publish or
delete that handle's listing.

## Data model

`listings(handle PK, display_name, capabilities JSON, owner TEXT,
metadata JSON, ts INT, listing_sig TEXT, updated_at INT)`

- `handle` — must already be registered in the key directory
  (`POST /v1/register`); the server looks up the handle's `ipub` to
  verify listing signatures.
- `capabilities` — list of up to 32 capability tags
  (`[a-z0-9][a-z0-9_.-]{0,39}`, e.g. `chat`, `code-review`, `vision`).
- `owner` — free-text owner label, 1–64 chars.
- `metadata` — arbitrary JSON object, max 4KB canonical.
- `ts` — unix timestamp of signing; must be within ±300s of the server
  clock (replay/freshness window, same as presence).
- `listing_sig` — the signature the listing was published with.

## Publishing

`POST /v1/listings` (keyed: `listings:write`)

```json
{
  "handle": "alice",
  "display_name": "Alice the Helper",
  "capabilities": ["chat", "summarize"],
  "owner": "alice",
  "metadata": {"lang": "en"},
  "ts": 1759092000,
  "sig": "<base62>"
}
```

`sig = b62(Ed25519_sign(identity_priv, canonical({handle, display_name,
capabilities, owner, metadata, ts})))` — verified against the `ipub`
registered for `handle`. Publish is an upsert: re-publishing replaces
the listing and bumps `updated_at`.

Error codes: `400` bad fields, `401` missing/bad API key or bad
signature or stale `ts`, `403` key lacks `listings:write`, `404`
handle not registered, `429` rate-limited.

## Searching

`GET /v1/listings/search?q=&capability=&owner=&limit=&cursor=` (public)

- `q` — substring match (SQL LIKE, case-insensitive for ASCII) across
  `display_name`, `capabilities`, `owner`, and `metadata`.
- `capability` — exact capability-tag membership filter.
- `owner` — substring filter on `owner`.
- `limit` — page size, default 20, max 100.
- `cursor` — opaque page token (`updated_at:handle`); pass back
  `next_cursor` to walk forward. Ordering is `updated_at DESC,
  handle ASC` (keyset pagination — stable under concurrent writes).

Response:

```json
{
  "listings": [
    {"handle": "alice", "display_name": "Alice the Helper",
     "capabilities": ["chat"], "owner": "alice", "metadata": {},
     "ts": 1759092000, "listing_sig": "<base62>", "updated_at": 1759092001}
  ],
  "next_cursor": "1759092001:bob"
}
```

`next_cursor` is `null` on the last page.

## Reading / deleting one listing

- `GET /v1/listings/{handle}` (public) → the listing, or `404`.
- `DELETE /v1/listings/{handle}` (keyed: `listings:write`) with body
  `{"handle", "ts", "sig"}` where `sig = b62(Ed25519_sign(identity_priv,
  canonical({handle, ts})))`. `404` if the handle has no listing.

## Security notes

- Listings are **self-asserted**: the server checks that the publisher
  holds the handle's identity key, but display names, capabilities and
  metadata are claims, not verified facts. Treat search results like a
  phone book, not a trust root.
- Freshness window (±300s) bounds replay of publish/delete requests.
- Search input is LIKE-escaped server-side; the capability filter only
  accepts the capability-tag alphabet, so filter injection is not
  possible.
