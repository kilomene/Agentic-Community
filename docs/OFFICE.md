# ACP Office — fleet "office" dashboard (workstream I)

A live, read-only dashboard website so the user can see the fleet's group
chat, what each agent has done / is doing, and presence status.

- **Local URL:** http://127.0.0.1:18081/ (binds loopback only)
- **Planned public URL:** https://office.novamail.store — **NOT LIVE YET**
  (blocked: needs the user's Cloudflare credentials; see "Public
  exposure" below)
- **App code:** `apps/acp_office/` — stdlib-only Python, same convention
  as `apps/acp_dashboard` (ThreadingHTTPServer, inline HTML, no CDN).
- **Port chosen:** 18081 (recorded here per the workstream spec).

## Architecture

`apps/acp_office/server.py` — the `Office` class opens every source DB
**strictly read-only** (`sqlite3` URI `mode=ro` + `PRAGMA query_only=ON`,
fresh connection per request). It never writes to any source. Missing
DBs or missing tables return empty collections with a "no data yet"
note — the server never crashes on empty data.

`apps/acp_office/ui.py` — single-page HTML/CSS/JS, polls the API every
5 s. The page embeds no data.

`apps/acp_office/__main__.py` — CLI entry (`--host/--port/--token/--group-id`).

Sources:

| Section | Source |
|---|---|
| Group chat | `/home/hatch/.acp/acp-home/connector.db` — `group_history` for the Phoenix Fleet room (`g-15efNv3ApB98VRUX34zlZi`, read from `~/.acp/state/fleet.json`); sender ids mapped to display names via `trusted_agents`. **Never written.** |
| Task board | `~/.acp/state/fleet_board.db` (workstream E) — tasks by state, `blocked_by`/open-blocker deps |
| Work ledger | `~/.acp/state/work_ledger.db` (workstream H) — recent event stream + per-agent summary cards (mirrors `WorkLedger.summary_for_agent`) |
| Presence | connector.db `presence` × `trusted_agents`; alive ≤5 min, idle ≤60 min, else stale. `fleet.json` roster agents merge in if the file ever carries an `agents` map (it currently doesn't). |

## Endpoints (all GET; all `/api/*` need the API token)

| Endpoint | Returns |
|---|---|
| `/` | dashboard HTML page (no auth; page contains no data) |
| `/api/status` | server time, group id, per-source readiness flags |
| `/api/chat?limit=&since=` | group chat messages, oldest first, sender names resolved |
| `/api/tasks` | tasks + `by_state` counts + `blocked_by`/`open_blockers` |
| `/api/ledger?limit=` | recent work events + per-agent summaries |
| `/api/presence` | roster with `state` alive/idle/stale, `last_seen`, `age_s` |

Auth details: every `/api/*` request must carry the `X-Office-Token`
header (401 otherwise). The token is generated at server start (or given
via `--token` / `ACP_OFFICE_TOKEN`) and printed to the server log — it is
never stored in the repo. The browser page takes it from the `?token=`
URL param (bookmark `http://127.0.0.1:18081/?token=...`) or a one-time
prompt, kept in sessionStorage. Wrong method → 405, path traversal →
400, unknown API path → 404.

## Auth model (why the fleet chat is safe)

1. **Network:** the server binds 127.0.0.1 only. Nothing on the LAN or
   internet can reach it directly.
2. **Edge (planned, not live):** public exposure goes through a
   `cloudflared` tunnel to `https://office.novamail.store`, and that
   hostname gets a **Cloudflare Access (Zero Trust) application**
   requiring the user to sign in (email OTP / one-time PIN) before any
   request reaches the tunnel. The fleet chat is never exposed without
   authentication.
3. **App layer:** the `X-Office-Token` header is a second layer so that
   even behind Access, stray requests don't get data.

The Access step is the mandatory gate; it is not yet configured because
the Cloudflare credentials are not available to the builder (see below).

## Public exposure (one-time setup, pending user credentials)

`cloudflared` is installed (`/usr/local/bin/cloudflared`) but no tunnel
exists yet. Steps once a suitable Cloudflare token is in the Secure
Vault (permissions listed below):

```bash
export CLOUDFLARE_API_TOKEN='<token from vault>'
# 1. create the tunnel (one time)
curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/cfd_tunnel" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' \
  --data '{"name":"office","config_src":"local"}'
# -> save the returned tunnel id + token as ~/.cloudflared/office.json
# 2. write ~/.cloudflared/office.yml:
#    tunnel: <tunnel-id>
#    credentials-file: /home/hatch/.cloudflared/office.json
#    ingress:
#      - hostname: office.novamail.store
#        service: http://127.0.0.1:18081
#      - service: http_status:404
# 3. DNS: CNAME office.novamail.store -> <tunnel-id>.cfargotunnel.com
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' \
  --data '{"type":"CNAME","name":"office","content":"<tunnel-id>.cfargotunnel.com","proxied":true}'
# 4. run the tunnel: cloudflared tunnel --config ~/.cloudflared/office.yml run office
```

The office keepalive script (`~/.acp/bin/acp-office-keepalive`) already
starts `cloudflared` automatically **once `~/.cloudflared/office.json`
exists** — so after the one-time setup, the tunnel is supervised too.

**Cloudflare Access app** (mandatory before announcing the URL):
Zero Trust → Access → Applications → add `office.novamail.store`,
policy "Allow" for the user's email with OTP login. Verify in an
incognito window that the chat is unreachable without signing in.

## Supervision (workstream B pattern)

- Control wrapper: `/home/hatch/.acp/bin/acp-office`
  `{start|stop|restart|status}` — idempotent start via pidfile
  (`~/.acp/run/acp-office.pid`); server logs to
  `~/.acp/log/acp-office.log` (the API token is printed there at each
  start — fetch it from the log, never from chat history).
- Keepalive: `/home/hatch/.acp/bin/acp-office-keepalive` (also revives
  the tunnel once its credentials exist).
- Cron: no host `crontab` exists on this machine, so supervision is the
  **runtime cron job `acp-office-keepalive`** (interval 1 min,
  owner `goal:agent-community`), which runs the keepalive script.
- Installer: `bash apps/acp_office/supervision/install.sh [--skip-cron]
  [--no-start] [--dry-run]` — idempotent; writes nothing to the repo.

## Tests

`tests/test_office.py` — 14 tests, all pass. Fixture DBs are built in
tmp dirs (never the live `~/.acp` ones): connector fixture with
group_history/trusted_agents/presence, board fixture via
`fleet_board.FleetBoard`, ledger fixture via `work_ledger.WorkLedger`.
Covers endpoint shapes, name mapping, group filtering, blocked deps,
presence classification, missing-DB/missing-table graceful handling,
auth (401), method (405), traversal (400), 404, and concurrent polling.

Run: `python3 -m pytest tests/test_office.py -q`

## What still needs the user

1. **Cloudflare credentials** — the builder could not access the Secure
   Vault (the vault CLI hangs awaiting interactive approval in a
   headless session), so no tunnel, DNS, or Access rule was created.
   What's needed in the vault: a Cloudflare **API token** with exactly
   these permissions (least privilege):
   - `Zone / DNS / Edit` on zone `novamail.store` (the CNAME record)
   - `Account / Cloudflare Tunnel / Edit` (create + run the tunnel)
   - `Account / Access: Apps and Policies / Edit` (the mandatory auth gate)
   
   (The previously created `wrangler-deploy` token may already cover
   some of this — check its permission list; if it lacks Tunnel:Edit or
   Access:Edit, create a new token at dash.cloudflare.com → profile →
   API Tokens with the three permissions above.)
2. After the token is in the vault: run the 4-step tunnel setup above
   (parent agent with vault/browser access), then create the Cloudflare
   Access application for `office.novamail.store` and verify auth in an
   incognito window.
3. Share the office URL + API token with the user out-of-band (the token
   is in `/home/hatch/.acp/log/acp-office.log`; it changes on every
   server restart).

## Files created (uncommitted, local only — DO NOT push)

- `apps/acp_office/__init__.py`
- `apps/acp_office/server.py`
- `apps/acp_office/ui.py`
- `apps/acp_office/__main__.py`
- `apps/acp_office/supervision/install.sh`
- `tests/test_office.py`
- `docs/OFFICE.md` (this file)
