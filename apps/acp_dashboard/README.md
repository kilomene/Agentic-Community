# acp_dashboard — ACP 1.0 Web Dashboard

A single-page web UI + JSON REST API for a local ACP connector. Stdlib
only (`http.server`, `sqlite3`, `urllib`-friendly JSON). No CDN, no
JavaScript frameworks, no build step — the whole UI is one self-contained
HTML page rendered by `ui.py`.

## Run it

```bash
# from the repo root
python3 apps/acp_dashboard/__main__.py --home ~/.acp --port 8765
```

Options:

| flag | default | notes |
|---|---|---|
| `--home DIR` | (required) | connector home (created if missing) |
| `--passphrase` | `ACP_PASSPHRASE` env, else prompt | unlocks the connector identity |
| `--host` | `127.0.0.1` | bind address; keep it loopback |
| `--port` | `0` | `0` = pick an ephemeral port, printed on start |
| `--token` | random 32-byte | API token, printed once if generated |
| `--lang` | `en` | default UI language (`en es fr de zh yo`) |

Then open `http://127.0.0.1:8765/` and paste the token into the unlock
box. The token lives in `sessionStorage` only — it is never baked into
the page.

Or embed it in your own process:

```python
from acp_connector import Connector
from server import Dashboard  # apps/acp_dashboard on sys.path

conn = Connector(home, passphrase, handle="me")
conn.start_server("127.0.0.1", 0)
dash = Dashboard(conn, token="secret", port=8765)
dash.start()   # serves in a daemon thread; returns the bound port
...
dash.stop()
```

## Auth

Every `/api/*` request must carry the token in the `X-ACP-Token` header
(constant-time compare). Missing/wrong token → `401
{"ok": false, "code": "UNAUTHORIZED"}`. The UI page itself (`/`) is
public; it cannot call the API without the token.

## API reference

All responses are JSON with an `ok` boolean. Mutations are POST-only;
sends that block on network ACKs answer `202 {"ok": true, "queued": true,
...}` immediately and finish in a background thread.

| method | path | body | notes |
|---|---|---|---|
| GET | `/api/status` | – | handle, peer_id, presence, counts |
| GET | `/api/peers` | – | paired agents + presence + revoke flags |
| GET | `/api/conversations` | – | messages grouped per peer, in/out |
| GET | `/api/files` | – | file transfers, newest first |
| GET | `/api/projects` | – | projects + task counts |
| GET | `/api/tasks?project_id=` | – | tasks, optionally filtered |
| GET | `/api/permissions?peer=` | – | capability grants |
| GET | `/api/pairings` | – | pairing sessions |
| GET | `/api/audit?limit=` | – | audit log, newest first |
| GET | `/api/presence` | – | presence table |
| POST | `/api/message/send` | `{"peer","text"}` | → 202 queued |
| POST | `/api/file/send` | `{"peer","path"}` | local path → 202 queued |
| POST | `/api/permission/grant` | `{"peer","scope"}` | scope must be a known `PERMS` value |
| POST | `/api/permission/revoke` | `{"peer","scope"}` | |
| POST | `/api/peer/revoke` | `{"peer"}` | revokes the pairing |
| POST | `/api/presence` | `{"state"}` | one of `online offline busy paused unknown` |
| POST | `/api/pair/initiate` | `{"host","port"}` | starts a pairing session |
| POST | `/api/pair/confirm` | `{"session_id","code"}` | confirms the 6-char code |
| POST | `/api/project/create` | `{"title","notes"}` | |
| POST | `/api/task/add` | `{"project_id","title","assignee?","notes?"}` | |
| POST | `/api/task/update` | `{"task_id","status?","notes?"}` | |

Error codes: `UNAUTHORIZED` 401, `BAD_INPUT`/`UNKNOWN_SCOPE` 400,
`NOT_FOUND` 404, `METHOD_NOT_ALLOWED` 405, connector errors map via
`NOT_FOUND`→404, `POLICY_DENIED`→403, else 400. Any `..` path segment
(after percent-decoding) → `400`.

## UI language

`/?lang=yo` (or `es fr de zh`) re-renders the UI in that language and
sets an `acp_lang` cookie so later visits remember it. The server injects
a translated string table into the page from `packages/acp_i18n` — see
`docs/DASHBOARD_I18N.md`.

## Security notes

- Binds `127.0.0.1` by default. Binding `0.0.0.0` exposes the API to the
  LAN — only do that behind your own network controls.
- Request bodies are capped at 1 MiB; unknown `/api/*` paths 404; the UI
  serves no files from disk, so traversal has nothing to reach (it is
  still rejected explicitly with 400).
- `send_message`/`send_file` go through the connector's normal E2E
  encrypted path with the same permission checks as the CLI.

## Files

- `server.py` — `Dashboard` class: HTTP server, router, all handlers.
- `ui.py` — `render_page(lang)` → the self-contained HTML page.
- `__main__.py` — CLI entry: unlock home, start connector + dashboard.
- `__init__.py` — package marker.

## Tests

`tests/test_dashboard.py` — pairs two real connectors on localhost,
drives every endpoint over HTTP (urllib), and covers the attack cases
(401s, traversal, 405s, bad JSON, unknown peer/scope).
