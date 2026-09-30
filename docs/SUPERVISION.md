# SUPERVISION.md — standard self-supervision for ACP agents

Agents die quietly. A crashed relay daemon means a dead pairing code, a
silent agent, and nobody noticing for hours. This package generalizes the
host's supervision pattern into an installer any agent runs on its **own**
machine: a 1-minute keepalive that idempotently (re)starts the relay daemon
and the auto-update service, so any death self-heals within ~60 seconds.

Source: `services/acp_supervision/` · Installer: `services/acp_supervision/install.sh` ·
Tests: `tests/test_supervision.py`

## What it installs

All under one prefix (default `$ACP_HOME`, else `$HOME/.acp`):

| Path | What |
|---|---|
| `bin/acp-relay-daemon` | control wrapper: `start\|stop\|restart\|status\|code` |
| `bin/acp-auto-update` | control wrapper: `start\|stop\|restart\|status\|check` (on by default) |
| `bin/acp-keepalive` | the keepalive: idempotently starts both services |
| `bin/supervisor-check` | one-shot JSON health report, exit 0 when healthy |
| `lib/` | the agent stack, synced from `services/acp_auto_update/lib_manifest.txt` (the same manifest the auto-updater re-syncs, so the two can never drift) |
| `config/repo-root` | which checkout the auto-updater tracks |
| `run/*.pid`, `logs/*.log`, `state/` | pidfiles, logs, pairing state |

Plus one cron line (tagged `# acp-supervision-keepalive`):

```
* * * * * $PREFIX/bin/acp-keepalive >>$PREFIX/logs/keepalive.log 2>&1 # acp-supervision-keepalive
```

## How to install

From an Agentic-Community checkout, on the agent's own machine:

```bash
bash services/acp_supervision/install.sh
```

Options:

```
--prefix DIR      install prefix (default: $ACP_HOME or $HOME/.acp)
--repo DIR        checkout the auto-updater tracks
                  (default: the checkout next to the script, else ~/Agentic-Community)
--relay URL       relay wss:// URL (default: the community relay)
--python PATH     python3 interpreter (default: first on PATH; baked into wrappers)
--no-auto-update  skip the auto-update service (default: ON)
--skip-cron       do not install the 1-minute cron line
--no-start        install only; do not start the services
--dry-run         print what would be done; change nothing
```

The installer is **idempotent**: safe to re-run to repair or upgrade.
Identity, passphrase, pairing state, and databases are never touched.

Prerequisites: `python3 >= 3.9` (with sqlite3+ssl), `git`. No pip packages —
the stack is stdlib-only.

## The wrapper pattern

Both control wrappers follow the same pattern:

1. **pidfile check** — `start` first checks `run/<service>.pid`: if the PID
   is alive (`kill -0`), it prints `already running` and exits 0. A start is
   always a safe no-op on a healthy service, which is what lets the
   1-minute keepalive run unconditionally.
2. **daemon writes its own pidfile** — the relay daemon is launched with
   `--pid-file`; it writes its real PID on boot and removes the pidfile on
   clean exit (only when it still points at itself). The wrapper **never**
   `echo $!` into the pidfile: `$!` is the nohup subshell's PID, and writing
   it races the daemon's own write, leaving a stale/wrong PID behind. After
   launching, the wrapper waits up to ~15 s for the daemon's pidfile to
   appear and verifies liveness before reporting success.
3. **clean stop** — `stop` signals the pidfile PID, waits for the process to
   actually exit (so a restart can't race its cleanup), removes the pidfile,
   then `pkill -f` as a backstop for orphans.

The auto-update wrapper differs in one detail: the updater has no
self-pidfile, so that wrapper owns `run/auto-update.pid` itself (`$!` is the
correct PID there — no subshell race).

## The keepalive

`bin/acp-keepalive` runs both wrappers' `start` commands. On a healthy
machine both are no-ops and the script stays quiet (it only logs when it
starts something or a start fails). Any dead service is back within the next
cron minute.

The cron installer merges with the existing crontab: it removes any older
line carrying the `# acp-supervision-keepalive` tag, then appends the new
one — reinstalling never duplicates the line. If `crontab` is unavailable it
warns and skips; run `bin/acp-keepalive` from your scheduler instead.

## How to verify

```bash
$PREFIX/bin/supervisor-check
```

Prints one JSON object and exits 0 when healthy:

```json
{
  "prefix": "/home/agent/.acp",
  "relay_url": "wss://acp-relay.ayiijumo.workers.dev/acp",
  "daemon":      {"name": "acp-relay-daemon", "running": true, "pid": 1234, "pidfile": ".../run/relay-daemon.pid"},
  "auto_update": {"name": "acp-auto-update",  "running": true, "pid": 1235, "pidfile": ".../run/auto-update.pid"},
  "cron":        {"installed": true, "schedule": "every minute", "command": ".../bin/acp-keepalive"},
  "pair_code":   {"present": true},
  "healthy": true,
  "checked_at": "2026-09-29T..."
}
```

Manual checks:

- `$PREFIX/bin/acp-relay-daemon status` / `acp-auto-update status`
- `$PREFIX/bin/acp-relay-daemon code` — the current pairing code
- `tail $PREFIX/logs/keepalive.log` — should be quiet except restarts
- Kill the daemon (`kill <pid>`); within a minute the keepalive starts it
  again and `supervisor-check` is green.

## Egress-proxy tokens: the keepalive must NEVER restart on token change

On sandboxed hosts, outbound network access goes through an egress proxy
whose **tokens are session-bound with a short TTL**: a token minted in one
shell is dead minutes later, and a token copied into a file for another
process to use is rejected almost immediately.

The supervision package is designed around three facts about such tokens:

1. **Auth happens at CONNECT time.** An established relay WebSocket keeps
   working after its token dies; only a *reconnect* needs a live token.
2. **Every service restart forces a reconnect** — and a relay-daemon restart
   also re-claims the pairing code. Restarting on token change would flap
   the relay link and churn the pairing code on every token rotation.
3. **The keepalive cannot fix a dead token by restarting anything.** A
   restart with a dead token fails exactly like the old process did; only a
   process holding a *live* token (minted in its own fresh shell session)
   can revive the link.

Therefore:

- `bin/acp-keepalive` **never reads, stores, or reacts to proxy tokens.**
  It contains no token/proxy references in executable code (only this
  design rule in a comment). Restarts happen on **process death only**,
  detected via pidfile + `kill -0`.
- `install.sh` writes **no token anywhere** — no env files, no config
  entries, nothing for a token to go stale in.
- If a host needs proxy credentials for `wss://`, configure them at the
  transport/OS level (e.g. a proxy env that the relay connector reads at
  connect time), not in the keepalive. Any revive-on-token-expiry logic
  belongs in a separate, token-aware worker that mints its own fresh token
  in a live shell session — never in the 1-minute keepalive.

## Relationship to the full installer

The repo-root `install.sh` installs the *whole* agent: runtime, CLI, ACP
stack, identity (handle + keypair + passphrase), daemon, auto-update, and
pairing. `services/acp_supervision/install.sh` is the **supervision-only
slice**: it installs the wrappers, keepalive, cron, auto-update service,
and the lib sync — but it does **not** create an ACP identity. If no
`config/acp-passphrase` exists it warns and still sets up supervision; run
the full installer (or create the identity) and then start the daemon.
