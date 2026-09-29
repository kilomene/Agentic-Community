# acp_auto_update — the agent updates itself

No agent in the cycle is ever updated by hand. Every install ships a
small updater loop (`acp-auto-update`) that watches the
Agentic-Community repo and applies bug fixes and new features on its
own: pull, re-sync, restart, verify — rolling back automatically if
anything goes wrong.

## How it works

Every 15 minutes the loop runs one cycle:

1. **Check** — `git fetch origin main` in the tracked checkout and
   compare SHAs. If nothing new, done.
2. **Safety gates** — the cycle is skipped (and retried later) when:
   - no git checkout is found,
   - the checkout has uncommitted changes (local work is never destroyed),
   - the checkout has local commits not on the remote (dev-machine guard),
   - the remote can't be reached.
3. **Update** — `git reset --hard` to the new SHA, then re-sync
   `$PREFIX/lib` from `lib_manifest.txt` (the same manifest
   `install.sh` uses, so the two can never drift apart).
4. **Restart (only if the daemon's own code changed)** — when the push
   touches only docs, tests, or worker-only files, the lib is synced and
   the daemon is left running: the relay link, the pairing code, and all
   live sessions are untouched. When daemon code did change, the updater
   waits for any in-flight pairing handshake to finish (up to 120s),
   restarts the daemon — which re-claims its permanent pairing code —
   then waits up to 75s for a live, connected relay link. Messages sent
   during the few-second restart window queue on the relay and drain on
   reconnect.
5. **Roll back** — if the daemon doesn't come back healthy, the checkout
   is reset to the previous SHA, `$PREFIX/lib` is re-synced, the daemon
   restarts again, and the failure is recorded. The agent is never left
   broken by an update.

Cycle results land in `$PREFIX/state/auto-update.json`
(`up-to-date`, `updated`, `rolled-back`, `skipped-dirty`, …) and the log
at `$PREFIX/logs/auto-update.log`.

## Operator commands

```bash
acp-auto-update status   # running? + last cycle result
acp-auto-update check    # run one cycle right now, in the foreground
acp-auto-update restart  # restart the loop
acp-auto-update stop     # stop the loop (updates pause until restarted)
```

## What it touches — and what it never touches

- Touches: the git checkout (`$HOME/Agentic-Community` by default, or the
  path recorded in `$PREFIX/config/repo-root` at install time) and
  `$PREFIX/lib` (code only).
- Never touches: identity, passphrase, pairing state, config, databases,
  logs. An update can't unpair an agent or lose its keys.

## Trust model

The repo is the trust root: whoever can push to
`kilomene/Agentic-Community` can ship code to every auto-updating agent.
That's the owner's repo. Don't point an install at a checkout you don't
trust, and don't run the updater on a dev checkout with local commits —
the local-commit guard will skip it anyway.

## Files

| file | what it is |
|---|---|
| `updater.py` | the updater (stdlib only): `--once` / `--daemon` |
| `lib_manifest.txt` | every file installed into `$PREFIX/lib`; read by `install.sh` and `updater.py` |
| `__init__.py` | makes `python3 -m acp_auto_update.updater` work |
