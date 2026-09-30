# acp_supervision — standard self-supervision for ACP agents

The installable package that keeps agents from dying quietly. An agent runs
`install.sh` on its **own** machine; it sets up:

- **control wrappers** — `bin/acp-relay-daemon` and `bin/acp-auto-update`
  (`start` is idempotent; the daemon writes its own pidfile)
- **keepalive** — `bin/acp-keepalive`, run every minute from cron,
  idempotently (re)starts both services
- **cron** — the 1-minute keepalive line, tagged so reinstalls never
  duplicate it
- **auto-update** — on by default (`--no-auto-update` to opt out)
- **supervisor-check** — one-shot JSON health report (`bin/supervisor-check`)

Full documentation: `docs/SUPERVISION.md`.

Tests: `tests/test_supervision.py` (runs the installer against a stub
repo in a tmp dir — never touches the live machine's cron or `~/.acp`).
