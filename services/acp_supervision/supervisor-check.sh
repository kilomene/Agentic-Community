#!/usr/bin/env bash
# supervisor-check: one-shot health report for acp self-supervision.
#
#   supervisor-check [--prefix DIR] [--relay URL]
#
# Prints a single JSON object to stdout and exits 0 when every supervised
# service is running (exit 1 otherwise). Needs no credentials: it only
# reads pidfiles, the crontab, and state files.
#
# Test seam: ACP_SUPERVISION_FAKE_CRONTAB=/path/to/file checks that file
# instead of the real crontab.
set -u

DEFAULT_RELAY="wss://acp-relay.ayiijumo.workers.dev/acp"
CRON_MARKER="acp-supervision-keepalive"

PREFIX=""
RELAY="${ACP_RELAY_URL:-$DEFAULT_RELAY}"
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --relay) RELAY="$2"; shift 2;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 1;;
  esac
done

# resolve prefix: explicit arg > $ACP_HOME > sibling-of-bin > ~/.acp
if [ -z "$PREFIX" ]; then
  if [ -n "${ACP_HOME:-}" ]; then
    PREFIX="$ACP_HOME"
  else
    _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    case "$_here" in
      */bin) PREFIX="$(dirname "$_here")";;
      *) PREFIX="$HOME/.acp";;
    esac
  fi
fi

_alive() { # _alive <pidfile> -> prints pid or nothing
  [ -f "$1" ] || return 0
  _p="$(cat "$1" 2>/dev/null || true)"
  case "$_p" in ''|*[!0-9]*) return 0;; esac
  kill -0 "$_p" 2>/dev/null && printf '%s' "$_p"
}

_dpid="$(_alive "$PREFIX/run/relay-daemon.pid")"
_upid="$(_alive "$PREFIX/run/auto-update.pid")"
_au_installed=0; [ -x "$PREFIX/bin/acp-auto-update" ] && _au_installed=1

# cron: is our tagged keepalive line present?
_cron=""; _cron_installed="false"
if [ -n "${ACP_SUPERVISION_FAKE_CRONTAB:-}" ]; then
  [ -f "$ACP_SUPERVISION_FAKE_CRONTAB" ] \
    && _cron="$(grep "$CRON_MARKER" "$ACP_SUPERVISION_FAKE_CRONTAB" | head -1 || true)"
else
  command -v crontab >/dev/null 2>&1 \
    && _cron="$(crontab -l 2>/dev/null | grep "$CRON_MARKER" | head -1 || true)"
fi
[ -n "$_cron" ] && _cron_installed="true"

_pair="false"; [ -f "$PREFIX/state/pair-code.json" ] && _pair="true"
_now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

_jbool() { [ -n "$1" ] && printf 'true' || printf 'false'; }

_daemon_running="$(_jbool "$_dpid")"
_up_running="$(_jbool "$_upid")"
if [ "$_au_installed" = "1" ]; then
  _healthy="false"; { [ "$_daemon_running" = "true" ] && [ "$_up_running" = "true" ]; } \
    && _healthy="true" || true
else
  _healthy="$_daemon_running"
fi

cat <<EOF
{
  "prefix": "$PREFIX",
  "relay_url": "$RELAY",
  "daemon": {"name": "acp-relay-daemon", "running": $_daemon_running, "pid": ${_dpid:-null}, "pidfile": "$PREFIX/run/relay-daemon.pid"},
  "auto_update": {"name": "acp-auto-update", "installed": $([ "$_au_installed" = "1" ] && echo true || echo false), "running": $_up_running, "pid": ${_upid:-null}, "pidfile": "$PREFIX/run/auto-update.pid"},
  "cron": {"installed": $_cron_installed, "schedule": "every minute", "command": "$PREFIX/bin/acp-keepalive"},
  "pair_code": {"present": $_pair},
  "healthy": $_healthy,
  "checked_at": "$_now"
}
EOF

[ "$_healthy" = "true" ] && exit 0 || exit 1
