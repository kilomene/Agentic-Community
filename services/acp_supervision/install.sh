#!/usr/bin/env bash
# acp-supervision installer — standard self-supervision for any ACP agent.
#
# An agent runs this on its OWN machine. It sets up the supervision pattern
# that keeps agents from dying quietly:
#
#   1. control wrappers   $PREFIX/bin/acp-relay-daemon   {start|stop|restart|status|code}
#                         $PREFIX/bin/acp-auto-update    {start|stop|restart|status|check}
#      - start is idempotent: a live pidfile is a safe no-op
#      - the relay daemon writes its OWN pidfile (--pid-file); the wrapper
#        never echoes $! into it (the subshell PID != the daemon PID)
#   2. keepalive           $PREFIX/bin/acp-keepalive — called every minute
#      from cron; idempotently starts both services (no-op when alive)
#   3. cron               a 1-minute cron line, tagged so reinstalls never
#      duplicate it
#   4. auto-update        ON by default (opt out with --no-auto-update)
#
# Usage:
#   bash services/acp_supervision/install.sh [--prefix DIR] [--repo DIR]
#       [--relay URL] [--python PATH] [--no-auto-update] [--skip-cron]
#       [--no-start] [--dry-run]
#
# Options:
#   --prefix DIR        install prefix (default: $ACP_HOME or $HOME/.acp)
#   --repo DIR          Agentic-Community checkout the updater tracks
#                       (default: checkout next to this script, else
#                       $HOME/Agentic-Community)
#   --relay URL         relay wss:// URL (default: the community relay)
#   --python PATH       python3 interpreter (default: first on PATH)
#   --no-auto-update    skip the auto-update service (default: enabled)
#   --skip-cron         do not install the 1-minute cron line
#   --no-start          install only; do not start the services
#   --dry-run           print what would be done; change nothing
#
# Idempotent: safe to run again to repair or upgrade. Existing identity,
# passphrase, state, and databases are never touched.
#
# Test seam: ACP_SUPERVISION_FAKE_CRONTAB=/path/to/file makes the cron
# installer read/write that file instead of the real crontab.
set -euo pipefail

DEFAULT_RELAY="wss://acp-relay.ayiijumo.workers.dev/acp"
CRON_MARKER="acp-supervision-keepalive"

PREFIX="${ACP_HOME:-$HOME/.acp}"
REPO=""
RELAY="$DEFAULT_RELAY"
PYTHON=""
AUTO_UPDATE=1
INSTALL_CRON=1
DO_START=1
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    --relay) RELAY="$2"; shift 2;;
    --python) PYTHON="$2"; shift 2;;
    --no-auto-update) AUTO_UPDATE=0; shift;;
    --skip-cron) INSTALL_CRON=0; shift;;
    --no-start) DO_START=0; shift;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) sed -n '2,36p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 1;;
  esac
done

# --- where is the package / the repo? ---------------------------------------
PKG_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$PKG_DIR" in
  */services/acp_supervision)
    PKG_REPO_ROOT="$(cd "$PKG_DIR/../.." && pwd)"
    [ -d "$PKG_REPO_ROOT/packages/acp_connector" ] && REPO_DEFAULT="$PKG_REPO_ROOT" \
      || REPO_DEFAULT="$HOME/Agentic-Community";;
  *) REPO_DEFAULT="$HOME/Agentic-Community";;
esac
[ -n "$REPO" ] || REPO="$REPO_DEFAULT"

say() { echo "acp-supervision: $*"; }
die() { echo "acp-supervision FATAL: $*" >&2; exit 1; }

# --- dry run: describe only ---------------------------------------------------
if [ "$DRY_RUN" = "1" ]; then
  cat <<EOF
dry-run plan:
  prefix      : $PREFIX
  repo        : $REPO
  relay       : $RELAY
  auto-update : $([ "$AUTO_UPDATE" = "1" ] && echo on || echo off)
  cron        : $([ "$INSTALL_CRON" = "1" ] && echo "1-minute keepalive" || echo skipped)
  start       : $([ "$DO_START" = "1" ] && echo yes || echo no)
EOF
  exit 0
fi

# --- prerequisites ------------------------------------------------------------
[ -n "$PYTHON" ] || PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 is required"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 9)' \
  || die "python3 >= 3.9 required ($PYTHON)"
"$PYTHON" -c "import sqlite3, ssl" || die "python3 needs sqlite3+ssl"
command -v git >/dev/null || die "git is required"

[ -f "$REPO/services/acp_auto_update/lib_manifest.txt" ] \
  || die "repo checkout not found at $REPO (pass --repo)"

say "prefix: $PREFIX"
say "repo:   $REPO"
say "python: $PYTHON"

# --- directory layout ----------------------------------------------------------
mkdir -p "$PREFIX"/{bin,lib,state,config,logs,run}

# --- sync $PREFIX/lib from the repo checkout (manifest-driven) ----------------
# services/acp_auto_update/lib_manifest.txt lists every installed file, so
# the installer and the auto-updater can never drift apart.
sync_lib_from_manifest() {
  _manifest="$REPO/services/acp_auto_update/lib_manifest.txt"
  while read -r _kind _src _dst; do
    case "$_kind" in
      ""|\#*) continue;;
      dir)
        rm -rf "$PREFIX/lib/$_dst"
        cp -r "$REPO/$_src" "$PREFIX/lib/$_dst";;
      opt-dir)
        [ -d "$REPO/$_src" ] || continue
        rm -rf "$PREFIX/lib/$_dst"
        cp -r "$REPO/$_src" "$PREFIX/lib/$_dst";;
      file)
        mkdir -p "$PREFIX/lib/$(dirname "$_dst")"
        rm -f "$PREFIX/lib/$_dst"
        cp "$REPO/$_src" "$PREFIX/lib/$_dst";;
      opt-file)
        [ -f "$REPO/$_src" ] || continue
        mkdir -p "$PREFIX/lib/$(dirname "$_dst")"
        rm -f "$PREFIX/lib/$_dst"
        cp "$REPO/$_src" "$PREFIX/lib/$_dst";;
      touch)
        mkdir -p "$PREFIX/lib/$(dirname "$_dst")"
        touch "$PREFIX/lib/$_dst";;
      *)
        die "bad manifest line: $_kind $_src $_dst";;
    esac
  done < "$_manifest"
}
sync_lib_from_manifest
say "lib synced from manifest"

# record which checkout this install tracks, so the auto-updater knows
# what to pull (rewritten on every reinstall)
echo "$REPO" > "$PREFIX/config/repo-root"

# --- control wrappers ----------------------------------------------------------
# Generated with the real paths baked in; $PREFIX is still overridable at
# runtime via $ACP_HOME, exactly like the hand-maintained wrappers.
python3 - "$PREFIX" "$RELAY" "$PYTHON" "$PKG_DIR" <<'PYEOF'
import os, sys
prefix, relay, python, pkg_dir = sys.argv[1:5]

def write(name, text):
    p = os.path.join(prefix, "bin", name)
    with open(p, "w") as fh:
        fh.write(text.replace("__PYTHON__", python).replace("__RELAY__", relay))
    os.chmod(p, 0o755)
    print("wrote", p)

# --- relay daemon wrapper -----------------------------------------------------
# PIDFILE RULE: the daemon writes its own pidfile via --pid-file (it knows
# its real PID). The wrapper must NEVER `echo $!` into the pidfile: $! is
# the nohup subshell's PID, which races the daemon's own write and leaves a
# stale/wrong PID behind.
daemon_ctl = """#!/usr/bin/env bash
# acp-relay-daemon control: start|stop|restart|status|code
set -u
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_prefix="$(dirname "$_here")"
if [ -n "${ACP_HOME:-}" ]; then _prefix="$ACP_HOME"; fi
export PYTHONPATH="$_prefix/lib${PYTHONPATH:+:$PYTHONPATH}"
PIDF="$_prefix/run/relay-daemon.pid"
LOGF="$_prefix/logs/relay-daemon.log"
case "${1:-status}" in
  start)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "relay daemon already running (pid $(cat "$PIDF"))"; exit 0; fi
    rm -f "$PIDF"  # stale pidfile, if any: the daemon writes its own on boot
    shift
    nohup __PYTHON__ -m acp_relay_daemon.daemon \\
      --home "$_prefix/acp-home" \\
      --passphrase-file "$_prefix/config/acp-passphrase" \\
      --url "${ACP_RELAY_URL:-__RELAY__}" \\
      --state-dir "$_prefix/state" \\
      --pid-file "$PIDF" "$@" >>"$LOGF" 2>&1 &
    # wait for the daemon to write its own pidfile, then verify liveness
    for _i in $(seq 1 30); do
      [ -f "$PIDF" ] && break
      sleep 0.5
    done
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "relay daemon started (pid $(cat "$PIDF"))"
    else
      echo "relay daemon FAILED to start -- see $LOGF" >&2; exit 1
    fi
    ;;
  stop)
    if [ -f "$PIDF" ]; then
      _pid="$(cat "$PIDF")"
      kill "$_pid" 2>/dev/null || true
      # wait for it to actually exit so a restart can't race its cleanup
      for _i in $(seq 1 20); do
        kill -0 "$_pid" 2>/dev/null || break
        sleep 0.5
      done
      rm -f "$PIDF"
    fi
    pkill -f "acp_relay_daemon.daemon" 2>/dev/null || true
    echo "relay daemon stopped"
    ;;
  restart) "$0" stop; sleep 1; shift; "$0" start "$@";;
  status)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "running (pid $(cat "$PIDF"))"
    else
      echo "not running"; exit 1
    fi
    [ -f "$_prefix/state/relay-status.json" ] && cat "$_prefix/state/relay-status.json"
    exit 0
    ;;
  code)
    [ -f "$_prefix/state/pair-code.json" ] && cat "$_prefix/state/pair-code.json" \\
      || { echo "no pairing code yet (daemon still connecting?)"; exit 1; }
    ;;
  *) echo "usage: $0 {start|stop|restart|status|code}" >&2; exit 1;;
esac
"""
write("acp-relay-daemon", daemon_ctl)

# --- keepalive ----------------------------------------------------------------
# Run from cron every minute. `start` on each wrapper is a safe no-op when
# the service is alive, so this script only ever *starts* dead services.
keepalive = """#!/usr/bin/env bash
# acp-keepalive: the 1-minute cron calls this. Idempotently ensures the
# relay daemon and (when installed) the auto-update service are running.
#
# DESIGN RULES (see docs/SUPERVISION.md before changing):
#  - Each wrapper's `start` is a safe no-op when the service is alive, so
#    this script can run every minute without ever flapping a healthy link.
#  - This script NEVER reads, stores, or reacts to egress-proxy tokens.
#    Tokens are session-bound with a short TTL; the established relay link
#    keeps working after a token dies (auth happens at CONNECT time), so
#    restarting on token change would only flap the link and churn the
#    pairing code. Restarts happen on process death ONLY (pidfile + kill).
set -u
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_prefix="$(dirname "$_here")"
if [ -n "${ACP_HOME:-}" ]; then _prefix="$ACP_HOME"; fi
_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
_keepalive() {
  _svc="$1"; shift
  if _out="$("$_prefix/bin/$_svc" start 2>&1)"; then
    case "$_out" in
      *"already running"*) ;;  # healthy: stay quiet
      *) echo "$_ts keepalive: $_svc: $_out";;
    esac
  else
    echo "$_ts keepalive: $_svc FAILED to start: $_out"
  fi
}
_keepalive acp-relay-daemon
[ -x "$_prefix/bin/acp-auto-update" ] && _keepalive acp-auto-update
exit 0  # the cron job itself never fails; failures are logged above
"""
write("acp-keepalive", keepalive)

# --- supervisor check -----------------------------------------------------------
# Reference health script: one JSON report, exit 0 when supervised services
# are running. Agents can also run it standalone from the package dir.
import shutil
shutil.copy(os.path.join(pkg_dir, "supervisor-check.sh"),
            os.path.join(prefix, "bin", "supervisor-check"))
os.chmod(os.path.join(prefix, "bin", "supervisor-check"), 0o755)
print("wrote", os.path.join(prefix, "bin", "supervisor-check"))
PYEOF

# --- auto-update wrapper (default ON) -------------------------------------------
if [ "$AUTO_UPDATE" = "1" ]; then
  python3 - "$PREFIX" "$PYTHON" <<'PYEOF'
import os, sys
prefix, python = sys.argv[1:3]
ctl = """#!/usr/bin/env bash
# acp-auto-update control: start|stop|restart|status|check
set -u
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_prefix="$(dirname "$_here")"
if [ -n "${ACP_HOME:-}" ]; then _prefix="$ACP_HOME"; fi
export PYTHONPATH="$_prefix/lib${PYTHONPATH:+:$PYTHONPATH}"
PIDF="$_prefix/run/auto-update.pid"
LOGF="$_prefix/logs/auto-update.log"
# The updater has no self-pidfile, so this wrapper owns the pidfile
# ($! IS the right PID here — no subshell race as with the daemon).
_repo="$(cat "$_prefix/config/repo-root" 2>/dev/null || true)"
case "${1:-status}" in
  start)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "auto-update already running (pid $(cat "$PIDF"))"; exit 0; fi
    rm -f "$PIDF"
    if [ -n "$_repo" ]; then _repo_args="--repo $_repo"; else _repo_args=""; fi
    nohup __PYTHON__ -m acp_auto_update.updater --daemon \\
      --prefix "$_prefix" $_repo_args \\
      --log-file "$LOGF" \\
      >>"$LOGF" 2>&1 &
    echo $! > "$PIDF"
    sleep 1
    if kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "auto-update started (pid $(cat "$PIDF"))"
    else
      echo "auto-update FAILED to start -- see $LOGF" >&2; exit 1
    fi
    ;;
  stop)
    if [ -f "$PIDF" ]; then
      _pid="$(cat "$PIDF")"
      kill "$_pid" 2>/dev/null || true
      for _i in $(seq 1 20); do
        kill -0 "$_pid" 2>/dev/null || break
        sleep 0.5
      done
      rm -f "$PIDF"
    fi
    pkill -f "acp_auto_update.updater" 2>/dev/null || true
    echo "auto-update stopped"
    ;;
  restart) "$0" stop; sleep 1; "$0" start;;
  status)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "running (pid $(cat "$PIDF"))"
    else
      echo "not running"; exit 1
    fi
    [ -f "$_prefix/state/auto-update.json" ] && cat "$_prefix/state/auto-update.json"
    exit 0
    ;;
  check)
    if [ -n "$_repo" ]; then _repo_args="--repo $_repo"; else _repo_args=""; fi
    __PYTHON__ -m acp_auto_update.updater --once \\
      --prefix "$_prefix" $_repo_args
    ;;
  *) echo "usage: $0 {start|stop|restart|status|check}" >&2; exit 1;;
esac
"""
p = os.path.join(prefix, "bin", "acp-auto-update")
with open(p, "w") as fh:
    fh.write(ctl.replace("__PYTHON__", python))
os.chmod(p, 0o755)
print("wrote", p)
PYEOF
else
  rm -f "$PREFIX/bin/acp-auto-update"
  say "auto-update disabled (--no-auto-update)"
fi

# --- 1-minute keepalive cron -----------------------------------------------------
install_cron() {
  _line="* * * * * $PREFIX/bin/acp-keepalive >>$PREFIX/logs/keepalive.log 2>&1 # $CRON_MARKER"
  if [ -n "${ACP_SUPERVISION_FAKE_CRONTAB:-}" ]; then
    # test seam: merge into a file instead of the real crontab
    touch "$ACP_SUPERVISION_FAKE_CRONTAB"
    grep -v "$CRON_MARKER" "$ACP_SUPERVISION_FAKE_CRONTAB" > "$ACP_SUPERVISION_FAKE_CRONTAB.tmp" || true
    mv "$ACP_SUPERVISION_FAKE_CRONTAB.tmp" "$ACP_SUPERVISION_FAKE_CRONTAB"
    printf '%s\n' "$_line" >> "$ACP_SUPERVISION_FAKE_CRONTAB"
    say "cron line -> fake crontab ($ACP_SUPERVISION_FAKE_CRONTAB)"
    return 0
  fi
  if ! command -v crontab >/dev/null 2>&1; then
    say "warn: crontab not found -- skipping cron install (run $PREFIX/bin/acp-keepalive from your scheduler)"
    return 0
  fi
  { crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true; printf '%s\n' "$_line"; } | crontab -
  say "cron installed: every minute -> $PREFIX/bin/acp-keepalive"
}
if [ "$INSTALL_CRON" = "1" ]; then
  install_cron
else
  say "cron skipped (--skip-cron)"
fi

# --- start services ---------------------------------------------------------------
if [ "$DO_START" = "1" ]; then
  "$PREFIX/bin/acp-relay-daemon" stop >/dev/null 2>&1 || true
  "$PREFIX/bin/acp-relay-daemon" start
  if [ "$AUTO_UPDATE" = "1" ]; then
    "$PREFIX/bin/acp-auto-update" stop >/dev/null 2>&1 || true
    "$PREFIX/bin/acp-auto-update" start
  fi
else
  say "services not started (--no-start)"
fi

# --- sanity warning: supervision needs an identity to supervise ------------------
if [ ! -f "$PREFIX/config/acp-passphrase" ]; then
  say "warn: no $PREFIX/config/acp-passphrase yet -- the daemon needs an ACP"
  say "      identity. Run the full installer (repo-root install.sh) or create"
  say "      one, then: $PREFIX/bin/acp-relay-daemon start"
fi

cat <<EOF

acp-supervision installed:
  prefix      : $PREFIX
  daemon ctl  : $PREFIX/bin/acp-relay-daemon {start|stop|restart|status|code}
  keepalive   : $PREFIX/bin/acp-keepalive (cron: every minute)
  health      : $PREFIX/bin/supervisor-check
EOF
if [ "$AUTO_UPDATE" = "1" ]; then
  echo "  auto-update : $PREFIX/bin/acp-auto-update {start|stop|restart|status|check} (default ON)"
fi
cat <<EOF
  verify      : $PREFIX/bin/supervisor-check
EOF
