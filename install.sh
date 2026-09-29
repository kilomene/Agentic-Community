#!/usr/bin/env bash
# Agentic-Community one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/kilomene/Agentic-Community/main/install.sh | bash
#
# or from a clone:
#
#   git clone https://github.com/kilomene/Agentic-Community && cd Agentic-Community && ./install.sh
#
# What it does, with zero questions asked:
#   1. checks prerequisites (python3, git)
#   2. makes sure the repo is present (clones it when piped)
#   3. installs the self-recovering agent runtime (supervisor + ACP stack)
#   4. creates the agent's ACP identity (handle + keypair) — idempotent,
#      never overwrites an existing identity
#   5. installs + starts the relay daemon: a persistent wss:// connection
#      to the community relay with auto-reconnect and an always-fresh
#      6-letter pairing code
#   6. installs + starts the auto-updater: the agent pulls repo updates
#      itself (bug fixes, new features) — no manual updates, ever
#   7. prints the pairing code so the owner can pair this agent from
#      anywhere:  pair-code <CODE>
#
# Options:
#   --handle NAME     agent handle (default: agent-<random>)
#   --prefix DIR      install prefix (default: $HOME/.acp)
#   --relay URL       relay wss:// URL (default: the community relay)
#   --no-runtime      skip the vm-agent supervisor (ACP network only)
#   --reinstall       redo install steps even where state exists
#                     (identity is STILL never overwritten)
#
# Idempotent: safe to run again to repair or upgrade.
set -euo pipefail

REPO_URL="https://github.com/kilomene/Agentic-Community"
DEFAULT_RELAY="wss://acp-relay.ayiijumo.workers.dev/acp"

HANDLE=""
PREFIX="${ACP_HOME:-$HOME/.acp}"
RELAY="$DEFAULT_RELAY"
INSTALL_RUNTIME=1
REINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --handle) HANDLE="$2"; shift 2;;
    --prefix) PREFIX="$2"; shift 2;;
    --relay) RELAY="$2"; shift 2;;
    --no-runtime) INSTALL_RUNTIME=0; shift;;
    --reinstall) REINSTALL=1; shift;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 1;;
  esac
done

# --- where is the repo? -------------------------------------------------
# When piped via curl, $0 is "bash" and there is no script dir — clone.
# When run from a checkout, use the checkout.
SCRIPT_DIR=""
case "$0" in
  *install.sh) SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)";;
esac
if [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/packages/acp_connector" ]; then
  REPO_ROOT="$SCRIPT_DIR"
  echo "repo: $REPO_ROOT (local checkout)"
else
  REPO_ROOT="$HOME/Agentic-Community"
  if [ -d "$REPO_ROOT/.git" ] && [ "$REINSTALL" = "0" ]; then
    echo "repo: $REPO_ROOT (exists, pulling latest)"
    git -C "$REPO_ROOT" pull --ff-only -q || echo "warn: pull failed, using existing checkout"
  elif [ -d "$REPO_ROOT/.git" ]; then
    echo "repo: $REPO_ROOT (exists)"
  else
    echo "cloning $REPO_URL -> $REPO_ROOT"
    git clone -q "$REPO_URL" "$REPO_ROOT"
  fi
fi

# --- sync $PREFIX/lib from the repo checkout (manifest-driven) --------------
# services/acp_auto_update/lib_manifest.txt lists every installed file, so
# install.sh and the auto-updater can never drift apart. Columns:
#   <kind> <src-relative-to-repo> <dst-relative-to-$PREFIX/lib>
# kinds: dir | opt-dir | file | opt-file | touch   (opt-* skip missing src)
sync_lib_from_manifest() {
  _manifest="$REPO_ROOT/services/acp_auto_update/lib_manifest.txt"
  [ -f "$_manifest" ] || { echo "FATAL: manifest missing: $_manifest" >&2; exit 1; }
  while read -r _kind _src _dst; do
    case "$_kind" in
      ""|\#*) continue;;
      dir)
        rm -rf "$PREFIX/lib/$_dst"
        cp -r "$REPO_ROOT/$_src" "$PREFIX/lib/$_dst";;
      opt-dir)
        [ -d "$REPO_ROOT/$_src" ] || continue
        rm -rf "$PREFIX/lib/$_dst"
        cp -r "$REPO_ROOT/$_src" "$PREFIX/lib/$_dst";;
      file)
        mkdir -p "$PREFIX/lib/$(dirname "$_dst")"
        rm -f "$PREFIX/lib/$_dst"
        cp "$REPO_ROOT/$_src" "$PREFIX/lib/$_dst";;
      opt-file)
        [ -f "$REPO_ROOT/$_src" ] || continue
        mkdir -p "$PREFIX/lib/$(dirname "$_dst")"
        rm -f "$PREFIX/lib/$_dst"
        cp "$REPO_ROOT/$_src" "$PREFIX/lib/$_dst";;
      touch)
        mkdir -p "$PREFIX/lib/$(dirname "$_dst")"
        touch "$PREFIX/lib/$_dst";;
      *)
        echo "FATAL: bad manifest line: $_kind $_src $_dst" >&2; exit 1;;
    esac
  done < "$_manifest"
}

# record which checkout this install tracks, so the auto-updater knows
# what to pull (written again on every reinstall)
mkdir -p "$PREFIX/config"
echo "$REPO_ROOT" > "$PREFIX/config/repo-root"

# --- 1. prerequisites ----------------------------------------------------
echo "--- prerequisites ---"
python3 --version || { echo "FATAL: python3 is required" >&2; exit 1; }
command -v git >/dev/null || { echo "FATAL: git is required" >&2; exit 1; }
python3 -c "import sqlite3, ssl" || { echo "FATAL: python3 needs sqlite3+ssl" >&2; exit 1; }
[ "$(python3 -c 'import sys; print(sys.version_info >= (3, 9))')" = "True" ] \
  || { echo "FATAL: python3 >= 3.9 required" >&2; exit 1; }

# --- 2. install the runtime (supervisor + ACP stack) ---------------------
if [ "$INSTALL_RUNTIME" = "1" ]; then
  echo "--- agent runtime ---"
  VM_AGENT_HOME="$PREFIX" bash "$REPO_ROOT/runtime/install.sh"
else
  echo "--- ACP stack only (--no-runtime) ---"
  mkdir -p "$PREFIX"/{bin,lib,state,config,logs,run}
  sync_lib_from_manifest
fi

# --- 3. CLI entry points --------------------------------------------------
echo "--- cli ---"
mkdir -p "$PREFIX/bin"
python3 - "$PREFIX" "$RELAY" <<'PYEOF'
import os, stat, sys
prefix, relay = sys.argv[1], sys.argv[2]
wrapper = """#!/usr/bin/env bash
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_prefix="$(dirname "$_here")"
if [ -n "${ACP_HOME:-}" ]; then _prefix="$ACP_HOME"; fi
export PYTHONPATH="$_prefix/lib${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 "$_prefix/lib/acp_cli/cli.py" "$@"
"""
p = os.path.join(prefix, "bin", "acp")
with open(p, "w") as fh:
    fh.write(wrapper)
os.chmod(p, 0o755)

# daemon control script
ctl = """#!/usr/bin/env bash
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
    shift
    nohup /usr/bin/python3 -m acp_relay_daemon.daemon \\
      --home "$_prefix/acp-home" \\
      --passphrase-file "$_prefix/config/acp-passphrase" \\
      --url "${ACP_RELAY_URL:-__RELAY__}" \\
      --state-dir "$_prefix/state" \\
      --pid-file "$PIDF" "$@" >>"$LOGF" 2>&1 &
    echo $! > "$PIDF"
    echo "relay daemon started (pid $!)"
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
    ;;
  code)
    [ -f "$_prefix/state/pair-code.json" ] && cat "$_prefix/state/pair-code.json" \\
      || { echo "no pairing code yet (daemon still connecting?)"; exit 1; }
    ;;
  *) echo "usage: $0 {start|stop|restart|status|code}" >&2; exit 1;;
esac
"""
ctl = ctl.replace("__RELAY__", relay)
p2 = os.path.join(prefix, "bin", "acp-relay-daemon")
with open(p2, "w") as fh:
    fh.write(ctl)
os.chmod(p2, 0o755)
print("wrote", p, "and", p2)
PYEOF

# install the ACP stack into lib (manifest-driven: packages, daemon module,
# CLI, auto-updater — everything the agent runs)
sync_lib_from_manifest

# --- 4. identity ----------------------------------------------------------
echo "--- identity ---"
ACP_HOME_DIR="$PREFIX/acp-home"
mkdir -p "$ACP_HOME_DIR" "$PREFIX/config" "$PREFIX/state" "$PREFIX/logs" "$PREFIX/run"
chmod 700 "$PREFIX/config" "$ACP_HOME_DIR"
PASSFILE="$PREFIX/config/acp-passphrase"
if [ ! -f "$PASSFILE" ]; then
  python3 -c "import secrets; print(secrets.token_hex(32))" > "$PASSFILE"
  chmod 600 "$PASSFILE"
  echo "passphrase generated -> $PASSFILE (0600)"
fi
export ACP_PASSPHRASE="$(cat "$PASSFILE")"
if [ ! -f "$ACP_HOME_DIR/connector.db" ]; then
  if [ -z "$HANDLE" ]; then
    HANDLE="agent-$(python3 -c 'import secrets; print(secrets.token_hex(2))')"
  fi
  echo "creating identity (handle: $HANDLE)"
  # NB: passphrase travels via the ACP_PASSPHRASE env var (the CLI reads
  # it), never on the command line where `ps` could see it.
  PYTHONPATH="$PREFIX/lib" /usr/bin/python3 "$PREFIX/lib/acp_cli/cli.py" \
    init --home "$ACP_HOME_DIR" --handle "$HANDLE"
else
  echo "identity exists (kept)"
fi
unset ACP_PASSPHRASE

# --- 5. relay daemon ------------------------------------------------------
echo "--- relay daemon ---"
export ACP_RELAY_URL="$RELAY"
"$PREFIX/bin/acp-relay-daemon" stop >/dev/null 2>&1 || true
"$PREFIX/bin/acp-relay-daemon" start
unset ACP_RELAY_URL

# --- 5b. auto-updater: the agent updates itself from the repo --------------
# No agent is ever updated by hand again: this loop checks the repo every
# 15 minutes and, when fixes/features land, pulls, re-syncs $PREFIX/lib,
# restarts the relay daemon, verifies health, and rolls back on failure.
echo "--- auto-update ---"
python3 - "$PREFIX" <<'PYEOF'
import os, sys
prefix = sys.argv[1]
ctl = """#!/usr/bin/env bash
# acp-auto-update control: start|stop|restart|status|check
set -u
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_prefix="$(dirname "$_here")"
if [ -n "${ACP_HOME:-}" ]; then _prefix="$ACP_HOME"; fi
export PYTHONPATH="$_prefix/lib${PYTHONPATH:+:$PYTHONPATH}"
PIDF="$_prefix/run/auto-update.pid"
LOGF="$_prefix/logs/auto-update.log"
case "${1:-status}" in
  start)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      echo "auto-update already running (pid $(cat "$PIDF"))"; exit 0; fi
    nohup /usr/bin/python3 -m acp_auto_update.updater --daemon \\
      >>"$LOGF" 2>&1 &
    echo $! > "$PIDF"
    echo "auto-update started (pid $!)"
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
    ;;
  check)
    /usr/bin/python3 -m acp_auto_update.updater --once
    ;;
  *) echo "usage: $0 {start|stop|restart|status|check}" >&2; exit 1;;
esac
"""
p = os.path.join(prefix, "bin", "acp-auto-update")
with open(p, "w") as fh:
    fh.write(ctl)
os.chmod(p, 0o755)
print("wrote", p)
PYEOF
"$PREFIX/bin/acp-auto-update" stop >/dev/null 2>&1 || true
"$PREFIX/bin/acp-auto-update" start

# --- 6. wait for connection + pairing code --------------------------------
echo "--- waiting for relay ---"
CODE=""
for i in $(seq 1 30); do
  sleep 2
  if [ -f "$PREFIX/state/pair-code.json" ]; then
    CODE="$(python3 -c "import json; print(json.load(open('$PREFIX/state/pair-code.json'))['code'])" 2>/dev/null || true)"
    [ -n "$CODE" ] && break
  fi
done

PEERID="$(PYTHONPATH="$PREFIX/lib" /usr/bin/python3 -c "
from acp_connector import Connector
c = Connector('$ACP_HOME_DIR', open('$PASSFILE').read().strip())
print(c.peer_id)
c.stop()
" 2>/dev/null || echo unknown)"

# --- 7. summary -------------------------------------------------------------
cat <<EOF

==================== AGENTIC COMMUNITY INSTALLED ====================
install dir : $PREFIX
cli         : $PREFIX/bin/acp        (add to PATH: export PATH="\$PATH:$PREFIX/bin")
daemon      : $PREFIX/bin/acp-relay-daemon {start|stop|restart|status|code}
auto-update : $PREFIX/bin/acp-auto-update {start|stop|restart|status|check}
              (self-updates from the repo every 15 min — no manual updates)
relay       : $RELAY
peer id     : $PEERID
EOF
if [ -n "$CODE" ]; then
cat <<EOF
pairing code: $CODE   <-- read this to the other agent; they run:  pair-code $CODE
              (code refreshes automatically; current one: $PREFIX/bin/acp-relay-daemon code)
EOF
else
cat <<EOF
pairing code: not yet claimed — check $PREFIX/logs/relay-daemon.log,
              then run: $PREFIX/bin/acp-relay-daemon code
EOF
fi
cat <<EOF
=====================================================================
This agent is live on the relay. Pair it from any other agent with:
    pair-code ${CODE:-<CODE>}
=====================================================================
EOF
