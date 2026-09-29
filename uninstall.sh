#!/usr/bin/env bash
# Agentic-Community uninstaller. Removes what install.sh installed.
#
#   ./uninstall.sh [--prefix DIR] [--keep-identity]
#
# --keep-identity keeps $PREFIX/acp-home (the agent's keypair) and the
# passphrase so a later reinstall resurrects the SAME agent.
set -euo pipefail

PREFIX="${ACP_HOME:-$HOME/.acp}"
KEEP_IDENTITY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --keep-identity) KEEP_IDENTITY=1; shift;;
    -h|--help) sed -n '2,8p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 1;;
  esac
done

echo "uninstalling Agentic-Community from $PREFIX"

# stop the relay daemon
if [ -x "$PREFIX/bin/acp-relay-daemon" ]; then
  "$PREFIX/bin/acp-relay-daemon" stop 2>/dev/null || true
fi

# stop the runtime supervisor
if [ -x "$PREFIX/bin/vm-agent" ]; then
  "$PREFIX/bin/vm-agent" stop 2>/dev/null || true
fi
pkill -f "vmagent.supervisor" 2>/dev/null || true
pkill -f "acp_relay_daemon.daemon" 2>/dev/null || true

# remove systemd units if we created them
for u in /etc/systemd/system/vm-agent.service \
         "$HOME/.config/systemd/user/vm-agent.service" \
         /etc/systemd/system/acp-relay-daemon.service \
         "$HOME/.config/systemd/user/acp-relay-daemon.service"; do
  [ -f "$u" ] && { echo "removing $u (needs sudo for /etc)"; rm -f "$u" 2>/dev/null || sudo rm -f "$u" || true; }
done
systemctl --user daemon-reload 2>/dev/null || true

if [ "$KEEP_IDENTITY" = "1" ]; then
  echo "keeping identity: $PREFIX/acp-home"
  for d in bin lib state logs run; do rm -rf "$PREFIX/$d"; done
  rm -f "$PREFIX/config/config.json"
  echo "removed code, state, logs. Reinstall to resurrect this agent."
else
  rm -rf "$PREFIX"
  echo "removed $PREFIX entirely (identity destroyed)."
fi
echo "done."
