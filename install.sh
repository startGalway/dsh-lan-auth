#!/usr/bin/env bash
# dsh-lan-auth installer: password gate in front of the loopback DSH Web GUI.
#
#   ./install.sh                       # prompts for the access password
#   DSH_LAN_AUTH_PASSWORD=secret ./install.sh
#   ./install.sh --no-systemd          # only stage files, print a start command
#
# Requirements: node >= 20 on PATH, systemd (user) for the service path.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${DSH_LAN_AUTH_INSTALL_DIR:-$HOME/.local/share/dsh-lan-auth}"
UNIT_NAME="dsh-lan-auth.service"
HARNESS_UNIT="${DSH_LAN_AUTH_HARNESS_UNIT:-dsh-web}"
NO_SYSTEMD=0

for arg in "$@"; do
  case "$arg" in
    --no-systemd) NO_SYSTEMD=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

command -v node >/dev/null || { echo "node not found on PATH (need >= 20)" >&2; exit 1; }
NODE_BIN="$(command -v node)"

password="${DSH_LAN_AUTH_PASSWORD:-}"
if [ -z "$password" ]; then
  read -r -s -p "访问密码 (access password, >= 6 chars): " password
  echo
fi
if [ "${#password}" -lt 6 ]; then
  echo "password must be at least 6 characters" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0644 "$ROOT/packages/lan-auth/server.js" "$INSTALL_DIR/server.js"
install -m 0644 "$ROOT/scripts/patch-remote-web-ui.js" "$INSTALL_DIR/patch-remote-web-ui.js"

"$NODE_BIN" "$INSTALL_DIR/server.js" --set-password "$password"
echo "state dir: $HOME/.config/dsh-lan-auth"

if [ "$NO_SYSTEMD" -eq 1 ]; then
  echo
  echo "start it manually:"
  echo "  DSH_LAN_AUTH_UNIT=$HARNESS_UNIT $NODE_BIN $INSTALL_DIR/server.js"
  exit 0
fi

mkdir -p "$HOME/.config/systemd/user"
sed -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" \
    -e "s#__NODE__#$NODE_BIN#g" \
    -e "s#__HARNESS_UNIT__#$HARNESS_UNIT#g" \
    "$ROOT/deploy/dsh-lan-auth.service" > "$HOME/.config/systemd/user/$UNIT_NAME"

systemctl --user daemon-reload
systemctl --user enable --now "$UNIT_NAME"
sleep 1
systemctl --user --no-pager status "$UNIT_NAME" | head -12

echo
echo "listening addresses:"
ss -tln | grep ":${DSH_LAN_AUTH_PORT:-3080}" || true
echo
echo "next: run scripts/patch-remote-web-ui.js to drop the pairing screen, then reload the GUI"
