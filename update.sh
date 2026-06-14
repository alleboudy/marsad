#!/usr/bin/env bash
#
# marsad updater — copy the current code to /opt/marsad and restart every running
# instance, preserving each instance's env + config.json. Use this after editing
# marsad.py (e.g. `git pull`) so all deployed instances pick up the change:
#
#   sudo ./update.sh
#
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo ./update.sh"; exit 1; }

CODE_DIR=/opt/marsad
UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

[ -d "$CODE_DIR" ] || { echo "$CODE_DIR not found — run ./install.sh first."; exit 1; }

# Refresh code + the unit template (config/secrets/state are left untouched).
install -m 755 "$SRC_DIR/marsad.py" "$CODE_DIR/marsad.py"
[ -f "$SRC_DIR/marsad@.service" ] && install -m 644 "$SRC_DIR/marsad@.service" "$UNIT_DIR/marsad@.service"
systemctl daemon-reload

restarted=0
for u in $(systemctl list-units --plain --no-legend 'marsad@*' 'marsad.service' 2>/dev/null | awk '{print $1}'); do
  echo "restarting $u"
  systemctl restart "$u" && restarted=$((restarted + 1))
done
[ "$restarted" -eq 0 ] && echo "No running marsad instances found (nothing to restart)."
echo "Updated $CODE_DIR/marsad.py and restarted $restarted instance(s)."
