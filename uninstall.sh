#!/usr/bin/env bash
# marsad uninstaller. Run as root: sudo ./uninstall.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo ./uninstall.sh"; exit 1; }

UNIT_DIR=/etc/systemd/system

# Stop + disable the template instances and the legacy single-instance unit.
for unit in marsad@host marsad@network marsad; do
  systemctl disable --now "$unit.service" 2>/dev/null || true
done
# Catch any other marsad@* instances that were created.
for u in $(systemctl list-units --all --plain --no-legend 'marsad@*' 2>/dev/null | awk '{print $1}'); do
  systemctl disable --now "$u" 2>/dev/null || true
done

rm -f "$UNIT_DIR/marsad@.service" "$UNIT_DIR/marsad.service"
rm -rf "$UNIT_DIR/marsad@network.service.d"
systemctl daemon-reload
rm -rf /opt/marsad
echo "Removed the marsad service(s) and code (/opt/marsad)."

if [ -t 0 ]; then
  read -rp "Also delete config + data (/etc/marsad and /var/lib/marsad*)? [y/N] " a
  if [[ ${a:-N} =~ ^[Yy] ]]; then
    rm -rf /etc/marsad /var/lib/marsad /var/lib/marsad-*
    echo "Deleted /etc/marsad and /var/lib/marsad*."
  else
    echo "Kept /etc/marsad (secrets) and /var/lib/marsad* (history)."
  fi
fi
