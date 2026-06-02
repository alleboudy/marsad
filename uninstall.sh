#!/usr/bin/env bash
# marsad uninstaller. Run as root: sudo ./uninstall.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo ./uninstall.sh"; exit 1; }

systemctl disable --now marsad.service 2>/dev/null || true
rm -f /etc/systemd/system/marsad.service
systemctl daemon-reload
rm -rf /opt/marsad
echo "Removed the service and code (/opt/marsad)."

if [ -t 0 ]; then
  read -rp "Also delete config + data (/etc/marsad and /var/lib/marsad)? [y/N] " a
  if [[ ${a:-N} =~ ^[Yy] ]]; then
    rm -rf /etc/marsad /var/lib/marsad
    echo "Deleted /etc/marsad and /var/lib/marsad."
  else
    echo "Kept /etc/marsad (secrets) and /var/lib/marsad (history)."
  fi
fi
