#!/usr/bin/env bash
#
# marsad installer — installs the daemon, systemd unit, config and secrets.
# Run as root:  sudo ./install.sh
#
# Non-interactive use: pre-set any of these env vars to skip the prompts:
#   MARSAD_SLACK_TOKEN  MARSAD_SLACK_CHANNEL  MARSAD_PANEL_TOKEN
#   MARSAD_CAP_GB  MARSAD_PANEL_HOST  MARSAD_PANEL_PORT
#
set -euo pipefail

CODE_DIR=/opt/marsad
CONF_DIR=/etc/marsad
STATE_DIR=/var/lib/marsad
UNIT=/etc/systemd/system/marsad.service
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo ./install.sh"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required."; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required."; exit 1; }

echo "== marsad installer =="

# --- nethogs (optional, for per-process/container attribution) ---------------
if ! command -v nethogs >/dev/null 2>&1; then
  echo "nethogs is not installed (needed for per-process attribution; interface"
  echo "totals work without it)."
  ans=Y
  [ -t 0 ] && { read -rp "Install nethogs now? [Y/n] " ans; ans=${ans:-Y}; }
  if [[ $ans =~ ^[Yy] ]]; then
    if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y nethogs || true
    elif command -v dnf     >/dev/null; then dnf install -y nethogs || true
    elif command -v yum     >/dev/null; then yum install -y nethogs || true
    elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm nethogs || true
    elif command -v zypper  >/dev/null; then zypper --non-interactive install nethogs || true
    elif command -v apk     >/dev/null; then apk add nethogs || true
    else echo "Unknown package manager — install 'nethogs' manually."; fi
  fi
fi

# --- collect settings --------------------------------------------------------
SLACK_TOKEN="${MARSAD_SLACK_TOKEN:-}"
SLACK_CHANNEL="${MARSAD_SLACK_CHANNEL:-}"
PANEL_TOKEN="${MARSAD_PANEL_TOKEN:-}"
CAP_GB="${MARSAD_CAP_GB:-5}"
PANEL_HOST="${MARSAD_PANEL_HOST:-0.0.0.0}"
PANEL_PORT="${MARSAD_PANEL_PORT:-8092}"

if [ -t 0 ]; then
  read -rp "Slack bot token (xoxb-…, blank to skip Slack for now): " v; SLACK_TOKEN=${v:-$SLACK_TOKEN}
  read -rp "Slack channel / DM id (C…/D…/U…): " v;                    SLACK_CHANNEL=${v:-$SLACK_CHANNEL}
  read -rp "Cap-alert threshold in GB per window [${CAP_GB}]: " v;     CAP_GB=${v:-$CAP_GB}
  read -rp "Panel bind host (0.0.0.0 | localhost | tailscale | <ip>) [${PANEL_HOST}]: " v; PANEL_HOST=${v:-$PANEL_HOST}
  read -rp "Panel port [${PANEL_PORT}]: " v;                          PANEL_PORT=${v:-$PANEL_PORT}
fi

# Auto-generate an admin token if none given (the panel default binds 0.0.0.0).
GEN_TOKEN=
if [ -z "$PANEL_TOKEN" ]; then
  PANEL_TOKEN="$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  GEN_TOKEN=1
fi

# --- install files -----------------------------------------------------------
install -d -m 755 "$CODE_DIR"
install -m 755 "$SRC_DIR/marsad.py" "$CODE_DIR/marsad.py"
install -d -m 750 "$CONF_DIR"
install -d -m 750 "$STATE_DIR"

umask 077
cat > "$CONF_DIR/marsad.env" <<EOF
# marsad secrets / install settings — keep mode 0600.
MARSAD_SLACK_TOKEN=$SLACK_TOKEN
MARSAD_SLACK_CHANNEL=$SLACK_CHANNEL
# Admin token required to change settings via the panel (recommended when the
# panel is reachable on the network). Blank = no auth.
MARSAD_PANEL_TOKEN=$PANEL_TOKEN
EOF
chmod 600 "$CONF_DIR/marsad.env"

# Seed the tunables the user chose (the daemon fills the rest from its defaults).
cat > "$STATE_DIR/config.json" <<EOF
{
  "cap_gb": $CAP_GB,
  "panel_host": "$PANEL_HOST",
  "panel_port": $PANEL_PORT
}
EOF
chmod 600 "$STATE_DIR/config.json"

install -m 644 "$SRC_DIR/marsad.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now marsad.service

# --- report ------------------------------------------------------------------
sleep 2
echo
systemctl --no-pager --full status marsad.service | sed -n '1,6p' || true
echo
echo "marsad installed and started."
echo "  Panel:   http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PANEL_PORT  (bind: $PANEL_HOST)"
[ -n "$GEN_TOKEN" ] && {
  echo "  Admin token (needed to change settings in the panel):"
  echo "      $PANEL_TOKEN"
}
[ "$PANEL_HOST" = "0.0.0.0" ] && [ -z "$PANEL_TOKEN" ] && \
  echo "  WARNING: panel on 0.0.0.0 with no admin token — anyone on the network can change settings."
echo "  Secrets:  $CONF_DIR/marsad.env   Tunables: $STATE_DIR/config.json (or the panel, live)"
echo "  Logs:     journalctl -u marsad -f"
