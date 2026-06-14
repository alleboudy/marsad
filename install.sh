#!/usr/bin/env bash
#
# marsad installer — installs the daemon + a templated systemd unit, and configures
# one or more instances. Run as root:
#
#   sudo ./install.sh                 # interactive; asks which instance(s)
#   sudo ./install.sh host            # NIC + per-process monitor (the classic mode)
#   sudo ./install.sh network         # poll an LTE/router for whole-network usage
#   sudo ./install.sh both            # both, on separate panel ports
#
# Each instance is a systemd template unit `marsad@<name>` with its own state dir
# (/var/lib/marsad-<name>), env file (/etc/marsad/<name>.env), config.json and port.
#
# Non-interactive (config management): pre-set any of these and the prompts are
# skipped (applied to the instance being installed):
#   MARSAD_SLACK_TOKEN  MARSAD_SLACK_CHANNEL  MARSAD_PANEL_TOKEN
#   MARSAD_CAP_GB  MARSAD_PANEL_HOST  MARSAD_PANEL_PORT
#   MARSAD_ROUTER_HOST  MARSAD_ROUTER_PASSWORD  MARSAD_AGENT_ENDPOINTS (comma list)
#
set -euo pipefail

CODE_DIR=/opt/marsad
CONF_DIR=/etc/marsad
UNIT_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
NET_USER=marsad   # unprivileged user for the router/network instance

[ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo ./install.sh"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required."; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required."; exit 1; }

# --- which instances? --------------------------------------------------------
SEL="${1:-}"
if [ -z "$SEL" ]; then
  if [ -t 0 ]; then
    read -rp "Install which instance? [host/network/both] (host): " SEL; SEL=${SEL:-host}
  else
    SEL=host
  fi
fi
case "$SEL" in
  host)    INSTANCES=(host) ;;
  network) INSTANCES=(network) ;;
  both)    INSTANCES=(host network) ;;
  *) echo "Unknown selection '$SEL' (use host | network | both)"; exit 1 ;;
esac

gen_token() { openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

install_nethogs() {
  command -v nethogs >/dev/null 2>&1 && return 0
  echo "nethogs is not installed (needed for host-mode per-process attribution)."
  ans=Y; [ -t 0 ] && { read -rp "Install nethogs now? [Y/n] " ans; ans=${ans:-Y}; }
  [[ $ans =~ ^[Yy] ]] || return 0
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y nethogs || true
  elif command -v dnf     >/dev/null; then dnf install -y nethogs || true
  elif command -v yum     >/dev/null; then yum install -y nethogs || true
  elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm nethogs || true
  elif command -v zypper  >/dev/null; then zypper --non-interactive install nethogs || true
  elif command -v apk     >/dev/null; then apk add nethogs || true
  else echo "Unknown package manager — install 'nethogs' manually."; fi
}

# --- shared code + unit ------------------------------------------------------
echo "== marsad installer =="
install -d -m 755 "$CODE_DIR"
install -m 755 "$SRC_DIR/marsad.py" "$CODE_DIR/marsad.py"
install -d -m 750 "$CONF_DIR"
install -m 644 "$SRC_DIR/marsad@.service" "$UNIT_DIR/marsad@.service"
systemctl daemon-reload

# --- per-instance ------------------------------------------------------------
install_instance() {
  local name="$1" mode port default_cap state envf
  state="/var/lib/marsad-$name"
  envf="$CONF_DIR/$name.env"
  if [ "$name" = "network" ]; then mode=network; port=8093; default_cap=3
  else mode=host; port=8092; default_cap=5; fi

  local SLACK_TOKEN SLACK_CHANNEL PANEL_TOKEN CAP_GB PANEL_HOST PANEL_PORT
  local ROUTER_HOST ROUTER_PASSWORD AGENT_ENDPOINTS
  SLACK_TOKEN="${MARSAD_SLACK_TOKEN:-}"; SLACK_CHANNEL="${MARSAD_SLACK_CHANNEL:-}"
  PANEL_TOKEN="${MARSAD_PANEL_TOKEN:-}"; CAP_GB="${MARSAD_CAP_GB:-$default_cap}"
  PANEL_HOST="${MARSAD_PANEL_HOST:-0.0.0.0}"; PANEL_PORT="${MARSAD_PANEL_PORT:-$port}"
  ROUTER_HOST="${MARSAD_ROUTER_HOST:-}"; ROUTER_PASSWORD="${MARSAD_ROUTER_PASSWORD:-}"
  AGENT_ENDPOINTS="${MARSAD_AGENT_ENDPOINTS:-}"

  echo; echo "--- configuring marsad@$name (mode=$mode) ---"
  if [ -t 0 ]; then
    read -rp "Slack bot token (xoxb-…, blank to skip): " v; SLACK_TOKEN=${v:-$SLACK_TOKEN}
    read -rp "Slack channel / DM id (C…/D…/U…): " v;       SLACK_CHANNEL=${v:-$SLACK_CHANNEL}
    read -rp "Cap-alert threshold in GB per window [$CAP_GB]: " v; CAP_GB=${v:-$CAP_GB}
    read -rp "Panel bind (0.0.0.0|localhost|tailscale|<ip>) [$PANEL_HOST]: " v; PANEL_HOST=${v:-$PANEL_HOST}
    read -rp "Panel port [$PANEL_PORT]: " v;               PANEL_PORT=${v:-$PANEL_PORT}
    if [ "$mode" = network ]; then
      read -rp "Router IP/host (e.g. 192.168.0.1): " v;    ROUTER_HOST=${v:-$ROUTER_HOST}
      read -rsp "Router admin password (stored 0600, never logged): " v; echo; ROUTER_PASSWORD=${v:-$ROUTER_PASSWORD}
      read -rp "Agent endpoints to aggregate (comma URLs, optional): " v; AGENT_ENDPOINTS=${v:-$AGENT_ENDPOINTS}
    fi
  fi

  local GEN_TOKEN=""
  if [ -z "$PANEL_TOKEN" ]; then PANEL_TOKEN="$(gen_token)"; GEN_TOKEN=1; fi

  # secrets -> env file (0600)
  umask 077
  {
    echo "# marsad@$name secrets / install settings — keep mode 0600."
    echo "MARSAD_SLACK_TOKEN=$SLACK_TOKEN"
    echo "MARSAD_SLACK_CHANNEL=$SLACK_CHANNEL"
    echo "MARSAD_PANEL_TOKEN=$PANEL_TOKEN"
    [ "$mode" = network ] && echo "MARSAD_ROUTER_PASSWORD=$ROUTER_PASSWORD"
  } > "$envf"
  chmod 600 "$envf"

  # network instance: dedicated unprivileged user + caps-drop drop-in
  if [ "$mode" = network ]; then
    id -u "$NET_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$NET_USER" 2>/dev/null || \
      useradd --system --no-create-home --shell /sbin/nologin "$NET_USER" 2>/dev/null || true
    install -d -m 755 "$UNIT_DIR/marsad@network.service.d"
    # use the dedicated user (deterministic ownership so we can pre-seed config.json)
    sed "s/^DynamicUser=yes/User=$NET_USER/" "$SRC_DIR/marsad@network.override.conf" \
      > "$UNIT_DIR/marsad@network.service.d/override.conf"
    systemctl daemon-reload
  fi

  # state dir + seed config.json (the daemon fills the rest from DEFAULTS)
  install -d -m 750 "$state"
  local AE_JSON="[]"
  if [ -n "$AGENT_ENDPOINTS" ]; then
    AE_JSON=$(printf '%s' "$AGENT_ENDPOINTS" | awk -F, '{printf "[";for(i=1;i<=NF;i++){gsub(/^ +| +$/,"",$i);printf "%s\"%s\"",(i>1?",":""),$i}printf "]"}')
  fi
  if [ "$mode" = network ]; then
    cat > "$state/config.json" <<EOF
{
  "mode": "network",
  "cap_gb": $CAP_GB,
  "summary_window_min": 60,
  "panel_host": "$PANEL_HOST",
  "panel_port": $PANEL_PORT,
  "router_host": "$ROUTER_HOST",
  "agent_endpoints": $AE_JSON,
  "device_names": {}
}
EOF
    chown -R "$NET_USER":"$NET_USER" "$state" 2>/dev/null || true
  else
    cat > "$state/config.json" <<EOF
{
  "mode": "host",
  "cap_gb": $CAP_GB,
  "panel_host": "$PANEL_HOST",
  "panel_port": $PANEL_PORT
}
EOF
  fi
  chmod 600 "$state/config.json"

  systemctl enable --now "marsad@$name.service"
  sleep 1
  echo "  marsad@$name: panel http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PANEL_PORT (bind $PANEL_HOST)"
  [ -n "$GEN_TOKEN" ] && echo "    admin token: $PANEL_TOKEN"
  echo "    secrets: $envf   tunables: $state/config.json (or the panel, live)"
  echo "    logs:    journalctl -u marsad@$name -f"
}

for inst in "${INSTANCES[@]}"; do
  [ "$inst" = host ] && install_nethogs
  install_instance "$inst"
done

echo; echo "Done. To upgrade after editing the code:  sudo ./update.sh"
