# marsad &nbsp;مرصد

> *marsad* (Arabic: مرصد, "observatory / watch-post") — a small, self-contained host bandwidth observatory for Linux.

`marsad` watches a host's network usage at the NIC level, attributes traffic to processes and containers, sends you an hourly Slack digest of **download / upload / total**, and fires a **cap alert** when usage in a rolling window crosses a threshold — the guardrail that turns a silent multi-GB bandwidth bleed into a Slack ping. A tiny web panel lets you see live usage and change the settings.

It is one Python file (standard library only) plus a hardened systemd unit. No agents, no database server, no cloud.

---

## Features

- **NIC-level truth** — reads `/proc/net/dev` per interface; reports download, upload, and total. Handles reboots and counter resets.
- **Per-process / container attribution** — via `nethogs` (optional). Long-lived flows are attributed to the program or docker container; short-lived ones are shown by their (reverse-DNS'd) remote endpoint. Each digest reports the **% attributed to a process** so the breakdown is honest.
- **Hourly Slack digest** — independent knobs for *how often* you're notified (report interval) and *how much history* each report covers (summary window).
- **Cap alert** — a louder Slack alert when a rolling window exceeds `cap_gb` (default 5 GB), with a cooldown that is only consumed on confirmed delivery.
- **Live admin panel** — view current/window/today usage + top talkers, and change the knobs without a restart. Optional admin-token auth.
- **Hardened** — runs under a tight systemd sandbox (minimal capabilities, `ProtectSystem=strict`, private state dir, 0600 secrets).

---

## Requirements

- Linux with **systemd**
- **Python 3.8+** (standard library only)
- **`nethogs`** — optional, for the per-process/container breakdown (interface totals work without it). The installer offers to install it.
- A **Slack bot token** with `chat:write`, and the channel/DM id to post to (optional — the panel works without Slack).

---

## Install

```bash
git clone <your-repo-url> marsad
cd marsad
sudo ./install.sh
```

The installer asks for your Slack token, channel, cap threshold, and panel bind address/port; installs the daemon to `/opt/marsad`, secrets to `/etc/marsad/marsad.env`, and state to `/var/lib/marsad`; then enables the `marsad` service. It auto-generates a panel **admin token** and prints it.

Non-interactive (e.g. config management): pre-set `MARSAD_SLACK_TOKEN`, `MARSAD_SLACK_CHANNEL`, `MARSAD_PANEL_TOKEN`, `MARSAD_CAP_GB`, `MARSAD_PANEL_HOST`, `MARSAD_PANEL_PORT` and the prompts are skipped.

```bash
journalctl -u marsad -f          # logs
sudo ./uninstall.sh              # remove
```

---

## Configuration

**Secrets / install settings** live in `/etc/marsad/marsad.env` (mode 0600, loaded by systemd):

| Variable | Purpose |
|---|---|
| `MARSAD_SLACK_TOKEN` | Slack bot token (`xoxb-…`). Blank disables Slack. |
| `MARSAD_SLACK_CHANNEL` | Default channel/DM id (`C…`/`D…`/`U…`). |
| `MARSAD_PANEL_TOKEN` | Admin token to change settings via the panel. Blank = no auth. |

**Tunables** live in `/var/lib/marsad/config.json` and are editable **live in the panel** (see `config.example.json`):

| Key | Default | Notes |
|---|---|---|
| `report_interval_min` | 60 | How often a digest is sent. |
| `summary_window_min` | 60 | How much history each digest + the cap covers. |
| `cap_gb` | 5.0 | Alert if the window exceeds this many GB (0 = off). |
| `cap_cooldown_min` | 30 | Minimum minutes between cap alerts. |
| `sample_interval_sec` | 60 | How often counters are sampled. |
| `nethogs_delay_sec` | 5 | nethogs refresh granularity. *(restart to change)* |
| `uplink_iface` | `auto` | `auto` = the default-route interface. *(restart to change)* |
| `panel_host` | `0.0.0.0` | `0.0.0.0` \| `localhost` \| `tailscale` \| an IP. *(restart to change)* |
| `panel_port` | 8092 | Panel TCP port. *(restart to change)* |
| `retention_days` | 8 | Drop samples older than this. |
| `slack_channel` | `""` | Overrides `MARSAD_SLACK_CHANNEL` when set. |
| `resolve_names` | 1 | Reverse-DNS endpoint IPs to hostnames (1/0). |

Report interval and summary window are **independent**: e.g. report every 30 min summarising the last 120 min.

---

## The admin panel

`http://<host>:<panel_port>` shows live / window / today usage (down·up·total), the top talkers with their share of WAN, the % attributed to a process, and a form to change the live knobs.

**Security:** the panel can *change settings*, so by default it requires the **admin token** (`MARSAD_PANEL_TOKEN`) to save changes — viewing is open. The default bind is `0.0.0.0` (reachable on the LAN); set `panel_host` to `localhost` and reach it via an SSH tunnel, or to `tailscale` to bind your Tailscale IP, if you prefer not to expose it. If you bind `0.0.0.0` with no token, the daemon logs a warning.

---

## Slack setup

1. Create a Slack app → add a **Bot Token Scope** of `chat:write` → install to your workspace → copy the **Bot User OAuth Token** (`xoxb-…`).
2. Invite the bot to the target channel (`/invite @your-bot`), or use a DM/user id.
3. Find the channel id (channel details → bottom, `C…`) and put the token + id in `marsad.env` (the installer does this).

---

## How attribution works

`marsad` reads authoritative byte counters from `/proc/net/dev`. For the *who*, it runs `nethogs -t` on the uplink. Some `nethogs` builds report cumulative per-connection totals in trace mode, which `marsad` handles by accumulating per-key deltas. nethogs maps **long-lived** flows (the kind a real bandwidth bleed produces) to the owning process/container; **short-lived** connections it can't map are shown by their remote endpoint (reverse-DNS'd to a hostname when possible). The digest always states what fraction of the window was attributed to a named process, so you know how much of the breakdown is process-level vs endpoint-level.

---

## Security notes

`marsad` runs as root because per-process network accounting needs raw sockets (pcap) and the ability to read other users' `/proc/<pid>` to map sockets to processes. The systemd unit drops it to only `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH` and sandboxes the filesystem (`ProtectSystem=strict`, `ProtectHome=true`, private writable state dir, restricted address families, `NoNewPrivileges`). Secrets and the SQLite history are created 0600. The config-mutating panel is protected by the admin token.

---

## License

MIT — see [LICENSE](LICENSE).
