# marsad &nbsp;مرصد

> *marsad* (Arabic: مرصد, "observatory / watch-post") — a small, self-contained bandwidth observatory for Linux.

`marsad` watches network usage, sends you an hourly Slack digest of **download / upload / total**, and fires a **cap alert** when usage in a rolling window crosses a threshold — the guardrail that turns a silent multi-GB bandwidth bleed into a Slack ping. A tiny web panel shows live usage, a rate graph, and lets you change the settings.

It runs in one of two modes, from the same single Python file (standard library only — no pip, no agents, no database server, no cloud):

- **host mode** — watches *this machine's* NICs at the `/proc/net/dev` level and attributes traffic to processes/containers via `nethogs`. Includes a one-click "stop the top consumers" button.
- **router/network mode** — polls a **TP-Link M7200**-class LTE/Mi-Fi router for **whole-network** usage and the list of connected devices. Every device behind the router rolls up into one WAN total + the 3-GB-style cap.

You can run both at once as two systemd instances (`marsad@host` + `marsad@network`) on one box.

---

## Features

- **NIC-level truth** (host) / **whole-network truth** (router) — authoritative byte counters; reports download, upload, total. Handles reboots and counter resets.
- **Per-process / container attribution** (host) — via `nethogs`. Each digest reports the **% attributed to a process** so the breakdown is honest.
- **Hourly Slack digest** — independent knobs for *how often* you're notified and *how much history* each report covers.
- **Cap alert** — a louder Slack alert when a rolling window exceeds `cap_gb`, with a cooldown only consumed on confirmed delivery.
- **Projected next-1h consumption** and a **server-side SVG rate graph** (stdlib only — no JS libraries) in both the digest and the panel.
- **Stop top consumers** (host) — a panel button that SIGTERM→SIGKILLs the *daemon-computed* heaviest local processes, with a hard allowlist that never touches critical processes.
- **Live admin panel** — view current/window/today usage + the graph + top talkers (host) or connected devices (router), and change knobs without a restart. Optional admin-token auth.
- **Hardened** — tight systemd sandbox (minimal capabilities, `ProtectSystem=strict`, private state dir, 0600 secrets); the router instance runs fully unprivileged.

---

## Requirements

- Linux with **systemd**
- **Python 3.8+** (standard library only — no third-party packages, ever)
- **`nethogs`** (host mode, optional) — for the per-process breakdown; interface totals work without it. The installer offers to install it.
- A **Slack bot token** with `chat:write` and the channel/DM id to post to (optional — the panel works without Slack).
- *(router mode)* a TP-Link **M7200** (or firmware sibling) reachable on the LAN, and its admin password.

---

## Install

```bash
git clone <your-repo-url> marsad
cd marsad
sudo ./install.sh            # interactive — asks host / network / both
# or non-interactively:
sudo ./install.sh host       # NIC + per-process monitor
sudo ./install.sh network    # whole-network via the router
sudo ./install.sh both       # both, on separate panel ports (8092 / 8093)
```

The installer collects each instance's settings; installs the daemon to `/opt/marsad`, the templated unit to `/etc/systemd/system/marsad@.service`, secrets to `/etc/marsad/<instance>.env` (0600), and state to `/var/lib/marsad-<instance>`; then enables `marsad@<instance>`. It auto-generates a panel **admin token** and prints it. The **network** instance is installed as a dedicated unprivileged user with all host capabilities dropped.

```bash
journalctl -u marsad@host -f        # logs (host instance)
journalctl -u marsad@network -f     # logs (network instance)
sudo ./update.sh                    # after editing the code: refresh + restart all instances
sudo ./uninstall.sh                 # remove
```

`update.sh` is the unify path: edit `marsad.py` (or `git pull`), run `sudo ./update.sh`, and **every** installed instance picks up the change.

---

## Router / network mode (TP-Link M7200)

In `mode: "network"`, marsad authenticates to the router's local admin API and, each `router_poll_sec`, reads:

- the **whole-SIM WAN total** (cumulative bytes) → the down/up/total figures and the rolling cap;
- the **connected-device list** (name / MAC / IP) → who is currently online.

Set `router_host` and put the admin password in `MARSAD_ROUTER_PASSWORD` (env, 0600 — never in `config.json`). Point the cap at the whole network with `cap_gb` (e.g. `3`) over `summary_window_min: 60` for "3 GB per hour".

**What it can and cannot do — read this.** The M7200 exposes only a *whole-network total* and a *presence list*; it has **no per-device byte counters**. So marsad does **not** invent per-device usage. For genuine per-machine numbers, run a marsad **host** instance on the machines you control and list them in `agent_endpoints` — the router instance aggregates each host's own measured usage and shows the remainder as **"other / uninstrumented devices (combined)"** (phones, TVs, guests — which cannot be split apart by this router). Every router digest says this plainly.

**Two safety properties you should know:**

- **Single admin session.** The M7200 allows only one admin logged in at a time. marsad logs in **once** and reuses the session; when someone opens the tpMiFi app/web UI it transiently evicts the poller, which politely waits `router_reauth_cooldown_sec` before reclaiming the slot (so the two don't fight).
- **No lockout storms.** A wrong password is never retried in a loop. After `router_auth_fail_limit` rejections marsad stops trying for `router_lockout_backoff_min` minutes, posts **one** Slack alert, and keeps everything else running. This prevents a bad credential from locking the whole household out of the router for hours.

> The router admin channel is plaintext HTTP on the LAN (the device's native protocol). marsad implements the encrypted handshake (AES-128-CBC + RSA, pure stdlib) where the firmware requires it, with a plaintext fallback for older firmware. The crypto primitives are verified against FIPS-197 / OpenSSL; confirm the exact field names against your unit on first run (`journalctl -u marsad@network -f`).

---

## Configuration

**Secrets** live in `/etc/marsad/<instance>.env` (mode 0600, loaded by systemd):

| Variable | Purpose |
|---|---|
| `MARSAD_SLACK_TOKEN` | Slack bot token (`xoxb-…`). Blank disables Slack. |
| `MARSAD_SLACK_CHANNEL` | Default channel/DM id (`C…`/`D…`/`U…`). |
| `MARSAD_PANEL_TOKEN` | Admin token to change settings via the panel; **required** for the host stop-top action. |
| `MARSAD_ROUTER_PASSWORD` | *(network)* router admin password. Never logged or shown. |

**Tunables** live in `/var/lib/marsad-<instance>/config.json` and are editable **live in the panel** (see `config.example.json`):

| Key | Default | Notes |
|---|---|---|
| `mode` | `host` | `host` or `network`/`router`. *(restart)* |
| `report_interval_min` | 60 | How often a digest is sent. |
| `summary_window_min` | 60 | History each digest + the cap covers. |
| `cap_gb` | 5.0 | Alert if the window exceeds this many GB (0 = off). |
| `cap_cooldown_min` | 30 | Minimum minutes between cap alerts. |
| `sample_interval_sec` | 60 | How often counters are sampled. |
| `projection_window_min` | 5 | Rate basis for the projected next-1h figure. |
| `graph_window_min` | 120 | Time span shown in the panel rate graph. |
| `resolve_names` | 1 | Reverse-DNS endpoint IPs to hostnames (host). |
| `nethogs_delay_sec` | 5 | nethogs refresh granularity (host). *(restart)* |
| `uplink_iface` | `auto` | `auto` = the default-route interface (host). *(restart)* |
| `stop_top_n` / `stop_grace_sec` | 3 / 8 | host stop-top: how many PIDs, and SIGTERM→SIGKILL grace. |
| `protected_procs` | `[]` | extra process-name substrings stop-top must never kill. |
| `panel_host` / `panel_port` | `0.0.0.0` / 8092 | Panel bind + port. *(restart)* |
| `retention_days` | 8 | Drop samples older than this. |
| `slack_channel` | `""` | Overrides `MARSAD_SLACK_CHANNEL` when set. |
| `router_host` | `""` | *(network)* router IP/host. *(restart)* |
| `router_poll_sec` | 30 | *(network)* router poll cadence. |
| `router_auth_fail_limit` / `router_lockout_backoff_min` | 2 / 240 | *(network)* lockout safety. |
| `router_reauth_cooldown_sec` | 120 | *(network)* anti-session-thrash. |
| `router_max_delta_mb` | 0 | *(network)* clamp any single WAN delta (0 = off). |
| `agent_endpoints` | `[]` | *(network)* marsad host URLs to aggregate per-host. *(restart)* |
| `device_names` | `{}` | *(network)* MAC → friendly name for the presence list. |

---

## The admin panel

`http://<host>:<panel_port>` shows live / window / today usage, the projected next-1h, an SVG rate graph, and — depending on mode — the top talkers (host) or the connected devices (router). It also has the settings form and, in host mode, the **stop top consumers** button.

**Security:** the config-mutating actions require the **admin token** (`MARSAD_PANEL_TOKEN`); viewing is open. The stop-top action additionally refuses to run unless a token is configured. The default bind is `0.0.0.0`; set `panel_host` to `localhost` (reach it via SSH tunnel) or `tailscale` (bind your Tailscale IP) if you prefer not to expose it. Binding `0.0.0.0` with no token logs a warning.

---

## Security notes

The **host** instance runs as root because per-process accounting needs raw sockets (pcap) and reading other users' `/proc/<pid>`; the unit drops it to `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH` (+ `CAP_KILL` for stop-top) and sandboxes the filesystem. The **network** instance needs none of that — it runs as an unprivileged user with all capabilities dropped (it only makes outbound HTTP). Secrets and the SQLite history are 0600. Stop-top only ever targets daemon-computed PIDs (never a value from the request), re-checks the protected-process allowlist at kill time, and excludes pid≤1, marsad itself and its process group, `sshd`, `dockerd`, `systemd`/`init`, plus anything in `protected_procs`.

---

## License

MIT — see [LICENSE](LICENSE).
