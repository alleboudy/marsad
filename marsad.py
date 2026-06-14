#!/usr/bin/env python3
"""
marsad — a small host bandwidth observatory.

(مرصد, "observatory / watch-post")

What it does
------------
* Samples /proc/net/dev per-interface byte counters every `sample_interval_sec`
  (authoritative totals; handles reboot/counter resets per-direction).
* Optionally runs `nethogs -t` on the WAN uplink and attributes traffic to
  processes / docker containers. Some nethogs builds emit *cumulative* per-connection
  totals in trace mode, so weights are accumulated as per-key deltas. Connections
  nethogs can't map to a pid are labelled by their (reverse-DNS'd) remote endpoint;
  the digest reports how much of the window was attributed to a named process.
* Stores per-interval deltas in SQLite so arbitrary summary windows + history work.
  Report cadence and the last-report/cap-alert timestamps survive restarts.
* Sends a usage digest to Slack every `report_interval_min` summarising the last
  `summary_window_min` (the two knobs are independent): download / upload / total,
  per-interface, and top talkers.
* Fires a louder Slack cap-alert (with cooldown, only consumed on confirmed
  delivery) when the rolling summary window exceeds `cap_gb`.
* Serves a tiny admin panel to view usage and change the knobs live, optionally
  protected by an admin token.

Configuration
-------------
* Tunables: <state-dir>/config.json (hot-reloaded each cycle; panel-editable).
* Secrets / install settings come from the environment (a systemd EnvironmentFile,
  or `<config-dir>/marsad.env`):
    MARSAD_SLACK_TOKEN    Slack bot token (xoxb-...)            [required to send]
    MARSAD_SLACK_CHANNEL  default channel/DM id (C…/D…/U…)      [optional]
    MARSAD_PANEL_TOKEN    admin token required to change config [optional, recommended]
    MARSAD_ENV            path to the env file (default /etc/marsad/marsad.env)
    STATE_DIRECTORY       state dir (set by systemd; default /var/lib/marsad)

Stdlib only. `nethogs` is optional: without it the tool still reports interface
totals, just without the per-process breakdown.
"""

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime

HOST = socket.gethostname()
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/marsad").split(":")[0]
CONFIG_PATH = os.path.join(STATE_DIR, "config.json")
DB_PATH = os.path.join(STATE_DIR, "marsad.db")
ENV_FILE = os.environ.get("MARSAD_ENV", "/etc/marsad/marsad.env")

DEFAULTS = {
    "mode": "host",                # "host" (NIC + nethogs) or "router"/"network" (poll a gateway) (restart)
    "report_interval_min": 60,     # how often a digest is sent (live)
    "summary_window_min": 60,      # how much history each digest + the cap covers (live)
    "cap_gb": 5.0,                 # alert if the summary window exceeds this many GB (0 = off, live)
    "cap_cooldown_min": 30,        # min minutes between cap alerts (live)
    "sample_interval_sec": 60,     # how often counters are sampled (live)
    "nethogs_delay_sec": 5,        # nethogs refresh granularity (re-applied on change)
    "uplink_iface": "auto",        # "auto" = interface holding the default route (re-applied)
    "panel_host": "0.0.0.0",       # bind addr: 0.0.0.0 | localhost | tailscale | <ip> (restart-only)
    "panel_port": 8092,            # restart-only
    "retention_days": 8,           # prune samples older than this (live)
    "slack_channel": "",           # overrides MARSAD_SLACK_CHANNEL when set (live)
    "resolve_names": 1,            # reverse-DNS endpoint IPs to hostnames (1=on, 0=off, live)
    "projection_window_min": 5,    # rate basis for the projected next-1h figure (live)
    "graph_window_min": 120,       # time span shown in the panel SVG rate graph (live)
    "stop_top_n": 3,               # how many top WAN PIDs the stop-top button targets (host, live)
    "stop_grace_sec": 8,           # SIGTERM->SIGKILL grace for stop-top (host, live)
    "protected_procs": [],         # extra process-name substrings stop-top must never kill (config.json, hot-reloaded)
    # --- router/network mode (mode="router"/"network"): poll a gateway router -----
    "router_host": "",             # router IP/hostname, e.g. 192.168.0.1 (restart)
    "router_iface_label": "WAN",   # synthetic interface name for the router's uplink (restart)
    "router_poll_sec": 30,         # how often the router HTTP API is polled (live)
    "router_auth_fail_limit": 2,   # consecutive credential rejections before locking out (live)
    "router_lockout_backoff_min": 240,  # long backoff after a credential lockout (live)
    "router_net_backoff_max_sec": 600,  # cap for transient-error exponential backoff (live)
    "router_reauth_cooldown_sec": 120,  # min gap before re-grabbing the single admin slot (live)
    "router_max_delta_mb": 0,      # clamp any single WAN delta to this many MB (0 = off, live)
    "agent_endpoints": [],         # marsad host-instance URLs to aggregate per-host (restart)
    "device_names": {},            # MAC -> friendly name for the presence list (config.json, hot-reloaded)
}

INTRAHOST_PREFIXES = ("lo", "docker", "br-", "veth", "tailscale")
LIVE_KEYS = ("report_interval_min", "summary_window_min", "cap_gb",
             "cap_cooldown_min", "sample_interval_sec", "resolve_names",
             "projection_window_min", "graph_window_min", "stop_top_n", "stop_grace_sec",
             "router_poll_sec", "router_auth_fail_limit", "router_lockout_backoff_min",
             "router_net_backoff_max_sec", "router_reauth_cooldown_sec", "router_max_delta_mb")
IFACE_RE = re.compile(r"auto|[A-Za-z0-9_.][A-Za-z0-9._-]{0,14}")
HOST_RE = re.compile(r"[A-Za-z0-9.:_-]{1,45}")

CLAMP = {
    "report_interval_min": (1, 1440),
    "summary_window_min": (1, 10080),
    "cap_gb": (0.0, 100000.0),
    "cap_cooldown_min": (1, 1440),
    "sample_interval_sec": (10, 3600),
    "nethogs_delay_sec": (1, 60),
    "panel_port": (1, 65535),
    "retention_days": (1, 365),
    "resolve_names": (0, 1),
    "projection_window_min": (1, 60),
    "graph_window_min": (5, 1440),
    "stop_top_n": (1, 20),
    "stop_grace_sec": (1, 60),
    "router_poll_sec": (10, 3600),
    "router_auth_fail_limit": (1, 5),
    "router_lockout_backoff_min": (5, 1440),
    "router_net_backoff_max_sec": (30, 3600),
    "router_reauth_cooldown_sec": (0, 3600),
    "router_max_delta_mb": (0, 1000000),
}

_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        print(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}", flush=True)


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:  # noqa: BLE001
        log(f"run {cmd!r} failed: {e}")
        return ""


def slack_escape(s):
    """Neutralise Slack mrkdwn control chars in attacker-influenceable labels."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        save_config(cfg)
    except Exception as e:  # noqa: BLE001
        log(f"config read error ({e}); using defaults")
    for k, (lo, hi) in CLAMP.items():
        try:
            v = type(DEFAULTS[k])(cfg.get(k, DEFAULTS[k]))
        except (TypeError, ValueError):
            v = DEFAULTS[k]
        cfg[k] = min(max(v, lo), hi)
    if not isinstance(cfg.get("uplink_iface"), str) or not IFACE_RE.fullmatch(cfg["uplink_iface"]):
        cfg["uplink_iface"] = "auto"
    if not isinstance(cfg.get("panel_host"), str) or not HOST_RE.fullmatch(cfg["panel_host"]):
        cfg["panel_host"] = DEFAULTS["panel_host"]
    sc = cfg.get("slack_channel", "")
    cfg["slack_channel"] = sc if isinstance(sc, str) and (sc == "" or re.fullmatch(r"[A-Za-z0-9]{6,24}", sc)) else ""
    if cfg.get("mode") not in ("host", "router", "network"):
        cfg["mode"] = "host"
    pp = cfg.get("protected_procs", [])
    if isinstance(pp, str):
        pp = [pp]
    if not isinstance(pp, list):
        pp = []
    cfg["protected_procs"] = [str(p)[:64] for p in pp
                              if isinstance(p, (str, int)) and str(p).strip()][:128]
    rh = cfg.get("router_host", "")
    cfg["router_host"] = rh if isinstance(rh, str) and (rh == "" or HOST_RE.fullmatch(rh)) else ""
    rl = cfg.get("router_iface_label", "WAN")
    cfg["router_iface_label"] = rl if isinstance(rl, str) and IFACE_RE.fullmatch(rl) else "WAN"
    ae = cfg.get("agent_endpoints", [])
    if not isinstance(ae, list):
        ae = []
    cfg["agent_endpoints"] = [u for u in (str(x).strip() for x in ae)
                              if re.fullmatch(r"https?://[A-Za-z0-9.:_-]{1,80}", u)][:32]
    dn = cfg.get("device_names", {})
    if not isinstance(dn, dict):
        dn = {}
    cfg["device_names"] = {str(k).upper()[:17]: str(v)[:48]
                           for k, v in list(dn.items())[:256]
                           if re.fullmatch(r"[0-9A-Fa-f:.\-]{12,17}", str(k))}
    return cfg


def save_config(cfg):
    clean = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS}
    os.makedirs(STATE_DIR, exist_ok=True) if not os.path.isdir(STATE_DIR) else None
    tmp = CONFIG_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(clean, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def env_value(key):
    """Look up an env var, falling back to parsing ENV_FILE (KEY=VALUE)."""
    v = os.environ.get(key)
    if v:
        return v
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:]
                if "=" not in line or line.startswith("#"):
                    continue
                k, _, val = line.partition("=")
                if k.strip() == key:
                    return val.strip().strip('"').strip("'")
    except Exception:  # noqa: BLE001
        pass
    return None


# --------------------------------------------------------------------------- #
# Network helpers
# --------------------------------------------------------------------------- #
def detect_uplink():
    """Interface holding the default route, or None if not yet resolvable."""
    out = run(["ip", "route", "get", "1.1.1.1"])
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if m else None


def tailscale_ip():
    out = run(["ip", "-4", "-o", "addr", "show", "tailscale0"])
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def read_proc_net_dev():
    """Return {iface: (rx_bytes, tx_bytes)} cumulative since boot."""
    res = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f.read().splitlines()[2:]:
                name, _, rest = line.partition(":")
                name = name.strip()
                cols = rest.split()
                if len(cols) >= 16:
                    res[name] = (int(cols[0]), int(cols[8]))
    except Exception as e:  # noqa: BLE001
        log(f"/proc/net/dev read error: {e}")
    return res


def is_intrahost(iface):
    return any(iface.startswith(p) for p in INTRAHOST_PREFIXES)


# --------------------------------------------------------------------------- #
# Per-process attribution via nethogs
# --------------------------------------------------------------------------- #
class NethogsReader(threading.Thread):
    """Runs `nethogs -t` on the uplink and accumulates per-key byte deltas.

    Trace lines:  /usr/bin/python3/1234/0\t<sent_kb>\t<recv_kb>
    Some nethogs builds report these as CUMULATIVE KB per connection (monotonic),
    so we track the last cumulative value per key and accumulate only the positive
    delta, converted to bytes. Keys are per-connection; labelling/aggregation later.
    """

    _MAX_KEYS = 20000

    def __init__(self, iface, delay):
        super().__init__(daemon=True)
        self.iface = iface
        self.delay = delay
        self._acc = {}
        self._cum = {}
        self._lock = threading.Lock()
        self._proc = None
        self.available = None
        self._stop = threading.Event()

    def drain(self):
        with self._lock:
            acc, self._acc = self._acc, {}
        return acc

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                pass

    _LINE = re.compile(r"^(.+)/(\d+)/(\d+)\t([\d.]+)\t([\d.]+)\s*$")

    def run(self):
        while not self._stop.is_set():
            try:
                self._proc = subprocess.Popen(
                    ["nethogs", "-t", "-d", str(self.delay), "--", self.iface],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                )
                with self._lock:
                    self._cum.clear()
                self.available = True
                log(f"nethogs started on {self.iface} (delay {self.delay}s)")
            except FileNotFoundError:
                self.available = False
                log("nethogs not installed — per-process breakdown disabled "
                    "(interface totals still recorded)")
                return
            except Exception as e:  # noqa: BLE001
                log(f"nethogs spawn error: {e}; retrying in 30s")
                self._stop.wait(30)
                continue

            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                m = self._LINE.match(line.rstrip("\n"))
                if not m:
                    continue
                path, pid, _uid, sent, recv = m.groups()
                cur_s, cur_r = float(sent), float(recv)
                key = (path, pid)
                with self._lock:
                    last = self._cum.get(key, (0.0, 0.0))
                    d_s = cur_s - last[0] if cur_s >= last[0] else cur_s
                    d_r = cur_r - last[1] if cur_r >= last[1] else cur_r
                    self._cum[key] = (cur_s, cur_r)
                    if len(self._cum) > self._MAX_KEYS:
                        self._cum.clear()
                    if d_s or d_r:
                        a = self._acc.setdefault(key, [0.0, 0.0])
                        a[0] += d_s * 1024
                        a[1] += d_r * 1024

            if not self._stop.is_set():
                log("nethogs exited; restarting in 5s")
                self._stop.wait(5)


# --------------------------------------------------------------------------- #
# Container / process label resolution
# --------------------------------------------------------------------------- #
class Labeler:
    def __init__(self):
        self._docker = {}
        self._docker_ts = 0

    def _refresh_docker(self):
        if time.time() - self._docker_ts < 60:
            return
        self._docker_ts = time.time()
        out = run(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"])
        m = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                m[parts[0][:64]] = parts[1]
        if m:
            self._docker = m

    _CID = re.compile(r"([0-9a-f]{64})")

    def label(self, path, pid):
        if not path.startswith("/"):
            if "-" in path and ":" in path:
                return f"→ {path.rsplit('-', 1)[-1]}"
            if path.startswith("unknown"):
                return "unattributed"
            return path
        self._refresh_docker()
        try:
            with open(f"/proc/{pid}/cgroup") as f:
                cg = f.read()
            cm = self._CID.search(cg)
            if cm:
                cid = cm.group(1)
                for full, name in self._docker.items():
                    if full.startswith(cid) or cid.startswith(full):
                        return f"📦 {name}"
                return f"📦 {cid[:12]}"
        except Exception:  # noqa: BLE001
            pass
        return os.path.basename(path) or path


# --------------------------------------------------------------------------- #
# Reverse-DNS for endpoint labels (non-blocking, cached)
# --------------------------------------------------------------------------- #
_RESOLVE_CACHE = {}
_RESOLVE_LOCK = threading.Lock()
_RESOLVE_MISS = object()
_PENDING = object()


def _do_resolve(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        name = False
    with _RESOLVE_LOCK:
        _RESOLVE_CACHE[ip] = name


def resolve_host(ip):
    with _RESOLVE_LOCK:
        v = _RESOLVE_CACHE.get(ip, _RESOLVE_MISS)
        if v is _RESOLVE_MISS:
            if len(_RESOLVE_CACHE) > 5000:
                _RESOLVE_CACHE.clear()
            _RESOLVE_CACHE[ip] = _PENDING
            spawn = True
        else:
            spawn = False
    if spawn:
        threading.Thread(target=_do_resolve, args=(ip,), daemon=True).start()
        return None
    return v if isinstance(v, str) else None


def pretty_label(label, resolve=True):
    if not resolve or not label.startswith("→ "):
        return label
    host, sep, port = label[2:].rpartition(":")
    if not sep:
        return label
    name = resolve_host(host)
    if name and name != host:
        return f"→ {name}:{port}"
    return label


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        # fetchall() consumes each PRAGMA's result row so the statement is finalized;
        # an unconsumed PRAGMA cursor leaves a read lock that makes the first write
        # fail with SQLITE_LOCKED ("database table is locked") on some platforms.
        self.db.execute("PRAGMA journal_mode=WAL").fetchall()
        self.db.execute("PRAGMA busy_timeout=5000").fetchall()  # wait on lock contention
        self.db.execute("PRAGMA wal_autocheckpoint=200").fetchall()
        self.db.execute("CREATE TABLE IF NOT EXISTS iface (ts INTEGER, iface TEXT, rx INTEGER, tx INTEGER)")
        self.db.execute("CREATE TABLE IF NOT EXISTS proc (ts INTEGER, label TEXT, w_sent REAL, w_recv REAL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v REAL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS i_iface_ts ON iface(ts)")
        self.db.execute("CREATE INDEX IF NOT EXISTS i_proc_ts ON proc(ts)")
        self.db.commit()

    def add_sample(self, ts, iface_deltas, proc_weights):
        with self.lock:
            self.db.executemany("INSERT INTO iface VALUES (?,?,?,?)",
                                [(ts, i, rx, tx) for i, (rx, tx) in iface_deltas.items()])
            self.db.executemany("INSERT INTO proc VALUES (?,?,?,?)",
                                [(ts, lbl, ws, wr) for lbl, (ws, wr) in proc_weights.items()])
            self.db.commit()

    def get_meta(self, k, default=0.0):
        with self.lock:
            r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def set_meta(self, k, v):
        with self.lock:
            self.db.execute("INSERT INTO meta VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                            (k, float(v)))
            self.db.commit()

    def iface_totals(self, since):
        with self.lock:
            rows = self.db.execute(
                "SELECT iface, SUM(rx), SUM(tx) FROM iface WHERE ts>=? GROUP BY iface", (since,)
            ).fetchall()
        return {r[0]: (r[1] or 0, r[2] or 0) for r in rows}

    def last_iface(self, iface):
        with self.lock:
            r = self.db.execute("SELECT rx, tx FROM iface WHERE iface=? ORDER BY ts DESC LIMIT 1",
                                (iface,)).fetchone()
        return (r[0], r[1]) if r else (0, 0)

    def top_talkers(self, since, limit=10):
        with self.lock:
            rows = self.db.execute(
                "SELECT label, SUM(w_sent), SUM(w_recv) FROM proc WHERE ts>=? "
                "GROUP BY label ORDER BY SUM(w_sent)+SUM(w_recv) DESC LIMIT ?", (since, limit)
            ).fetchall()
        return [(r[0], r[1] or 0.0, r[2] or 0.0) for r in rows]

    def attribution(self, since):
        with self.lock:
            r = self.db.execute(
                "SELECT SUM(CASE WHEN label LIKE '→%' OR label='unattributed' "
                "THEN 0 ELSE w_sent+w_recv END), SUM(w_sent+w_recv) FROM proc WHERE ts>=?", (since,)
            ).fetchone()
        return (r[0] or 0.0, r[1] or 0.0)

    def prune(self, before):
        with self.lock:
            self.db.execute("DELETE FROM iface WHERE ts<?", (before,))
            self.db.execute("DELETE FROM proc WHERE ts<?", (before,))
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.commit()

    def series(self, iface, since, buckets=80):
        """Bucket an iface's deltas into `buckets` equal time bins between `since`
        and now. Returns (bins=[[rx,tx], ...], bin_width_sec) for the SVG graph."""
        now = int(time.time())
        width = max(1.0, (now - since) / buckets)
        with self.lock:
            rows = self.db.execute(
                "SELECT ts, rx, tx FROM iface WHERE iface=? AND ts>=? ORDER BY ts",
                (iface, since)).fetchall()
        bins = [[0, 0] for _ in range(buckets)]
        for ts, rx, tx in rows:
            i = int((ts - since) / width)
            i = 0 if i < 0 else (buckets - 1 if i >= buckets else i)
            bins[i][0] += rx or 0
            bins[i][1] += tx or 0
        return bins, width


# --------------------------------------------------------------------------- #
# Formatting + Slack
# --------------------------------------------------------------------------- #
def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def projection_1h(store, iface, window_min):
    """Projected next-hour consumption = average rate over the last `window_min`
    × 3600. Returns {"rx","tx","total"} in bytes (0 if no traffic/target)."""
    if not iface:
        return {"rx": 0.0, "tx": 0.0, "total": 0.0}
    since = int(time.time()) - window_min * 60
    rx, tx = store.iface_totals(since).get(iface, (0, 0))
    secs = max(1, window_min * 60)
    return {"rx": rx / secs * 3600, "tx": tx / secs * 3600, "total": (rx + tx) / secs * 3600}


def render_svg(bins, width_sec, w=620, h=120, pad=4):
    """Render a stdlib-only inline SVG sparkline of download/upload *rates* from
    Store.series() bins. No JS libraries. All text is XML-escaped."""
    n = len(bins) or 1
    rx_rate = [(b[0] / width_sec) for b in bins]
    tx_rate = [(b[1] / width_sec) for b in bins]
    peak = max([1.0] + rx_rate + tx_rate)
    plot_h = h - 2 * pad
    step = (w - 2 * pad) / max(1, n - 1)

    def pts(series):
        out = []
        for i, v in enumerate(series):
            x = pad + i * step
            y = pad + plot_h - (v / peak) * plot_h
            out.append(f"{x:.1f},{y:.1f}")
        return " ".join(out)

    label = slack_escape(human(peak) + "/s peak")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" role="img" aria-label="traffic rate graph">'
        f'<rect x="0" y="0" width="{w}" height="{h}" fill="#fafafa" stroke="#e5e5e5"/>'
        f'<polyline fill="none" stroke="#2563eb" stroke-width="1.5" points="{pts(rx_rate)}"/>'
        f'<polyline fill="none" stroke="#dc2626" stroke-width="1.5" points="{pts(tx_rate)}"/>'
        f'<text x="{pad+2}" y="{pad+11}" font="11px sans-serif" font-size="11" '
        f'fill="#888">{label}  ·  ⬇ blue  ⬆ red</text>'
        f"</svg>"
    )


def post_slack(text, channel=None):
    """Send a Slack message. Returns True only on confirmed delivery.
    Token from MARSAD_SLACK_TOKEN; channel from arg or MARSAD_SLACK_CHANNEL."""
    token = env_value("MARSAD_SLACK_TOKEN")
    channel = channel or env_value("MARSAD_SLACK_CHANNEL")
    if not token or not channel:
        log("ERROR slack token/channel not configured; message NOT sent")
        return False
    body = json.dumps({"channel": channel, "text": text}).encode()
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage", data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            j = json.loads(resp.read())
            if not j.get("ok"):
                log(f"ERROR slack postMessage failed: {j.get('error')}")
                return False
            return True
    except Exception as e:  # noqa: BLE001
        log(f"ERROR slack post failed: {e}")
        return False


def midnight_epoch():
    now = datetime.now()
    return int(datetime(now.year, now.month, now.day).timestamp())


def _host_digest_block(lines, store, cfg, uplink, iface, since, up_rx, up_tx):
    others = [(i, v) for i, v in iface.items()
              if i != uplink and not is_intrahost(i) and (v[0] + v[1]) > 1024 * 1024]
    if others:
        others.sort(key=lambda x: -(x[1][0] + x[1][1]))
        seg = "  ·  ".join(f"{slack_escape(i)}: {human(v[0] + v[1])}" for i, v in others[:5])
        lines.append(f"other ifaces:  {seg}")

    talkers = store.top_talkers(since, limit=8)
    attr_w, tot_w = store.attribution(since)
    up_total = up_rx + up_tx
    if talkers and tot_w > 0 and up_total > 0:
        pct = attr_w / tot_w * 100
        lines.append(f"top talkers (est. share of WAN · {pct:.0f}% attributed to a process):")
        for label, ws, wr in talkers:
            frac = (ws + wr) / tot_w
            if frac < 0.01:
                continue
            name = slack_escape(pretty_label(label, cfg["resolve_names"]))
            lines.append(f"  • {name}: {human(frac * up_total)}  ({frac*100:.0f}%)")
    elif not talkers:
        lines.append("_(per-process breakdown unavailable — nethogs not running)_")


def _router_digest_block(lines, cfg, extras):
    if extras.get("available") is False:
        st = extras.get("state", "")
        extra = " (login disabled for safety)" if st == "LOCKED_OUT" else ""
        lines.append(f"_(router unreachable — WAN stats stale/unavailable{extra})_")
    op, status = extras.get("operator", ""), extras.get("status", "")
    if op or status:
        lines.append(f"carrier: {slack_escape(op) or '?'}   ·   link: {slack_escape(status) or '?'}")
    if extras.get("split_mode") == "estimated":
        lines.append("_(down/up split estimated from live speeds — total is exact)_")
    elif extras.get("split_mode") == "total_only":
        lines.append("_(router reports a single WAN total — no down/up split)_")

    devices = extras.get("devices", [])
    if devices:
        shown = [slack_escape(d.get("name") or d.get("mac") or d.get("ip") or "?")
                 for d in devices[:8]]
        more = f" · +{len(devices) - 8} more" if len(devices) > 8 else ""
        lines.append(f"{len(devices)} devices online: " + " · ".join(shown) + more)

    per_host = extras.get("per_host", [])
    if per_host:
        lines.append("per-host (instrumented agents, this window):")
        for h in per_host:
            lines.append(f"  • {slack_escape(h['host'])}: {h['total']}")
        if extras.get("residual"):
            lines.append(f"  • other / uninstrumented devices (combined): {extras['residual']}")
    lines.append("_(the M7200 reports no per-device byte counters — usage can't be split by "
                 "device; only presence + per-agent-host totals are shown)_")


def build_digest(store, cfg, uplink, window_min, extras=None):
    since = int(time.time()) - window_min * 60
    iface = store.iface_totals(since)
    up_rx, up_tx = iface.get(uplink, (0, 0))
    router = cfg["mode"] in ("router", "network")
    scope = "M7200, whole network" if router else uplink

    lines = [f"*{HOST} bandwidth* — last {window_min} min"]
    lines.append(f"WAN ({scope}):  ⬇ {human(up_rx)} down   ⬆ {human(up_tx)} up   "
                 f"Σ {human(up_rx + up_tx)} total")

    day = store.iface_totals(midnight_epoch()).get(uplink, (0, 0))
    lines.append(f"today so far:  ⬇ {human(day[0])} down   ⬆ {human(day[1])} up   "
                 f"Σ {human(day[0] + day[1])} total")

    pj = projection_1h(store, uplink, cfg["projection_window_min"])
    lines.append(f"projected next 1h (at last {cfg['projection_window_min']}m rate):  "
                 f"Σ {human(pj['total'])}")

    if router:
        _router_digest_block(lines, cfg, extras or {})
    else:
        _host_digest_block(lines, store, cfg, uplink, iface, since, up_rx, up_tx)

    if cfg["report_interval_min"] != window_min:
        rel = "overlap between reports" if cfg["report_interval_min"] < window_min \
            else "gaps between report windows not shown"
        lines.append(f"_(report every {cfg['report_interval_min']}m, window {window_min}m — {rel})_")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Collectors — each produces (iface_deltas, attribution_weights) per cycle, so the
# Store / cap / digest / panel machinery is identical regardless of data source.
# --------------------------------------------------------------------------- #
class Collector:
    """A source of per-cycle traffic samples.

    sample() returns (iface_deltas, attribution) — exactly the two dicts
    Store.add_sample takes: {iface: (rx_delta, tx_delta)} and
    {label: (w_sent, w_recv)}. target_label() is the interface the cap/digest/panel
    focus on. presence()/extras() carry mode-specific context for the digest + panel.
    """
    available = None

    def start(self):
        pass

    def stop(self):
        pass

    def target_label(self):
        return None

    def sample(self):
        return {}, {}

    def retarget(self, cfg):
        pass

    def presence(self):
        return []

    def extras(self):
        return {}


class HostCollector(Collector):
    """The original behaviour: /proc/net/dev per-interface deltas + nethogs
    per-process attribution on the default-route (or configured) uplink."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.uplink = self._resolve_uplink()
        self.labeler = Labeler()
        self.nethogs = NethogsReader(self.uplink or "lo", cfg["nethogs_delay_sec"])
        self._last_counters = read_proc_net_dev()
        self._started = False
        self._pid_acc = {}      # (path, pid:int) -> [w_sent, w_recv], decayed each cycle

    def _resolve_uplink(self):
        return detect_uplink() if self.cfg["uplink_iface"] == "auto" else self.cfg["uplink_iface"]

    @property
    def available(self):
        return self.nethogs.available

    def start(self):
        if self.uplink and not self._started:
            self.nethogs.start()
            self._started = True

    def stop(self):
        self.nethogs.stop()

    def target_label(self):
        return self.uplink

    def sample(self):
        cur = read_proc_net_dev()
        deltas = {}
        for iface, (rx, tx) in cur.items():
            prev = self._last_counters.get(iface)
            if prev is None:
                continue
            drx = rx - prev[0]
            dtx = tx - prev[1]
            if drx < 0:
                drx = rx
            if dtx < 0:
                dtx = tx
            if drx or dtx:
                deltas[iface] = (drx, dtx)
        self._last_counters = cur

        drained = self.nethogs.drain()
        proc_weights = {}
        for (path, pid), (ws, wr) in drained.items():
            label = self.labeler.label(path, pid)
            agg = proc_weights.setdefault(label, [0.0, 0.0])
            agg[0] += ws
            agg[1] += wr

        self._retain_pids(drained)
        return deltas, proc_weights

    _PID_DECAY = 0.5

    def _retain_pids(self, drained):
        """Keep a decaying per-PID byte map so stop-top can target *current* heavy
        local processes. Only real local processes (abs path + numeric pid) qualify;
        endpoint pseudo-entries (no killable local pid) are ignored."""
        for k in list(self._pid_acc):
            a = self._pid_acc[k]
            a[0] *= self._PID_DECAY
            a[1] *= self._PID_DECAY
            if a[0] + a[1] < 1.0:
                del self._pid_acc[k]
        for (path, pid), (ws, wr) in drained.items():
            if path.startswith("/") and str(pid).isdigit() and int(pid) > 1:
                a = self._pid_acc.setdefault((path, int(pid)), [0.0, 0.0])
                a[0] += ws
                a[1] += wr

    def top_pids(self, n):
        """Current heaviest local PIDs: [(pid:int, name, bytes), ...] desc."""
        items = sorted(self._pid_acc.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))
        out = []
        for (path, pid), (ws, wr) in items[:max(0, n)]:
            out.append((pid, os.path.basename(path) or path, ws + wr))
        return out

    def retarget(self, cfg):
        self.cfg = cfg
        want = self._resolve_uplink()
        if not want:
            if not self.uplink:
                log("uplink still unresolved (no default route yet)")
            return
        if want != self.uplink or cfg["nethogs_delay_sec"] != self.nethogs.delay:
            log(f"re-targeting capture: {self.uplink} -> {want} "
                f"(delay {self.nethogs.delay}->{cfg['nethogs_delay_sec']}s)")
            self.nethogs.stop()
            self.uplink = want
            self.nethogs = NethogsReader(want, cfg["nethogs_delay_sec"])
            self.nethogs.start()
            self._started = True


def make_collector(cfg):
    """Pick the collector for the configured mode. Router mode falls back to host
    if RouterCollector isn't present (it's defined further down for router builds)."""
    mode = cfg.get("mode", "host")
    if mode in ("router", "network"):
        rc = globals().get("RouterCollector")
        if rc is not None:
            return rc(cfg)
        log("WARNING mode=router set but RouterCollector unavailable — using host mode")
    return HostCollector(cfg)


# --------------------------------------------------------------------------- #
# Stop-top — kill the heaviest local consumers (host mode only). Hard-gated: it only
# ever targets the daemon-computed top PIDs, never a caller-supplied pid, and an
# allowlist protects critical processes (checked again at kill time).
# --------------------------------------------------------------------------- #
PROTECT_COMM = {"systemd", "init", "sshd", "dockerd", "containerd"}  # exact comm
PROTECT_TOKENS = ("marsad",)  # substring — never kill a sibling marsad instance


def proc_comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except Exception:  # noqa: BLE001
        return ""


def proc_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:  # noqa: BLE001
        return False


def is_protected(pid, extra=()):
    """True if `pid` must never be killed. Evaluated fresh (reads /proc) at call
    time so a PID recycled into a protected process is still safe."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return True
    if pid <= 1 or pid == os.getpid():
        return True
    try:
        if os.getpgid(pid) == os.getpgrp():  # our own process group
            return True
    except Exception:  # noqa: BLE001
        return True  # can't determine -> refuse to kill
    comm = proc_comm(pid)
    if not comm or comm in PROTECT_COMM:
        return True
    # token match is against comm + the FULL cmdline (lowercased), so allowlist
    # entries catch processes whose comm is generic (python3/node) but whose
    # cmdline identifies critical infra (CI runners, ci-* containers, the LLM stack).
    hay = (comm + " " + proc_cmdline(pid)).lower()
    for tok in PROTECT_TOKENS:
        if tok in hay:
            return True
    for tok in extra:
        t = str(tok).strip().lower()
        if t and t in hay:
            return True
    return False


def stop_top_consumers(collector, n, grace, extra=()):
    """SIGTERM (then SIGKILL after `grace`) the daemon-computed top-N local PIDs,
    skipping anything is_protected(). Returns a JSON-able report. Host mode only."""
    if not isinstance(collector, HostCollector):
        return {"ok": False, "error": "stop-top is only available in host mode"}

    def safe_to_kill(t):
        # Re-evaluated before EVERY signal: never kill a protected process, and
        # bail if the PID was recycled into a different process (comm changed)
        # between selection and now — closes the PID-reuse TOCTOU window.
        return (not is_protected(t["pid"], extra)) and proc_comm(t["pid"]) == t["comm"]

    targets = collector.top_pids(n)
    to_kill, skipped = [], []
    for pid, name, by in targets:
        comm = proc_comm(pid)
        if is_protected(pid, extra) or not comm:
            skipped.append({"pid": pid, "name": name, "reason": "protected"})
        else:
            to_kill.append({"pid": pid, "name": name, "comm": comm, "bytes": int(by)})
    for t in to_kill:
        try:
            if safe_to_kill(t):
                os.kill(t["pid"], signal.SIGTERM)
                t["signal"] = "TERM"
            else:
                t["signal"] = "skipped-protected"
        except ProcessLookupError:
            t["signal"] = "already-gone"
        except Exception as e:  # noqa: BLE001
            t["signal"] = f"error:{e}"
    if any(t.get("signal") == "TERM" for t in to_kill):
        time.sleep(max(0, min(60, grace)))
    for t in to_kill:
        if t.get("signal") == "TERM" and pid_alive(t["pid"]):
            try:
                if safe_to_kill(t):  # identity + allowlist re-checked at SIGKILL time
                    os.kill(t["pid"], signal.SIGKILL)
                    t["signal"] = "KILL"
                else:
                    t["signal"] = "TERM-then-recycled"
            except ProcessLookupError:
                t["signal"] = "TERM-then-gone"
            except Exception as e:  # noqa: BLE001
                t["signal"] = f"error:{e}"
    log(f"stop-top: killed={[t['pid'] for t in to_kill]} skipped={[s['pid'] for s in skipped]}")
    return {"ok": True, "killed": to_kill, "skipped": skipped}


# --------------------------------------------------------------------------- #
# Crypto (stdlib only) — for the TP-Link M7200 encrypted admin API.
# AES-128-CBC + RSA PKCS#1 v1.5. The primitives are verified against FIPS-197 and
# OpenSSL; the exact M7200 *wire framing* (field names, hex/base64) is confirmed on
# real hardware at install time — see M7200Client and the README "router mode" notes.
# --------------------------------------------------------------------------- #
def _rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _gen_sbox():
    """Generate the AES S-box (FIPS-197) programmatically to avoid transcription
    errors (the affine step uses byte rotation, ROTL8). Verified at import against
    the known fixed point S-box[0]=0x63 and at test time against FIPS-197 vectors."""
    p = q = 1
    sbox = bytearray(256)
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


_SBOX = _gen_sbox()
_INV_SBOX = bytes(_SBOX.index(i) for i in range(256))
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _key_expansion(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[r * 4:r * 4 + 4] for b in word) for r in range(11)]


def _shift_rows(s, inv=False):
    o = bytearray(16)
    for r in range(4):
        for c in range(4):
            src = (c - r) % 4 if inv else (c + r) % 4
            o[r + 4 * c] = s[r + 4 * src]
    return bytes(o)


def _mix_columns(s, inv=False):
    o = bytearray(16)
    m = (14, 11, 13, 9) if inv else (2, 3, 1, 1)
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            o[4 * c + r] = (_gmul(col[0], m[(0 - r) % 4]) ^ _gmul(col[1], m[(1 - r) % 4])
                            ^ _gmul(col[2], m[(2 - r) % 4]) ^ _gmul(col[3], m[(3 - r) % 4]))
    return bytes(o)


def _add_round_key(s, rk):
    return bytes(s[i] ^ rk[i] for i in range(16))


def _encrypt_block(b, rks):
    s = _add_round_key(b, rks[0])
    for rnd in range(1, 10):
        s = bytes(_SBOX[x] for x in s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, rks[rnd])
    s = bytes(_SBOX[x] for x in s)
    s = _shift_rows(s)
    return _add_round_key(s, rks[10])


def _decrypt_block(b, rks):
    s = _add_round_key(b, rks[10])
    for rnd in range(9, 0, -1):
        s = _shift_rows(s, inv=True)
        s = bytes(_INV_SBOX[x] for x in s)
        s = _add_round_key(s, rks[rnd])
        s = _mix_columns(s, inv=True)
    s = _shift_rows(s, inv=True)
    s = bytes(_INV_SBOX[x] for x in s)
    return _add_round_key(s, rks[0])


def aes_cbc_encrypt(data, key, iv):
    rks = _key_expansion(key)
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _encrypt_block(blk, rks)
        out += prev
    return bytes(out)


def aes_cbc_decrypt(data, key, iv):
    if not data or len(data) % 16 != 0:
        raise ValueError("ciphertext not a multiple of the AES block size")
    rks = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(blk, rks), prev))
        prev = blk
    pad = out[-1]
    # full PKCS#7 validation: every padding byte must equal the count.
    if pad < 1 or pad > 16 or any(b != pad for b in out[-pad:]):
        raise ValueError("invalid PKCS#7 padding")
    return bytes(out[:-pad])


def rsa_encrypt_pkcs1v15_hex(msg, e, n):
    """RSA PKCS#1 v1.5 type-2 (encryption) of `msg`, chunked across blocks the way
    the TP-Link web UI does, concatenated and hex-encoded. Public key only."""
    k = (n.bit_length() + 7) // 8
    maxm = k - 11
    if maxm <= 0:
        raise ValueError("RSA modulus too small")
    out = bytearray()
    for i in range(0, len(msg) or 1, maxm):
        chunk = msg[i:i + maxm]
        ps = bytearray()
        while len(ps) < k - 3 - len(chunk):
            b = secrets.token_bytes(1)
            if b != b"\x00":
                ps += b
        em = b"\x00\x02" + bytes(ps) + b"\x00" + chunk
        c = pow(int.from_bytes(em, "big"), e, n)
        out += c.to_bytes(k, "big")
    return out.hex()


def _md5hex(s):
    return hashlib.md5(s.encode()).hexdigest()


def _rand_ascii(n):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


# --------------------------------------------------------------------------- #
# TP-Link M7200 admin-API client
# --------------------------------------------------------------------------- #
class AuthRejected(Exception):
    """The router rejected our credentials (do NOT retry-loop — lockout risk)."""


class RouterUnreachable(Exception):
    """Transient failure: timeout / refused / garbage / token expired."""


def _num(v):
    """Coerce a router field (often a numeric string) to int bytes; None if absent."""
    if v is None:
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _first(d, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return None


class M7200Client:
    """Talks to a TP-Link M7200 (and firmware siblings). Holds ONE admin session
    (token + AES key/iv) and reuses it — re-login evicts the family's app/browser,
    so callers must avoid re-login storms. Encrypted (current firmware) with a
    plaintext-legacy fallback. Wire framing is validated on hardware at install."""

    AUTH = "/cgi-bin/auth_cgi"
    WEB = "/cgi-bin/web_cgi"
    LEGACY = "/cgi-bin/qcmap_web_cgi"

    def __init__(self, host, password, user="admin", timeout=12):
        self.base = f"http://{host}" if host and "://" not in host else (host or "")
        self.password = password or ""
        self.user = user or "admin"
        self.timeout = timeout
        self._token = None
        self._key = None
        self._iv = None
        self._legacy = False

    # -- low-level HTTP ----------------------------------------------------- #
    def _post(self, path, body, headers=None):
        if not self.base:
            raise RouterUnreachable("no router_host configured")
        data = body if isinstance(body, (bytes, bytearray)) else body.encode()
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers or {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise AuthRejected(f"http {e.code}")
            raise RouterUnreachable(f"http {e.code}")
        except Exception as e:  # noqa: BLE001  (timeout, refused, dns, reset, ...)
            raise RouterUnreachable(str(e))

    def _decode_envelope(self, text):
        """Parse a response that is either plain JSON or base64(AES(json))."""
        text = (text or "").strip()
        try:
            return json.loads(text)
        except Exception:  # noqa: BLE001
            pass
        if self._key and self._iv:
            try:
                ct = base64.b64decode(text)
                pt = aes_cbc_decrypt(ct, self._key.encode(), self._iv.encode())
                return json.loads(pt.decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                pass
        raise RouterUnreachable("undecodable response")

    # -- auth --------------------------------------------------------------- #
    def login(self):
        """Establish a session. Raises AuthRejected on bad creds, RouterUnreachable
        on transient failure. On success caches token + AES key/iv."""
        # Step 1: fetch nonce + RSA pubkey + seqNum (unencrypted).
        r1 = self._decode_envelope(self._post(
            self.AUTH, json.dumps({"module": "authenticator", "action": 0})))
        nonce = _first(r1, "nonce", "Nonce")
        rsa_e = _first(r1, "rsaPubKey", "ee", "e")
        rsa_n = _first(r1, "rsaMod", "nn", "n")
        seq = _num(_first(r1, "seqNum", "seq")) or 0
        if not (nonce and rsa_e and rsa_n):
            # No encrypted-handshake params -> try the legacy plaintext API.
            return self._login_legacy()
        e = int(str(rsa_e), 16)
        n = int(str(rsa_n), 16)
        self._key = _rand_ascii(16)
        self._iv = _rand_ascii(16)
        digest = _md5hex(f"{self.password}:{nonce}")
        payload = json.dumps({"module": "authenticator", "action": 1, "digest": digest})
        ct = base64.b64encode(aes_cbc_encrypt(payload.encode(), self._key.encode(),
                                              self._iv.encode())).decode()
        h = _md5hex(self.user + self.password)
        sign = rsa_encrypt_pkcs1v15_hex(
            f"key={self._key}&iv={self._iv}&h={h}&s={seq + len(ct)}".encode(), e, n)
        r2 = self._decode_envelope(self._post(
            self.AUTH, json.dumps({"data": ct, "sign": sign})))
        result = _num(_first(r2, "result", "errorcode"))
        if result == 0 and _first(r2, "token"):
            self._token = _first(r2, "token")
            self._legacy = False
            return True
        # result codes: 0 ok; nonzero is typically a credential/lockout signal.
        raise AuthRejected(f"login result={result}")

    def _login_legacy(self):
        """Best-effort plaintext (older qcmap firmware). Validated on hardware."""
        self._legacy = True
        try:
            r = self._decode_envelope(self._post(
                self.LEGACY, json.dumps({"module": "authenticator", "action": 1,
                                         "username": self.user, "password": self.password})))
        except RouterUnreachable:
            raise
        result = _num(_first(r, "result", "errorcode"))
        tok = _first(r, "token")
        if result == 0 or tok:
            self._token = tok or "legacy"
            return True
        raise AuthRejected(f"legacy login result={result}")

    def call(self, module, action, extra=None):
        if not self._token:
            raise AuthRejected("not logged in")
        inner = {"token": self._token, "module": module, "action": action}
        if extra:
            inner.update(extra)
        path = self.LEGACY if self._legacy else self.WEB
        if self._legacy or not (self._key and self._iv):
            body = json.dumps(inner)
        else:
            body = json.dumps({"token": self._token, "data": base64.b64encode(
                aes_cbc_encrypt(json.dumps(inner).encode(), self._key.encode(),
                                self._iv.encode())).decode()})
        resp = self._decode_envelope(self._post(path, body))
        # An expired/evicted token usually surfaces as a nonzero result here.
        if isinstance(resp, dict):
            res = _num(_first(resp, "result", "errorcode"))
            if res not in (None, 0) and ("token" in resp or "expire" in str(resp).lower()):
                self._token = None
                raise AuthRejected(f"token rejected result={res}")
        return resp

    def get_status(self):
        """Return a normalized WAN dict: rx/tx (bytes, if split), total (bytes),
        rx_speed/tx_speed (B/s), today (bytes), operator, status."""
        resp = self.call("status", 0)
        wan = resp.get("wan", resp) if isinstance(resp, dict) else {}
        return {
            "rx": _num(_first(wan, "rxBytes", "totalRx", "rx")),
            "tx": _num(_first(wan, "txBytes", "totalTx", "tx")),
            "total": _num(_first(wan, "totalStatistics", "totalBytes", "total")),
            "today": _num(_first(wan, "dailyStatistics", "todayBytes", "daily")),
            "rx_speed": _num(_first(wan, "rxSpeed", "downSpeed")) or 0,
            "tx_speed": _num(_first(wan, "txSpeed", "upSpeed")) or 0,
            "operator": _first(wan, "operatorName", "operator") or "",
            "status": _first(wan, "connectStatus", "status") or "",
        }

    def get_devices(self):
        resp = self.call("connectedDevices", 0)
        if isinstance(resp, dict):
            for k in ("connectedDevices", "clientList", "deviceList", "hosts", "list"):
                if isinstance(resp.get(k), list):
                    return resp[k]
            for v in resp.values():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    return v
        return resp if isinstance(resp, list) else []

    def logout(self):
        if self._token:
            try:
                self._post(self.AUTH, json.dumps(
                    {"token": self._token, "module": "authenticator", "action": 3}))
            except Exception:  # noqa: BLE001
                pass
            self._token = None


# --------------------------------------------------------------------------- #
# RouterCollector — polls a gateway router on its own thread; the daemon drains it.
# Whole-network WAN total + connected-device presence. NO per-device bytes exist on
# the M7200, so per-machine numbers come only from instrumented host agents, with an
# honest "other/uninstrumented (combined)" residual.
# --------------------------------------------------------------------------- #
class RouterCollector(Collector):
    def __init__(self, cfg, client=None):
        self.cfg = cfg
        self.label = cfg.get("router_iface_label", "WAN")
        self.password = env_value("MARSAD_ROUTER_PASSWORD") or ""
        self.client = client or M7200Client(cfg.get("router_host", ""), self.password,
                                             user="admin")
        self._lock = threading.Lock()
        self._acc = [0.0, 0.0]
        self._last = {}
        self._presence = []
        self._wan = {}
        self._split_mode = "unknown"
        self._state = "INIT"
        self._auth_fails = 0
        self._backoff_until = 0.0
        self._net_backoff = 0.0
        self._last_evicted = 0.0
        self._alerted_lockout = False
        self.available = None
        self._stop = threading.Event()
        self._thread = None
        self._per_host = {}
        self._per_host_ts = 0.0

    # -- Collector interface ----------------------------------------------- #
    def start(self):
        if not self.cfg.get("router_host"):
            log("router mode: no router_host configured — set it in config.json and "
                "restart; not starting the poll loop")
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            self.client.logout()
        except Exception:  # noqa: BLE001
            pass

    def target_label(self):
        return self.label

    def sample(self):
        with self._lock:
            acc, self._acc = self._acc, [0.0, 0.0]
        deltas = {self.label: (int(acc[0]), int(acc[1]))} if (acc[0] or acc[1]) else {}
        return deltas, {}

    def presence(self):
        with self._lock:
            return list(self._presence)

    def retarget(self, cfg):
        self.cfg = cfg  # poll cadence / agents read live in the worker

    def extras(self):
        # read-only: the worker thread refreshes _per_host (no blocking HTTP here,
        # so the panel handler and daemon loop never stall on a slow agent)
        with self._lock:
            devices = list(self._presence)
            wan = dict(self._wan)
            per_host = dict(self._per_host)
            state = self._state
            avail = self.available
            split = self._split_mode
        names = self.cfg.get("device_names", {})
        for d in devices:
            mac = (d.get("mac") or "").upper()
            if mac in names:
                d["name"] = names[mac]
        per_host_list = [{"host": h, "total": human(b)} for h, b in per_host.items()]
        win_secs = self.cfg["summary_window_min"] * 60
        wan_window = self._window_total(win_secs)
        residual = wan_window - sum(per_host.values())
        return {
            "available": avail,
            "state": state,
            "split_mode": split,
            "operator": wan.get("operator", ""),
            "status": wan.get("status", ""),
            "devices": [{"name": d.get("name", ""), "mac": d.get("mac", ""),
                         "ip": d.get("ip", "")} for d in devices],
            "per_host": per_host_list,
            "residual": human(residual) if per_host and residual > 0 else None,
        }

    def _window_total(self, secs):  # filled by the daemon via a back-reference
        return getattr(self, "_window_total_fn", lambda s: 0)(secs)

    # -- worker ------------------------------------------------------------- #
    def _poll_sec(self):
        return max(10, int(self.cfg.get("router_poll_sec", 30)))

    def _run(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:  # noqa: BLE001
                log(f"router collector error: {e}")
            self._stop.wait(self._poll_sec())

    def _tick(self):
        now = time.time()
        if now < self._backoff_until:
            return
        if self._state != "ACTIVE":
            if not self._try_login(now):
                return
        try:
            self._ingest_wan(self.client.get_status())
            try:
                devs = self.client.get_devices()
                with self._lock:
                    self._presence = self._normalize_devices(devs)
            except RouterUnreachable:
                pass  # presence is best-effort; keep last good
            self._refresh_agents()  # aggregate host agents on the worker thread
            self.available = True
            self._net_backoff = 0.0
        except AuthRejected:
            self.available = False
            self._state = "NEED_AUTH"
            self._last_evicted = now
            log("router token rejected/evicted — will re-auth after cooldown")
        except RouterUnreachable as e:
            self.available = False
            self._backoff_net(now, str(e))

    def _try_login(self, now):
        if self._state == "NEED_AUTH" and (now - self._last_evicted) < self.cfg["router_reauth_cooldown_sec"]:
            return False  # be a polite citizen of the single admin slot
        try:
            self.client.login()
        except AuthRejected:
            self._auth_fails += 1
            self._state = "NEED_AUTH"
            # Space even the pre-lockout attempts (never hammer the login endpoint
            # with a bad credential): wait the reauth cooldown before retrying.
            self._backoff_until = now + self.cfg["router_reauth_cooldown_sec"]
            if self._auth_fails >= self.cfg["router_auth_fail_limit"]:
                self._state = "LOCKED_OUT"
                self._backoff_until = now + self.cfg["router_lockout_backoff_min"] * 60
                if not self._alerted_lockout:
                    self._alerted_lockout = True
                    post_slack(
                        f":warning: *{HOST} marsad* — router login REJECTED. Pausing re-auth "
                        f"for {self.cfg['router_lockout_backoff_min']}m to avoid locking the "
                        f"router out. Check MARSAD_ROUTER_PASSWORD / router_host.",
                        self.cfg.get("slack_channel") or None)
                log(f"router credential rejected x{self._auth_fails} -> LOCKED_OUT")
            return False
        except RouterUnreachable as e:
            self._backoff_net(now, str(e))
            return False
        self._state = "ACTIVE"
        self._auth_fails = 0
        self._alerted_lockout = False
        log("router login ok")
        return True

    def _backoff_net(self, now, why):
        self._net_backoff = min(self.cfg["router_net_backoff_max_sec"],
                                max(self._poll_sec(), self._net_backoff * 2 or self._poll_sec()))
        self._backoff_until = now + self._net_backoff
        log(f"router unreachable ({why}); backing off {int(self._net_backoff)}s")

    def _ingest_wan(self, wan):
        with self._lock:
            self._wan = wan
        rx, tx, total = wan.get("rx"), wan.get("tx"), wan.get("total")
        if rx is not None and tx is not None:
            drx, dtx = self._delta("rx", rx), self._delta("tx", tx)
            self._split_mode = "real"
        elif total is not None:
            d = self._delta("total", total)
            srx, stx = wan.get("rx_speed") or 0, wan.get("tx_speed") or 0
            if srx + stx > 0:
                drx = d * srx / (srx + stx)
                dtx = d - drx
                self._split_mode = "estimated"
            else:
                drx, dtx = d, 0
                self._split_mode = "total_only"
        else:
            return  # nothing usable this poll
        drx, dtx = max(0, drx), max(0, dtx)
        cap_mb = self.cfg.get("router_max_delta_mb", 0)
        if cap_mb:
            cap = cap_mb * 1024 * 1024
            tot = drx + dtx
            if tot > cap and tot > 0:  # scale both directions, preserving the split
                scale = cap / tot
                drx, dtx = drx * scale, dtx * scale
        with self._lock:
            self._acc[0] += drx
            self._acc[1] += dtx

    def _delta(self, key, cur):
        last = self._last.get(key)
        self._last[key] = cur
        if last is None:
            return 0
        return cur - last if cur >= last else cur  # monotonic reset clamp

    def _normalize_devices(self, devs):
        out = []
        if not isinstance(devs, list):
            return out
        for d in devs[:256]:
            if not isinstance(d, dict):
                continue
            mac = str(_first(d, "mac", "macAddr", "MACAddress", "MAC") or "").upper()
            out.append({
                "name": slack_escape(str(_first(d, "name", "hostName", "hostname",
                                                "deviceName") or "")[:48]),
                "mac": mac,
                "ip": str(_first(d, "ip", "ipAddr", "IPAddress", "IP") or "")[:45],
            })
        return out

    def _refresh_agents(self):
        now = time.time()
        if now - self._per_host_ts < 30:
            return
        self._per_host_ts = now
        out = {}
        for url in self.cfg.get("agent_endpoints", []):
            try:
                with urllib.request.urlopen(url.rstrip("/") + "/api/stats", timeout=5) as r:
                    s = json.loads(r.read())
                wb = s.get("window_bytes")
                if wb is None:
                    continue
                out[str(s.get("host", url))] = int(wb)
            except Exception:  # noqa: BLE001
                continue
        with self._lock:
            self._per_host = out


# --------------------------------------------------------------------------- #
# Daemon
# --------------------------------------------------------------------------- #
class Daemon:
    def __init__(self):
        if not os.path.isdir(STATE_DIR):
            os.makedirs(STATE_DIR, exist_ok=True)
        self.cfg = load_config()
        self.store = Store(DB_PATH)
        self.collector = make_collector(self.cfg)
        if isinstance(self.collector, RouterCollector):
            # let the collector compute the WAN window total for the residual figure
            self.collector._window_total_fn = lambda secs: sum(
                self.store.iface_totals(int(time.time()) - secs).get(self.uplink, (0, 0)))
        self.collector.start()
        log(f"host={HOST} mode={self.cfg['mode']} target={self.collector.target_label()}")
        self._last_report = self.store.get_meta("last_report", 0.0)
        self._last_cap_alert = self.store.get_meta("last_cap_alert", 0.0)
        self._last_prune = 0.0
        self._stop = threading.Event()
        dest = self.cfg.get("slack_channel") or env_value("MARSAD_SLACK_CHANNEL")
        if not env_value("MARSAD_SLACK_TOKEN") or not dest:
            log("WARNING slack token/channel not configured — digests + cap alerts will NOT send")
        else:
            log(f"slack destination: {dest}")

    @property
    def uplink(self):
        return self.collector.target_label()

    def sample(self):
        ts = int(time.time())
        deltas, attribution = self.collector.sample()
        self.store.add_sample(ts, deltas, attribution)
        return ts

    def maybe_retarget(self):
        self.collector.retarget(self.cfg)

    def check_cap(self):
        cap = self.cfg["cap_gb"]
        if cap <= 0 or not self.uplink:
            return
        win = self.cfg["summary_window_min"]
        since = int(time.time()) - win * 60
        rx, tx = self.store.iface_totals(since).get(self.uplink, (0, 0))
        total_gb = (rx + tx) / (1024 ** 3)
        if total_gb < cap:
            return
        if time.time() - self._last_cap_alert < self.cfg["cap_cooldown_min"] * 60:
            return
        if self.cfg["mode"] in ("router", "network"):
            devs = self.collector.presence()
            who = (f"{len(devs)} devices online: " + ", ".join(
                slack_escape(d.get("name") or d.get("mac") or d.get("ip") or "?")
                for d in devs[:6])) if devs else "device list unavailable"
        else:
            talkers = self.store.top_talkers(since, limit=3)
            _, wtot = self.store.attribution(since)
            wtot = wtot or 1.0
            who = ", ".join(
                f"{slack_escape(pretty_label(l, self.cfg['resolve_names']))} {(ws+wr)/wtot*100:.0f}%"
                for l, ws, wr in talkers) or "unknown"
        ok = post_slack(
            f":rotating_light: *{HOST} BANDWIDTH CAP HIT* — "
            f"{total_gb:.2f} GB on {self.uplink} in the last {win} min (cap {cap} GB).\n"
            f"⬇ {human(rx)} down  ⬆ {human(tx)} up  Σ {human(rx + tx)} total.  top: {who}",
            self.cfg.get("slack_channel") or None,
        )
        if ok:
            self._last_cap_alert = time.time()
            self.store.set_meta("last_cap_alert", self._last_cap_alert)
            log(f"CAP ALERT sent: {total_gb:.2f}GB > {cap}GB in {win}min")
        else:
            log(f"CAP HIT but Slack delivery FAILED ({total_gb:.2f}GB) — will retry next cycle")

    def maybe_report(self):
        interval = self.cfg["report_interval_min"] * 60
        if self._last_report == 0.0:
            self._last_report = time.time()
            self.store.set_meta("last_report", self._last_report)
            return
        if time.time() - self._last_report < interval:
            return
        extras = self.collector.extras() if self.cfg["mode"] in ("router", "network") else None
        msg = build_digest(self.store, self.cfg, self.uplink,
                           self.cfg["summary_window_min"], extras)
        post_slack(msg, self.cfg.get("slack_channel") or None)
        self._last_report = time.time()
        self.store.set_meta("last_report", self._last_report)
        log("digest sent")

    def maybe_prune(self):
        if time.time() - self._last_prune < 3600:
            return
        self._last_prune = time.time()
        self.store.prune(int(time.time()) - self.cfg["retention_days"] * 86400)

    def loop(self):
        while not self._stop.is_set():
            self.cfg = load_config()
            try:
                self.maybe_retarget()
                self.sample()
                self.check_cap()
                self.maybe_report()
                self.maybe_prune()
            except Exception as e:  # noqa: BLE001
                log(f"loop error: {e}")
            self._stop.wait(self.cfg["sample_interval_sec"])

    def stop(self):
        self._stop.set()
        self.collector.stop()


# --------------------------------------------------------------------------- #
# Admin panel
# --------------------------------------------------------------------------- #
PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>marsad — {HOST}</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
body{font:14px system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 14px;color:#1a1a1a}
h1{font-size:19px} .card{border:1px solid #ddd;border-radius:10px;padding:14px 16px;margin:14px 0}
.big{font-size:26px;font-weight:600} label{display:block;margin:10px 0 3px;font-weight:600}
input{width:120px;padding:6px;border:1px solid #ccc;border-radius:6px}
button{margin-top:14px;padding:8px 16px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
table{width:100%;border-collapse:collapse} td{padding:3px 0} .r{text-align:right}
.muted{color:#777;font-size:12px}
</style></head><body>
<h1>مرصد marsad — {HOST}</h1>
<div class=card>
  <div class=muted>WAN uplink <b id=up></b> · refreshed <span id=ago>…</span></div>
  <div class=big id=live>…</div>
  <div id=window class=muted></div>
  <div id=day class=muted></div>
  <div id=proj class=muted></div>
</div>
<div class=card>
  <b>Rate graph</b> <span class=muted>(⬇ download blue · ⬆ upload red · last <span id=gwin></span> min)</span>
  <div><img id=graph alt="traffic rate graph" style="width:100%;max-width:620px;height:auto"></div>
</div>
<div class=card id=talkerscard>
  <b>Top talkers</b> <span class=muted>(this window, est. share of WAN; <span id=attr></span>)</span>
  <table id=talkers></table>
</div>
<div class=card id=devicescard style=display:none>
  <b>Connected devices</b> <span class=muted>(<span id=devcount></span> online · presence only — the router reports no per-device bytes)</span>
  <table id=devices></table>
</div>
<div class=card id=hostscard style=display:none>
  <b>Per-host usage</b> <span class=muted>(this window; instrumented hosts + combined "other")</span>
  <table id=hosts></table>
</div>
<div class=card id=stopcard style=display:none>
  <b>Danger zone</b>
  <div class=muted>Kill the current top <span id=stopn></span> local consumers (SIGTERM, then SIGKILL after the grace). Protected processes are never touched.</div>
  <button id=stopbtn style=background:#dc2626>⛔ Stop top consumers</button>
  <span id=stopmsg class=muted></span>
</div>
<div class=card>
  <b>Settings</b>
  <form id=f>
    <label>Report interval (min) — how often a digest is sent</label>
    <input name=report_interval_min type=number min=1 max=1440>
    <label>Summary window (min) — how much history each digest + the cap covers</label>
    <input name=summary_window_min type=number min=1 max=10080>
    <label>Cap alert (GB in the summary window; 0 = off)</label>
    <input name=cap_gb type=number step=0.1 min=0>
    <label>Sample interval (sec)</label>
    <input name=sample_interval_sec type=number min=10 max=3600>
    <label>Cap-alert cooldown (min)</label>
    <input name=cap_cooldown_min type=number min=1 max=1440>
    <label>Resolve endpoint IPs to hostnames (1 = on, 0 = off)</label>
    <input name=resolve_names type=number min=0 max=1>
    <label>Projection window (min) — rate basis for the projected next-1h figure</label>
    <input name=projection_window_min type=number min=1 max=60>
    <label>Graph window (min) — time span shown in the rate graph</label>
    <input name=graph_window_min type=number min=5 max=1440>
    <label>Stop-top: number of consumers to kill (host mode)</label>
    <input name=stop_top_n type=number min=1 max=20>
    <label>Stop-top: SIGTERM→SIGKILL grace (sec)</label>
    <input name=stop_grace_sec type=number min=1 max=60>
    <label>Admin token (only needed if the panel requires one)</label>
    <input id=token type=password style=width:200px>
    <button type=submit>Save</button>
    <span id=saved class=muted></span>
  </form>
</div>
<script>
function setText(id,t){ document.getElementById(id).textContent = t; }
document.getElementById('token').value = localStorage.getItem('marsad_token')||'';
async function refresh(){
  let s = await (await fetch('/api/stats')).json();
  setText('up', s.uplink);
  setText('live', '⬇ '+s.live.rx_rate+'  ⬆ '+s.live.tx_rate+'  Σ '+s.live.total_rate);
  setText('window', 'last '+s.cfg.summary_window_min+' min:  ⬇ '+s.window.rx+' down  ⬆ '+s.window.tx+' up  Σ '+s.window.total+' total');
  setText('day', 'today:  ⬇ '+s.day.rx+' down  ⬆ '+s.day.tx+' up  Σ '+s.day.total+' total');
  if(s.projection) setText('proj', 'projected next 1h:  Σ '+s.projection.total+'   (⬇ '+s.projection.rx+'  ⬆ '+s.projection.tx+')');
  setText('attr', s.attributed_pct+'% attributed to a process');
  setText('ago', new Date().toLocaleTimeString());
  let gw = s.cfg.graph_window_min||120; setText('gwin', gw);
  document.getElementById('graph').src = '/graph.svg?mins='+gw+'&_='+Date.now();
  let host = s.mode==='host';
  document.getElementById('stopcard').style.display = host ? '' : 'none';
  document.getElementById('talkerscard').style.display = host ? '' : 'none';
  document.getElementById('devicescard').style.display = host ? 'none' : '';
  document.getElementById('hostscard').style.display = host ? 'none' : '';
  setText('stopn', s.cfg.stop_top_n);
  let tb = document.getElementById('talkers');
  tb.replaceChildren();
  if(!s.talkers.length){
    let td = tb.insertRow().insertCell(); td.className='muted'; td.textContent='no data';
  } else for(const x of s.talkers){
    let tr = tb.insertRow();
    tr.insertCell().textContent = x.label;
    let c1 = tr.insertCell(); c1.className='r'; c1.textContent = x.bytes;
    let c2 = tr.insertCell(); c2.className='r'; c2.textContent = x.pct+'%';
  }
  if(s.router) renderRouter(s.router);
  for(const k in s.cfg){ let el=document.querySelector('[name='+k+']'); if(el&&el!==document.activeElement) el.value=s.cfg[k]; }
}
function renderRouter(r){
  setText('devcount', (r.devices||[]).length);
  let db = document.getElementById('devices'); db.replaceChildren();
  if(!(r.devices||[]).length){ let td=db.insertRow().insertCell(); td.className='muted'; td.textContent=r.available===false?'router unreachable':'no devices'; }
  else for(const d of r.devices){ let tr=db.insertRow(); tr.insertCell().textContent=d.name||d.mac||d.ip||'?'; let c=tr.insertCell(); c.className='muted'; c.textContent=(d.ip||'')+(d.mac?'  '+d.mac:''); }
  let hb = document.getElementById('hosts'); hb.replaceChildren();
  for(const h of (r.per_host||[])){ let tr=hb.insertRow(); tr.insertCell().textContent=h.host; let c=tr.insertCell(); c.className='r'; c.textContent=h.total; }
  if(r.residual){ let tr=hb.insertRow(); tr.insertCell().textContent='other / uninstrumented (combined)'; let c=tr.insertCell(); c.className='r'; c.textContent=r.residual; }
}
document.getElementById('stopbtn').onclick = async ()=>{
  if(!confirm('Kill the current top local consumers? Sends SIGTERM, then SIGKILL after the grace.')) return;
  let t = document.getElementById('token').value;
  let r = await (await fetch('/stop-top',{method:'POST',headers:{'Content-Type':'application/json','X-Marsad-Token':t},body:JSON.stringify({confirm:true})})).json();
  if(r.ok){ let k=(r.killed||[]).map(x=>x.name+'('+x.pid+'→'+x.signal+')').join(', ')||'nothing'; setText('stopmsg','✓ '+k+((r.skipped||[]).length?' · skipped '+r.skipped.length+' protected':'')); }
  else setText('stopmsg','✗ '+(r.error||'error'));
  setTimeout(()=>setText('stopmsg',''),6000);
};
document.getElementById('f').onsubmit = async e =>{
  e.preventDefault();
  let t = document.getElementById('token').value;
  localStorage.setItem('marsad_token', t);
  let fd = Object.fromEntries(new FormData(e.target));
  let r = await (await fetch('/config',{method:'POST',headers:{'Content-Type':'application/json','X-Marsad-Token':t},body:JSON.stringify(fd)})).json();
  setText('saved', r.ok ? '✓ saved' : '✗ '+(r.error||'error'));
  setTimeout(()=>setText('saved',''),2500);
  refresh();
};
refresh(); setInterval(refresh, 5000);
</script></body></html>""".replace("{HOST}", HOST)


def make_handler(daemon):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 15

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/index"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif self.path.startswith("/api/stats"):
                self._send(200, json.dumps(self._stats()))
            elif self.path.startswith("/graph.svg"):
                self._send(200, self._graph(), "image/svg+xml; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def _graph(self):
            cfg = daemon.cfg
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            iface = params.get("iface", [""])[0] or (daemon.uplink or "")
            if not IFACE_RE.fullmatch(iface or ""):
                iface = daemon.uplink or ""
            try:
                mins = int(params.get("mins", [cfg["graph_window_min"]])[0])
            except (ValueError, TypeError):
                mins = cfg["graph_window_min"]
            mins = min(max(mins, 5), 1440)
            if not iface:
                return render_svg([[0, 0]], 1)
            bins, width = daemon.store.series(iface, int(time.time()) - mins * 60)
            return render_svg(bins, width)

        def _check_token(self):
            tok = env_value("MARSAD_PANEL_TOKEN")
            if tok and self.headers.get("X-Marsad-Token", "") != tok:
                self._send(403, json.dumps({"ok": False, "error": "bad or missing admin token"}))
                return None
            return tok or ""

        def _read_json(self):
            n = int(self.headers.get("Content-Length", 0))
            if n > 65536:
                raise ValueError("payload too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_POST(self):
            if self.path == "/config":
                self._do_config()
            elif self.path == "/stop-top":
                self._do_stop_top()
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def _do_config(self):
            # Changing settings requires an admin token to be configured (matched).
            # With no token the panel is view-only — never silently world-writable.
            tok = self._check_token()
            if tok is None:
                return
            if not tok:
                self._send(403, json.dumps(
                    {"ok": False, "error": "set MARSAD_PANEL_TOKEN to change settings"}))
                return
            try:
                data = self._read_json()
                cfg = load_config()
                for k in LIVE_KEYS:
                    if k in data and data[k] != "":
                        v = type(DEFAULTS[k])(data[k])
                        lo, hi = CLAMP[k]
                        cfg[k] = min(max(v, lo), hi)
                if "slack_channel" in data:
                    sc = str(data["slack_channel"]).strip()
                    if sc == "" or re.fullmatch(r"[A-Za-z0-9]{6,24}", sc):
                        cfg["slack_channel"] = sc
                save_config(cfg)
                log(f"config updated from {self.client_address[0]}: { {k: cfg[k] for k in LIVE_KEYS} }")
                self._send(200, json.dumps({"ok": True}))
            except Exception as e:  # noqa: BLE001
                self._send(400, json.dumps({"ok": False, "error": str(e)}))

        def _do_stop_top(self):
            # Destructive: always require an admin token to be configured (not just
            # matched) so an unauthenticated panel can never kill processes.
            tok = self._check_token()
            if tok is None:
                return
            if not tok:
                self._send(403, json.dumps(
                    {"ok": False, "error": "stop-top requires MARSAD_PANEL_TOKEN to be set"}))
                return
            cfg = daemon.cfg
            if cfg.get("mode") != "host":
                self._send(400, json.dumps(
                    {"ok": False, "error": "stop-top is only available in host mode"}))
                return
            try:
                data = self._read_json()
            except Exception as e:  # noqa: BLE001
                self._send(400, json.dumps({"ok": False, "error": str(e)}))
                return
            if data.get("confirm") is not True:
                self._send(400, json.dumps(
                    {"ok": False, "error": 'confirmation required: {"confirm": true}'}))
                return
            res = stop_top_consumers(daemon.collector, cfg["stop_top_n"],
                                     cfg["stop_grace_sec"], cfg.get("protected_procs", []))
            self._send(200 if res.get("ok") else 400, json.dumps(res))

        def _stats(self):
            cfg = daemon.cfg
            up = daemon.uplink or "(resolving)"
            since = int(time.time()) - cfg["summary_window_min"] * 60
            iface = daemon.store.iface_totals(since)
            rx, tx = iface.get(daemon.uplink, (0, 0))
            day = daemon.store.iface_totals(midnight_epoch()).get(daemon.uplink, (0, 0))
            lrx, ltx = daemon.store.last_iface(daemon.uplink) if daemon.uplink else (0, 0)
            span = cfg["sample_interval_sec"] or 60
            talkers = daemon.store.top_talkers(since, limit=10)
            attr_w, tot_w = daemon.store.attribution(since)
            tot = rx + tx
            tk = []
            for label, ws, wr in talkers:
                frac = (ws + wr) / tot_w if tot_w else 0
                if frac < 0.01:
                    continue
                tk.append({"label": pretty_label(label, cfg["resolve_names"]),
                           "bytes": human(frac * tot), "pct": f"{frac*100:.0f}"})
            pj = projection_1h(daemon.store, daemon.uplink, cfg["projection_window_min"])
            out = {
                "host": HOST,
                "mode": cfg["mode"],
                "uplink": up,
                "live": {"rx_rate": human(lrx / span) + "/s",
                         "tx_rate": human(ltx / span) + "/s",
                         "total_rate": human((lrx + ltx) / span) + "/s"},
                "window": {"rx": human(rx), "tx": human(tx), "total": human(rx + tx)},
                "window_bytes": int(rx + tx),   # raw, for router-mode agent aggregation
                "day": {"rx": human(day[0]), "tx": human(day[1]), "total": human(day[0] + day[1])},
                "projection": {"rx": human(pj["rx"]), "tx": human(pj["tx"]), "total": human(pj["total"])},
                "attributed_pct": f"{(attr_w / tot_w * 100) if tot_w else 0:.0f}",
                "talkers": tk,
                "cfg": {k: cfg[k] for k in (
                    "report_interval_min", "summary_window_min", "cap_gb",
                    "sample_interval_sec", "cap_cooldown_min", "slack_channel",
                    "resolve_names", "projection_window_min", "graph_window_min",
                    "stop_top_n", "stop_grace_sec")},
            }
            if cfg["mode"] in ("router", "network"):
                out["router"] = daemon.collector.extras()  # presence / per-host / residual
            return out

    return H


def serve_panel(daemon):
    host = daemon.cfg["panel_host"]
    port = daemon.cfg["panel_port"]
    if host == "tailscale":
        bind = None
        for _ in range(60):
            bind = tailscale_ip()
            if bind:
                break
            log("waiting for tailscale0 IP before binding panel...")
            time.sleep(5)
        if not bind:
            bind = "127.0.0.1"
            log("WARNING: tailscale0 IP not found — panel bound to 127.0.0.1 only")
    elif host == "localhost":
        bind = "127.0.0.1"
    else:
        bind = host
    if bind == "0.0.0.0" and not env_value("MARSAD_PANEL_TOKEN"):
        log("WARNING: panel bound to 0.0.0.0 with NO admin token — usage is viewable "
            "by anyone who can reach this host (settings are read-only without a token; "
            "set MARSAD_PANEL_TOKEN to enable + protect changes)")
    httpd = http.server.ThreadingHTTPServer((bind, port), make_handler(daemon))
    httpd.daemon_threads = True
    log(f"admin panel on http://{bind}:{port}")
    httpd.serve_forever()


# --------------------------------------------------------------------------- #
def main():
    if "--print-config" in sys.argv:
        print(json.dumps(load_config(), indent=2))
        return
    daemon = Daemon()
    if "--once-report" in sys.argv:
        daemon.sample()
        time.sleep(2)
        daemon.sample()
        print(build_digest(daemon.store, daemon.cfg, daemon.uplink or "(none)",
                           daemon.cfg["summary_window_min"]))
        daemon.stop()
        return
    threading.Thread(target=serve_panel, args=(daemon,), daemon=True).start()
    log("marsad started")
    try:
        daemon.loop()
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    main()
