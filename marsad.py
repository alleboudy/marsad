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

import http.server
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

HOST = socket.gethostname()
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/marsad").split(":")[0]
CONFIG_PATH = os.path.join(STATE_DIR, "config.json")
DB_PATH = os.path.join(STATE_DIR, "marsad.db")
ENV_FILE = os.environ.get("MARSAD_ENV", "/etc/marsad/marsad.env")

DEFAULTS = {
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
}

INTRAHOST_PREFIXES = ("lo", "docker", "br-", "veth", "tailscale")
LIVE_KEYS = ("report_interval_min", "summary_window_min", "cap_gb",
             "cap_cooldown_min", "sample_interval_sec", "resolve_names")
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
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=200")
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


def build_digest(store, cfg, uplink, window_min):
    since = int(time.time()) - window_min * 60
    iface = store.iface_totals(since)
    up_rx, up_tx = iface.get(uplink, (0, 0))

    lines = [f"*{HOST} bandwidth* — last {window_min} min"]
    lines.append(f"WAN ({uplink}):  ⬇ {human(up_rx)} down   ⬆ {human(up_tx)} up   "
                 f"Σ {human(up_rx + up_tx)} total")

    day = store.iface_totals(midnight_epoch()).get(uplink, (0, 0))
    lines.append(f"today so far:  ⬇ {human(day[0])} down   ⬆ {human(day[1])} up   "
                 f"Σ {human(day[0] + day[1])} total")

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

    if cfg["report_interval_min"] != window_min:
        rel = "overlap between reports" if cfg["report_interval_min"] < window_min \
            else "gaps between report windows not shown"
        lines.append(f"_(report every {cfg['report_interval_min']}m, window {window_min}m — {rel})_")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Daemon
# --------------------------------------------------------------------------- #
class Daemon:
    def __init__(self):
        if not os.path.isdir(STATE_DIR):
            os.makedirs(STATE_DIR, exist_ok=True)
        self.cfg = load_config()
        self.uplink = self._resolve_uplink()
        log(f"host={HOST} uplink={self.uplink}")
        self.store = Store(DB_PATH)
        self.labeler = Labeler()
        self.nethogs = NethogsReader(self.uplink or "lo", self.cfg["nethogs_delay_sec"])
        if self.uplink:
            self.nethogs.start()
        self._last_counters = read_proc_net_dev()
        self._last_report = self.store.get_meta("last_report", 0.0)
        self._last_cap_alert = self.store.get_meta("last_cap_alert", 0.0)
        self._last_prune = 0.0
        self._stop = threading.Event()
        dest = self.cfg.get("slack_channel") or env_value("MARSAD_SLACK_CHANNEL")
        if not env_value("MARSAD_SLACK_TOKEN") or not dest:
            log("WARNING slack token/channel not configured — digests + cap alerts will NOT send")
        else:
            log(f"slack destination: {dest}")

    def _resolve_uplink(self):
        return detect_uplink() if self.cfg["uplink_iface"] == "auto" else self.cfg["uplink_iface"]

    def sample(self):
        ts = int(time.time())
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

        proc_weights = {}
        for (path, pid), (ws, wr) in self.nethogs.drain().items():
            label = self.labeler.label(path, pid)
            agg = proc_weights.setdefault(label, [0.0, 0.0])
            agg[0] += ws
            agg[1] += wr

        self.store.add_sample(ts, deltas, proc_weights)
        return ts

    def maybe_retarget(self):
        want = self._resolve_uplink()
        if not want:
            if not self.uplink:
                log("uplink still unresolved (no default route yet)")
            return
        if want != self.uplink or self.cfg["nethogs_delay_sec"] != self.nethogs.delay:
            log(f"re-targeting capture: {self.uplink} -> {want} "
                f"(delay {self.nethogs.delay}->{self.cfg['nethogs_delay_sec']}s)")
            self.nethogs.stop()
            self.uplink = want
            self.nethogs = NethogsReader(want, self.cfg["nethogs_delay_sec"])
            self.nethogs.start()

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
        msg = build_digest(self.store, self.cfg, self.uplink, self.cfg["summary_window_min"])
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
        self.nethogs.stop()


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
</div>
<div class=card>
  <b>Top talkers</b> <span class=muted>(this window, est. share of WAN; <span id=attr></span>)</span>
  <table id=talkers></table>
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
  setText('attr', s.attributed_pct+'% attributed to a process');
  setText('ago', new Date().toLocaleTimeString());
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
  for(const k in s.cfg){ let el=document.querySelector('[name='+k+']'); if(el&&el!==document.activeElement) el.value=s.cfg[k]; }
}
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
            else:
                self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self):
            if self.path != "/config":
                self._send(404, json.dumps({"error": "not found"}))
                return
            tok = env_value("MARSAD_PANEL_TOKEN")
            if tok and self.headers.get("X-Marsad-Token", "") != tok:
                self._send(403, json.dumps({"ok": False, "error": "bad or missing admin token"}))
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > 65536:
                    raise ValueError("payload too large")
                data = json.loads(self.rfile.read(n) or b"{}")
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
            return {
                "host": HOST,
                "uplink": up,
                "live": {"rx_rate": human(lrx / span) + "/s",
                         "tx_rate": human(ltx / span) + "/s",
                         "total_rate": human((lrx + ltx) / span) + "/s"},
                "window": {"rx": human(rx), "tx": human(tx), "total": human(rx + tx)},
                "day": {"rx": human(day[0]), "tx": human(day[1]), "total": human(day[0] + day[1])},
                "attributed_pct": f"{(attr_w / tot_w * 100) if tot_w else 0:.0f}",
                "talkers": tk,
                "cfg": {k: cfg[k] for k in (
                    "report_interval_min", "summary_window_min", "cap_gb",
                    "sample_interval_sec", "cap_cooldown_min", "slack_channel",
                    "resolve_names")},
            }

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
        log("WARNING: panel bound to 0.0.0.0 with NO admin token — "
            "anyone who can reach this host can change settings (set MARSAD_PANEL_TOKEN)")
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
