#!/usr/bin/env python3
"""marsad regression tests — stdlib only, no test framework needed:

    python3 tests/test_marsad.py

Covers: the AES-128 / RSA crypto primitives (vs FIPS-197, and OpenSSL when present),
projection + SVG rendering, the host stop-top allowlist + kill path (Linux only),
and the RouterCollector delta/clamp/split/presence/lockout logic plus a full
end-to-end run of the real M7200Client against a mock router."""
import http.server
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["STATE_DIRECTORY"] = tempfile.mkdtemp(prefix="marsad_test_")
os.environ.setdefault("MARSAD_ROUTER_PASSWORD", "s3cret")
_spec = importlib.util.spec_from_file_location("marsad", os.path.join(ROOT, "marsad.py"))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)
m.STATE_DIR = os.environ["STATE_DIRECTORY"]
m.DB_PATH = os.path.join(m.STATE_DIR, "db.sqlite")
m.CONFIG_PATH = os.path.join(m.STATE_DIR, "config.json")

_fails = []
def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        _fails.append(name)
def have(cmd):
    return subprocess.run(["sh", "-c", f"command -v {cmd}"], capture_output=True).returncode == 0


def test_crypto():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    rks = m._key_expansion(key)
    ct = m._encrypt_block(pt, rks)
    check("AES encrypt matches FIPS-197 C.1", ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a")
    check("AES decrypt inverts encrypt", m._decrypt_block(ct, rks) == pt)
    k, iv = b"sixteenbytekey!!", b"sixteenbyteiv!!!"
    msg = b'{"module":"status"}'
    check("AES-CBC PKCS7 round-trip", m.aes_cbc_decrypt(m.aes_cbc_encrypt(msg, k, iv), k, iv) == msg)
    if have("openssl"):
        enc = m.aes_cbc_encrypt(msg, k, iv)
        p = subprocess.run(["openssl", "enc", "-d", "-aes-128-cbc", "-K", k.hex(), "-iv", iv.hex()],
                           input=enc, capture_output=True)
        check("OpenSSL decrypts our AES-CBC", p.returncode == 0 and p.stdout == msg)
        d = tempfile.mkdtemp()
        pem = os.path.join(d, "k.pem")
        subprocess.run(["openssl", "genrsa", "-out", pem, "2048"], capture_output=True)
        mod = subprocess.run(["openssl", "rsa", "-in", pem, "-noout", "-modulus"],
                             capture_output=True, text=True).stdout.strip()
        n = int(mod.split("=")[1], 16)
        secret = b"key=abcd&iv=efgh&h=deadbeef&s=42"
        raw = bytes.fromhex(m.rsa_encrypt_pkcs1v15_hex(secret, 65537, n))
        dp = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", pem],
                            input=raw, capture_output=True)
        check("RSA PKCS1v15 -> OpenSSL decrypt", dp.returncode == 0 and dp.stdout == secret)
    else:
        print("SKIP OpenSSL cross-checks (openssl not found)")


def test_formatting():
    svg = m.render_svg([[100, 50], [200, 0], [0, 300]], 60)
    check("render_svg well-formed", svg.startswith("<svg") and svg.count("<polyline") == 2
          and svg.count("<") == svg.count(">"))
    store = m.Store(os.path.join(m.STATE_DIR, "fmt.db"))
    store.add_sample(int(time.time()) - 60, {"eth0": (300000, 0)}, {})
    check("projection ~3.6MB/h", abs(m.projection_1h(store, "eth0", 5)["total"] - 3_600_000) < 1)


def test_stop_top():
    if sys.platform != "linux":
        print("SKIP stop-top (needs Linux /proc)")
        return
    check("pid<=1 / self / non-numeric protected",
          m.is_protected(1) and m.is_protected(os.getpid()) and m.is_protected("x"))
    victim = subprocess.Popen(["sleep", "300"], start_new_session=True)
    guard = subprocess.Popen(["sleep", "300"], start_new_session=True)
    time.sleep(0.3)
    check("fresh unrelated proc not protected", not m.is_protected(victim.pid))
    check("extra-token protects a proc", m.is_protected(guard.pid, extra=["sleep"]))
    # comm is generic (python3) but the cmdline carries a protected token
    tagged = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(300)", "ci-proxpi-marker"],
                              start_new_session=True)
    time.sleep(0.3)
    check("cmdline token protects when comm is generic",
          m.is_protected(tagged.pid, extra=["ci-proxpi"]) and not m.is_protected(tagged.pid))
    try:
        tagged.kill()
    except Exception:
        pass
    hc = m.HostCollector(dict(m.DEFAULTS))
    hc._pid_acc = {("/bin/sleep", victim.pid): [1e9, 1e9], ("/sbin/init", 1): [9e8, 9e8]}
    res = m.stop_top_consumers(hc, n=5, grace=2, extra=[])
    time.sleep(0.3)
    check("stop-top kills target, skips pid1",
          victim.pid in [k["pid"] for k in res["killed"]]
          and 1 in [s["pid"] for s in res["skipped"]]
          and (victim.poll() is not None or not m.pid_alive(victim.pid)))
    check("stop-top refuses non-host collector", m.stop_top_consumers(object(), 3, 1)["ok"] is False)
    for p in (victim, guard):
        try:
            p.kill()
        except Exception:
            pass


def test_router_logic():
    class Mock:
        def __init__(self): self.t = 0; self.up = False
        def login(self): self.up = True; return True
        def get_status(self):
            if not self.up: raise m.AuthRejected("x")
            return {"rx": None, "tx": None, "total": self.t, "rx_speed": 300, "tx_speed": 100,
                    "operator": "Net", "status": "up"}
        def get_devices(self): return [{"name": "P", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.2"}]
        def logout(self): pass
    rc = m.RouterCollector(dict(m.DEFAULTS, mode="network", router_host="x"), client=Mock())
    rc.client.t = 1_000_000; rc._tick()
    check("router baseline -> no delta", rc.sample() == ({}, {}))
    rc.client.t = 1_500_000; rc._tick()
    d = rc.sample()[0]["WAN"]
    check("WAN delta 500k split 75/25 by speed", d[0] + d[1] == 500000 and abs(d[0] - 375000) <= 1)
    rc.client.t = 200_000; rc._tick()
    check("counter reset clamps to current", sum(rc.sample()[0]["WAN"]) == 200000)
    check("presence MAC normalized", rc.presence()[0]["mac"] == "AA:BB:CC:DD:EE:FF")
    # lockout safety
    posted = []
    m.post_slack = lambda t, ch=None: posted.append(t) or True
    class Bad:
        def login(self): raise m.AuthRejected("nope")
        def logout(self): pass
    rc2 = m.RouterCollector(dict(m.DEFAULTS, router_auth_fail_limit=2), client=Bad())
    now = time.time(); rc2._try_login(now); rc2._try_login(now)
    check("2 bad logins -> LOCKED_OUT + one alert",
          rc2._state == "LOCKED_OUT" and len(posted) == 1 and "REJECTED" in posted[0])
    before = rc2._state; rc2._tick()
    check("locked-out tick is a no-op", rc2._state == before)


def test_router_integration():
    # A crypto-VERIFYING mock M7200: it RSA-decrypts the login `sign` and
    # AES-decrypts the payload to validate the full handshake round-trip (the real
    # wire protocol: {data:base64} requests, base64(json) responses, cookie token).
    import hashlib
    import re as _re
    import subprocess
    import tempfile
    if not have("openssl"):
        print("SKIP router integration (needs openssl)")
        return
    d = tempfile.mkdtemp()
    pem = os.path.join(d, "k.pem")
    subprocess.run(["openssl", "genrsa", "-out", pem, "512"], capture_output=True)
    txt = subprocess.run(["openssl", "rsa", "-in", pem, "-noout", "-text"],
                         capture_output=True, text=True).stdout
    modhex = subprocess.run(["openssl", "rsa", "-in", pem, "-noout", "-modulus"],
                            capture_output=True, text=True).stdout.strip().split("=")[1]
    n = int(modhex, 16)
    e = 65537
    pd = _re.search(r"privateExponent:\s*\n((?:\s+[0-9a-f:]+\n)+)", txt).group(1)
    priv_d = int(_re.sub(r"[^0-9a-f]", "", pd), 16)
    klen = (n.bit_length() + 7) // 8
    NONCE, PW, SEQ = "abc123", "s3cret", 5
    state = {"total": 1_000_000_000}

    def rsa_dec(blob):  # decrypt concatenated PKCS#1 v1.5 blocks -> plaintext
        out = b""
        for i in range(0, len(blob), klen):
            em = pow(int.from_bytes(blob[i:i + klen], "big"), priv_d, n).to_bytes(klen, "big")
            out += em[em.find(b"\x00", 2) + 1:]
        return out

    import base64 as b64
    cls = m.M7200Client
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, obj):
            body = b64.b64encode(json.dumps(obj).encode())
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == cls.AUTH:
                if "sign" in req:  # login: verify the whole handshake
                    kv = dict(p.split("=", 1) for p in rsa_dec(bytes.fromhex(req["sign"])).decode().split("&"))
                    inner = json.loads(m.aes_cbc_decrypt(b64.b64decode(req["data"]),
                                                         kv["key"].encode(), kv["iv"].encode()))
                    ok = (kv["h"] == hashlib.md5(("admin" + PW).encode()).hexdigest()
                          and inner.get("digest") == hashlib.md5((PW + ":" + NONCE).encode()).hexdigest()
                          and int(kv["s"]) == SEQ + len(req["data"]))
                    return self._send({"result": 0, "token": "tok"} if ok else {"result": -2})
                return self._send({"result": 0, "nonce": NONCE, "rsaPubKey": format(e, "x"),
                                   "rsaMod": modhex, "seqNum": SEQ})
            if self.path == cls.WEB:
                inner = json.loads(b64.b64decode(req["data"]))
                if inner.get("token") != "tok":   # token travels in the body, not a cookie
                    return self._send({"result": -4})
                mod = inner["module"]
                if mod == "status":
                    return self._send({"wan": {"totalStatistics": state["total"], "rxSpeed": 300,
                                       "txSpeed": 100, "operatorName": "MockNet", "connectStatus": 4}})
                if mod == "connectedDevices":  # M7200 nests as STAs:{num,list:[...]}
                    return self._send({"STAs": {"num": 1, "list": [
                        {"name": "P", "mac": "a1:b2:c3:d4:e5:f6", "ip": "10.0.0.9"}]}})
                return self._send({"result": 0})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    rc = m.RouterCollector(dict(m.DEFAULTS, mode="network", router_host=f"127.0.0.1:{port}"),
                           client=m.M7200Client(f"127.0.0.1:{port}", PW))
    rc._tick()
    check("integration: full login handshake verified (RSA+AES round-trip)", rc._state == "ACTIVE")
    state["total"] += 2_000_000_000
    rc._tick()
    d2 = rc.sample()[0]["WAN"]
    check("integration: 2GB WAN delta via real HTTP", d2[0] + d2[1] == 2_000_000_000)
    check("integration: device parsed via wlan/clientList", rc.presence()[0]["mac"] == "A1:B2:C3:D4:E5:F6")
    try:
        m.M7200Client(f"127.0.0.1:{port}", "wrongpw").login()
        check("integration: bad pw -> AuthRejected", False)
    except m.AuthRejected:
        check("integration: bad pw -> AuthRejected", True)
    srv.shutdown()


def test_review_fixes():
    # PKCS#7: strict validation rejects bad padding and non-block-multiple input.
    k, iv = b"k" * 16, b"i" * 16
    rks = m._key_expansion(k)
    bad_pt = b"A" * 16  # last byte 0x41 > 16 -> invalid PKCS#7
    bad_ct = m._encrypt_block(bytes(a ^ b for a, b in zip(bad_pt, iv)), rks)
    try:
        m.aes_cbc_decrypt(bad_ct, k, iv); check("AES rejects bad padding", False)
    except ValueError:
        check("AES rejects bad padding", True)
    try:
        m.aes_cbc_decrypt(b"123", k, iv); check("AES rejects non-block-multiple", False)
    except ValueError:
        check("AES rejects non-block-multiple", True)

    # router_max_delta_mb clamps the TOTAL proportionally (ratio preserved).
    rc = m.RouterCollector(dict(m.DEFAULTS, mode="network", router_max_delta_mb=1))
    rc._ingest_wan({"rx": None, "tx": None, "total": 0, "rx_speed": 300, "tx_speed": 100})
    rc._ingest_wan({"rx": None, "tx": None, "total": 2 * 1024 * 1024, "rx_speed": 300, "tx_speed": 100})
    drx, dtx = rc.sample()[0]["WAN"]
    check("delta clamp caps total to 1MB", drx + dtx == 1024 * 1024)
    check("delta clamp preserves 3:1 split", abs(drx - 3 * dtx) <= 2)

    # First credential rejection applies a backoff (no immediate retry storm).
    class Bad:
        def login(self): raise m.AuthRejected("nope")
        def logout(self): pass
    rc2 = m.RouterCollector(dict(m.DEFAULTS, router_auth_fail_limit=3, router_reauth_cooldown_sec=120), client=Bad())
    now = time.time()
    rc2._try_login(now)
    check("1st bad login -> backoff set, not yet locked",
          rc2._state == "NEED_AUTH" and rc2._backoff_until - now >= 100)

    # stop-top identity guard: if a PID is recycled (comm changes) after selection,
    # it must NOT be killed.
    if sys.platform == "linux":
        victim = subprocess.Popen(["sleep", "300"], start_new_session=True)
        time.sleep(0.3)
        hc = m.HostCollector(dict(m.DEFAULTS))
        hc._pid_acc = {("/bin/sleep", victim.pid): [1e9, 1e9]}
        orig = m.proc_comm
        seen = {"n": 0}
        def fake(pid):
            seen["n"] += 1
            return "sleep" if seen["n"] <= 1 else "recycled-proc"  # change after selection
        m.proc_comm = fake
        try:
            res = m.stop_top_consumers(hc, 1, 1, [])
        finally:
            m.proc_comm = orig
        check("recycled PID (comm changed) is NOT killed", m.pid_alive(victim.pid))
        try:
            victim.kill()
        except Exception:
            pass
    else:
        print("SKIP stop-top identity guard (needs Linux)")


if __name__ == "__main__":
    test_crypto()
    test_formatting()
    test_stop_top()
    test_router_logic()
    test_router_integration()
    test_review_fixes()
    print()
    print("ALL PASS" if not _fails else f"{len(_fails)} FAILURES: {_fails}")
    sys.exit(1 if _fails else 0)
