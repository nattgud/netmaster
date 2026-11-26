"""Network insights: traffic history per device, behaviour alerts, port scans,
external exposure (Shodan InternetDB) and short speed tests."""
from __future__ import annotations

import asyncio
import http.client
import json
import logging
import statistics
import time
import urllib.request

log = logging.getLogger("netmaster.insights")


def _name(inventory, mac: str) -> str:
    d = inventory.devices.get(mac) or {}
    return d.get("name") or d.get("hostname") or d.get("vendor") or mac


# ---------------------------------------------------------------- trafik
class Usage:
    """Sums the router's speeds into bytes per minute and device, and alerts on unusual behaviour."""

    UPLOAD_ALERT_BPS = 1_000_000  # 8 Mbit/s up ...
    UPLOAD_ALERT_S = 300  # ... for 5 minutes in a row
    NIGHT_HOURS = range(1, 5)         # 01–05 lokal tid
    NIGHT_ALERT_BPS = 500_000         # 4 Mbit/s

    def __init__(self, db, events, inventory):
        self.db, self.events, self.inventory = db, events, inventory
        self._minute: float | None = None
        self._acc: dict[str, list[float]] = {}
        self._last_ts: float | None = None
        self._upload_since: dict[str, float] = {}
        self._alerted: dict[tuple[str, str], float] = {}

    def record(self, traffic: dict[str, dict], ts: float | None = None) -> None:
        ts = ts or time.time()
        dt = min(ts - self._last_ts, 120) if self._last_ts else 0
        self._last_ts = ts
        minute = ts - ts % 60
        if self._minute is not None and minute != self._minute:
            self._flush()
        self._minute = minute
        for mac, t in traffic.items():
            down, up = float(t.get("down") or 0), float(t.get("up") or 0)
            if dt and (down or up):
                acc = self._acc.setdefault(mac, [0.0, 0.0])
                acc[0] += down * dt
                acc[1] += up * dt
            self._behaviour(mac, down, up, ts)

    def _flush(self) -> None:
        rows = [(self._minute, mac, d, u) for mac, (d, u) in self._acc.items() if d or u]
        self._acc = {}
        if rows:
            self.db.execute("INSERT INTO usage(ts, mac, down, up) VALUES (?,?,?,?)", rows)

    def _alert_once(self, key: tuple[str, str], every_s: float) -> bool:
        now = time.time()
        if now - self._alerted.get(key, 0) < every_s:
            return False
        self._alerted[key] = now
        return True

    def _behaviour(self, mac: str, down: float, up: float, ts: float) -> None:
        name = _name(self.inventory, mac)
        if up >= self.UPLOAD_ALERT_BPS:
            since = self._upload_since.setdefault(mac, ts)
            if ts - since >= self.UPLOAD_ALERT_S and self._alert_once((mac, "upload"), 3600):
                self.events.emit("security", "notice", f"Heavy upload from {name}",
                                 f"{name} has uploaded over {up * 8 / 1e6:.0f} Mbit/s for "
                                 f"{(ts - since) / 60:.0f} minutes. Fine for backups or streaming, "
                                 "suspicious for a device that normally doesn't.", mac, kind="heavy_upload")
        else:
            self._upload_since.pop(mac, None)
        if time.localtime(ts).tm_hour in self.NIGHT_HOURS and down + up >= self.NIGHT_ALERT_BPS \
                and self._alert_once((mac, "night"), 12 * 3600):
            self.events.emit("security", "info", f"{name} is active at night",
                             f"{(down + up) * 8 / 1e6:.1f} Mbit/s at {time.strftime('%H:%M', time.localtime(ts))}.",
                             mac, kind="night_activity")

    def totals(self, hours: float) -> list[dict]:
        return self.db.query("SELECT mac, SUM(down) AS down, SUM(up) AS up FROM usage WHERE ts >= ? "
                             "GROUP BY mac ORDER BY SUM(down) + SUM(up) DESC", (time.time() - hours * 3600,))

    def series(self, mac: str, hours: float) -> dict:
        bucket = 300 if hours <= 24 else 3600
        rows = self.db.query(f"SELECT CAST(ts / {bucket} AS INT) * {bucket} AS ts, SUM(down) AS down, SUM(up) AS up "
                             "FROM usage WHERE mac = ? AND ts >= ? GROUP BY 1 ORDER BY 1",
                             (mac, time.time() - hours * 3600))
        return {"bucket_s": bucket, "points": rows}


# ---------------------------------------------------------------- portar
PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS",
         445: "SMB", 554: "RTSP (camera)", 1883: "MQTT", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
         5900: "VNC", 8000: "HTTP-alt", 8080: "HTTP-alt", 8096: "Jellyfin", 8443: "HTTPS-alt", 9100: "Printer"}
RISKY = {21, 23, 139, 445, 1883, 3306, 3389, 5432, 5900}


class PortScanner:
    """Checks which common services each device exposes in the network and alerts when new ones open."""

    def __init__(self, cfg, db, events, inventory):
        self.cfg, self.db, self.events, self.inventory = cfg, db, events, inventory
        self.open: dict[str, list[int]] = json.loads(db.get_meta("open_ports") or "{}")
        self.last_scan: float | None = None
        self.running = False

    async def _probe(self, ip: str, port: int, sem) -> bool:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 0.8)
                w.close()
                return True
            except Exception:
                return False

    async def scan(self) -> None:
        if self.running:
            return
        self.running = True
        try:
            now = time.time()
            targets = {mac: d["ip"] for mac, d in self.inventory.devices.items()
                       if d.get("ip") and now - (d.get("last_seen") or 0) < 600}
            sem = asyncio.Semaphore(150)
            jobs = {(mac, p): self._probe(ip, p, sem) for mac, ip in targets.items() for p in PORTS}
            results = dict(zip(jobs, await asyncio.gather(*jobs.values())))
            risky_first = []
            for mac in targets:
                found = sorted(p for p in PORTS if results[(mac, p)])
                before = self.open.get(mac)
                name = _name(self.inventory, mac)
                if before is None:
                    risky_first += [f"{name}: {p} ({PORTS[p]})" for p in found if p in RISKY]
                else:
                    for p in set(found) - set(before):
                        self.events.emit("security", "warning" if p in RISKY else "notice",
                                         f"New open port on {name}: {p} ({PORTS[p]})",
                                         f"{targets[mac]} now accepts connections on port {p}.", mac, kind="new_open_port")
                self.open[mac] = found
            if risky_first:
                self.events.emit("security", "notice", "Risky services found in the network",
                                 "\n".join(risky_first), "netmaster", kind="risky_services")
            self.db.set_meta("open_ports", json.dumps(self.open))
            self.last_scan = time.time()
        finally:
            self.running = False

    async def run(self) -> None:
        await asyncio.sleep(120)  # let the inventory find the devices first
        while True:
            try:
                await self.scan()
            except Exception:
                log.exception("Port scan failed")
            await asyncio.sleep(self.cfg.portscan_interval_h * 3600)

    def status(self) -> dict:
        return {"last_scan": self.last_scan, "running": self.running, "open": self.open,
                "names": {str(p): n for p, n in PORTS.items()}, "risky": sorted(RISKY)}


# ---------------------------------------------------------------- extern exponering
class Exposure:
    """What the internet sees of the public IP address, according to Shodan's free InternetDB."""

    def __init__(self, cfg, db, events, router):
        self.cfg, self.db, self.events, self.router = cfg, db, events, router
        self.result: dict | None = json.loads(db.get_meta("exposure") or "null")
        self.error: str | None = None

    def _fetch(self, ip: str) -> dict:
        req = urllib.request.Request(f"https://internetdb.shodan.io/{ip}", headers={"User-Agent": "NetMaster"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            data = {}  # 404 = nothing known about the address, which is good
        return {"ip": ip, "ports": data.get("ports", []), "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []), "ts": time.time()}

    async def check(self) -> None:
        ip = self.router.public_ip
        if not ip:
            return
        try:
            res = await asyncio.to_thread(self._fetch, ip)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"[:200]
            return
        self.error = None
        old = self.result or {}
        new_ports = set(res["ports"]) - set(old.get("ports", [])) - set(self.cfg.expected_public_ports)
        new_vulns = set(res["vulns"]) - set(old.get("vulns", []))
        if old and new_ports:
            self.events.emit("security", "warning", "New port visible from the internet",
                             f"{ip}: {', '.join(map(str, sorted(new_ports)))}", "netmaster", kind="internet_exposed_port")
        if new_vulns:
            self.events.emit("security", "warning", "Known vulnerabilities reported for your public IP",
                             ", ".join(sorted(new_vulns)[:20]), "netmaster", kind="vulnerability")
        self.result = res
        self.db.set_meta("exposure", json.dumps(res))

    async def run(self) -> None:
        await asyncio.sleep(90)  # wait for the public IP from the router
        while True:
            await self.check()
            await asyncio.sleep(12 * 3600)

    def status(self) -> dict:
        return {"result": self.result, "error": self.error, "expected": self.cfg.expected_public_ports}


# ---------------------------------------------------------------- hastighetstest
class SpeedTest:
    """Short test against Cloudflare: max ~1.5 s and 15 MB down, 1 s and 5 MB up, so the network is not disturbed.

    The test only gets what is left over, so what the other devices used at the same time (from the router
    module's traffic numbers, read just before the test) is added: down_mbps/up_mbps are the whole connection.
    test_*_mbps is what the test itself measured, others_*_mbps the other devices (None without a router module).
    """

    HOST = "speed.cloudflare.com"
    DOWN_S, DOWN_MAX = 1.5, 25_000_000
    UP_S, UP_MAX = 1.0, 5_000_000
    WARMUP_S = 0.25  # TCP slow start is not counted

    TRAFFIC_MAX_AGE_S = 180  # older router numbers say nothing about right now

    def __init__(self, cfg, db, events, hub, modules=None):
        self.cfg, self.db, self.events, self.hub, self.modules = cfg, db, events, hub, modules
        self.last: dict | None = (db.query("SELECT * FROM speedtests ORDER BY ts DESC LIMIT 1") or [None])[0]
        self.error: str | None = None
        self._slow = 0

    def _conn(self):
        return http.client.HTTPSConnection(self.HOST, timeout=10)

    @staticmethod
    def _ok(r):
        # Cloudflare answers 403/429 when it rate limits; then no value is stored.
        if r.status != 200:
            r.read()
            raise RuntimeError(f"speed server answered HTTP {r.status} (rate limited?)")
        return r

    def _ping(self) -> float:
        c = self._conn()
        try:
            c.request("GET", "/__down?bytes=0"); self._ok(c.getresponse()).read()  # opens the connection
            best = 1e9
            for _ in range(3):
                t = time.perf_counter()
                c.request("GET", "/__down?bytes=0"); c.getresponse().read()
                best = min(best, time.perf_counter() - t)
            return best * 1000
        finally:
            c.close()

    def _down(self) -> float:
        c = self._conn()
        try:
            c.request("GET", f"/__down?bytes={self.DOWN_MAX}")
            r = self._ok(c.getresponse())
            t0 = time.perf_counter(); n = 0; tw = None; nw = 0
            while chunk := r.read(65536):
                n += len(chunk)
                el = time.perf_counter() - t0
                if tw is None and el >= self.WARMUP_S:
                    tw, nw = el, n
                if el >= self.DOWN_S:
                    break
            el = time.perf_counter() - t0
            if tw is None or el - tw < 0.1:
                tw, nw = 0, 0
            return (n - nw) * 8 / (el - tw) / 1e6
        finally:
            c.close()

    def _up(self) -> float:
        block = b"\0" * 65536
        sent = [0]
        t0 = time.perf_counter()

        def body():
            while sent[0] < self.UP_MAX and time.perf_counter() - t0 < self.UP_S:
                sent[0] += len(block)
                yield block

        c = self._conn()
        try:
            c.request("POST", "/__up", body=body(), encode_chunked=True,
                      headers={"Transfer-Encoding": "chunked", "Content-Type": "application/octet-stream"})
            self._ok(c.getresponse()).read()
            return sent[0] * 8 / (time.perf_counter() - t0) / 1e6
        finally:
            c.close()

    def _others(self) -> tuple[float, float] | None:
        """Mbit/s (down, up) that all devices on the network used, per the router. None if unknown."""
        m = self.modules
        if not m or not m.traffic or not m.traffic_ts or time.time() - m.traffic_ts > self.TRAFFIC_MAX_AGE_S:
            return None
        down = sum(float(t.get("down") or 0) for t in m.traffic.values())
        up = sum(float(t.get("up") or 0) for t in m.traffic.values())
        return down * 8 / 1e6, up * 8 / 1e6

    async def test(self) -> None:
        others = self._others()  # before the test, so the test's own traffic is not counted
        try:
            ping = await asyncio.to_thread(self._ping)
            down = await asyncio.to_thread(self._down)
            up = await asyncio.to_thread(self._up)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"[:200]
            return
        self.error = None
        ts = time.time()
        od, ou = (round(others[0], 1), round(others[1], 1)) if others else (None, None)
        row = {"ts": ts, "down_mbps": round(down + (od or 0), 1), "up_mbps": round(up + (ou or 0), 1),
               "ping_ms": round(ping, 1), "test_down_mbps": round(down, 1), "test_up_mbps": round(up, 1),
               "others_down_mbps": od, "others_up_mbps": ou}
        self.db.execute(f"INSERT INTO speedtests({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                        [tuple(row.values())])
        self.last = row
        down = row["down_mbps"]
        self.hub.publish("speedtest", self.last)
        self._judge(down)

    def _judge(self, down: float) -> None:
        hist = [r["down_mbps"] for r in self.db.query(
            "SELECT down_mbps FROM speedtests WHERE ts >= ? AND down_mbps IS NOT NULL", (time.time() - 7 * 86400,))]
        if len(hist) < 20:
            return
        med = statistics.median(hist)
        self._slow = self._slow + 1 if down < med * 0.3 else 0
        if self._slow == 3:  # three tests in a row, not a temporary dip
            self.events.emit("disruption", "warning", "Internet is much slower than usual",
                             f"{down:.0f} Mbit/s down, normally about {med:.0f} Mbit/s.", "netmaster")

    def history(self, hours: float) -> list[dict]:
        return self.db.query("SELECT ts, down_mbps, up_mbps, ping_ms, test_down_mbps, test_up_mbps, others_down_mbps, "
                             "others_up_mbps FROM speedtests WHERE ts >= ? ORDER BY ts",
                             (time.time() - hours * 3600,))

    async def run(self) -> None:
        await asyncio.sleep(30)
        while True:
            await self.test()
            await asyncio.sleep(self.cfg.speedtest_interval_min * 60)

    def status(self) -> dict:
        return {"last": self.last, "error": self.error, "interval_min": self.cfg.speedtest_interval_min}


# ---------------------------------------------------------------- important services
class Services:
    """Monitors important web services over HTTP and alerts when they go down."""

    INTERVAL_S = 30
    FAILS_BEFORE_ALERT = 2  # a single miss does not alert

    def __init__(self, cfg, events):
        self.cfg, self.events = cfg, events
        self.state = {name: {"name": name, "url": url, "state": "unknown", "ms": None, "since": None,
                             "error": None, "fails": 0} for name, url in cfg.services.items()}

    def _get(self, url: str) -> float:
        t = time.perf_counter()
        req = urllib.request.Request(url, headers={"User-Agent": "NetMaster"})
        try:
            urllib.request.urlopen(req, timeout=6).close()
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                raise
        return (time.perf_counter() - t) * 1000

    async def _check(self, s: dict) -> None:
        try:
            s["ms"] = round(await asyncio.to_thread(self._get, s["url"]), 1)
            s["error"], s["fails"] = None, 0
            if s["state"] != "up":
                if s["state"] == "down":
                    self.events.emit("disruption", "info", f"{s['name']} is back up",
                                     f"Down for {(time.time() - s['since']) / 60:.0f} min.", s["url"])
                s["state"], s["since"] = "up", time.time()
        except Exception as e:
            s["fails"] += 1
            s["error"] = f"{type(e).__name__}: {e}"[:160]
            if s["fails"] >= self.FAILS_BEFORE_ALERT and s["state"] != "down":
                s["state"], s["since"] = "down", time.time()
                self.events.emit("disruption", "critical", f"{s['name']} is down", s["error"], s["url"])

    async def run(self) -> None:
        while True:
            await asyncio.gather(*(self._check(s) for s in self.state.values()))
            await asyncio.sleep(self.INTERVAL_S)

    def status(self) -> list[dict]:
        return [{k: v for k, v in s.items() if k != "fails"} for s in self.state.values()]


# ---------------------------------------------------------------- Wi-Fi
CONN_LABEL = {"host_2g": "Wi-Fi 2.4 GHz", "host_5g": "Wi-Fi 5 GHz", "guest_2g": "Guest Wi-Fi 2.4 GHz",
              "guest_5g": "Guest Wi-Fi 5 GHz", "wired": "Cable (or another access point)"}


class WifiWatch:
    """Stores each device's signal strength and connection (band or router) per minute.

    Alerts when a device is used with weak signal for a while, and when it jumps back and
    forth between bands/routers (that causes short drops, e.g. freezes in calls).
    """
    WEAK_DBM = -75
    BUSY_BPS = 125_000  # 1 Mbit/s counts as the device being in use

    def __init__(self, db, events, inventory):
        self.db, self.events, self.inventory = db, events, inventory
        self._minute: float | None = None
        self._acc: dict[str, dict] = {}
        self._conn: dict[str, str] = {}
        self._switches: dict[str, list[float]] = {}
        self._weak_since: dict[str, float] = {}
        self._alerted: dict[tuple, float] = {}

    def _once(self, key: tuple, every_s: float) -> bool:
        if time.time() - self._alerted.get(key, 0) < every_s:
            return False
        self._alerted[key] = time.time()
        return True

    def record(self, traffic: dict[str, dict], ts: float | None = None) -> None:
        ts = ts or time.time()
        minute = ts - ts % 60
        if self._minute is not None and minute != self._minute:
            self._flush()
        self._minute = minute
        for mac, t in traffic.items():
            sig, conn = t.get("signal"), t.get("conn")
            sig = sig if isinstance(sig, (int, float)) and sig < 0 else None
            a = self._acc.setdefault(mac, {"s": [], "c": conn})
            if sig is not None:
                a["s"].append(sig)
            a["c"] = conn or a["c"]
            name = _name(self.inventory, mac)
            prev = self._conn.get(mac)
            if conn and prev and conn != prev:
                sw = [x for x in self._switches.get(mac, []) if ts - x < 3600] + [ts]
                self._switches[mac] = sw
                if len(sw) >= 6 and self._once((mac, "flap"), 6 * 3600):
                    self.events.emit("disruption", "warning", f"{name} keeps switching Wi-Fi",
                                     f"Switched connection {len(sw)} times in the last hour (now {CONN_LABEL.get(conn, conn)}). "
                                     "Each switch gives a short dropout. It is usually between two routers or bands with "
                                     "about equally weak signal: move a router, or give them different network names.", mac)
            if conn:
                self._conn[mac] = conn
            busy = (t.get("down") or 0) + (t.get("up") or 0) >= self.BUSY_BPS
            if sig is not None and sig <= self.WEAK_DBM:
                since = self._weak_since.setdefault(mac, ts)
                if busy and ts - since >= 300 and self._once((mac, "weak"), 12 * 3600):
                    self.events.emit("disruption", "notice", f"{name} has weak Wi-Fi while in use",
                                     f"Signal {sig} dBm for {round((ts - since) / 60)} min ({CONN_LABEL.get(conn, conn or '')}). "
                                     "Below about -70 dBm calls and streaming start to stutter. Move closer to a router "
                                     "or use 2.4 GHz, which reaches further.", mac)
            else:
                self._weak_since.pop(mac, None)

    def _flush(self) -> None:
        rows = [(self._minute, mac, round(sum(a["s"]) / len(a["s"]), 1) if a["s"] else None, a["c"])
                for mac, a in self._acc.items()]
        self._acc = {}
        if rows:
            self.db.execute("INSERT INTO wifi(ts, mac, signal, conn) VALUES (?,?,?,?)", rows)

    def series(self, mac: str, hours: float) -> dict:
        rows = self.db.query("SELECT ts, signal, conn FROM wifi WHERE mac = ? AND ts >= ? ORDER BY ts",
                             (mac, time.time() - hours * 3600))
        switches, prev, bucket, pts = 0, None, 300 if hours <= 24 else 3600, {}
        for r in rows:
            if r["conn"] and prev and r["conn"] != prev:
                switches += 1
            prev = r["conn"] or prev
            if r["signal"] is not None:
                pts.setdefault(int(r["ts"] // bucket * bucket), []).append(r["signal"])
        return {"bucket_s": bucket, "points": [[k, round(sum(v) / len(v), 1)] for k, v in sorted(pts.items())],
                "switches": switches, "conn": CONN_LABEL.get(prev, prev)}
