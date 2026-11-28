"""Prometheus exporter: NetMaster's measurements at http://<netmaster>:9877/metrics.

Prometheus is the common format for measurements: Prometheus itself, Grafana (Alloy/Agent), Zabbix,
Datadog, Elastic, New Relic, Checkmk and others read it. Like other exporters it has its own port.

    scrape_configs:
      - job_name: netmaster
        static_configs: [{targets: ["192.168.0.34:9877"]}]
        authorization: {credentials: "<the token, if set>"}
"""
from __future__ import annotations

import asyncio
import hmac
import time

from netmaster import __version__
from netmaster.sdk import ModuleBase

UP = {"up": 1, "slow": 1, "degraded": 1, "down": 0}
ONLINE_S = 600   # same limit as "online" in the app


def _esc(v) -> str:
    return str(v if v is not None else "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    """Collects samples and writes the Prometheus text format, one HELP/TYPE per metric."""

    def __init__(self):
        self.out: dict[str, tuple[str, str, list[str]]] = {}

    def add(self, name: str, value, help_: str, labels: dict | None = None, kind: str = "gauge") -> None:
        if value is None:
            return
        name = "netmaster_" + name
        lab = ",".join(f'{k}="{_esc(v)}"' for k, v in (labels or {}).items())
        v = float(value)
        num = str(int(v)) if v.is_integer() and abs(v) < 1e15 else repr(v)   # full precision (timestamps)
        self.out.setdefault(name, (help_, kind, []))[2].append(f"{name}{{{lab}}} {num}" if lab else f"{name} {num}")

    def text(self) -> str:
        lines = []
        for name, (help_, kind, samples) in self.out.items():
            lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}", *samples]
        return "\n".join(lines) + "\n"


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.server: asyncio.base_events.Server | None = None
        self.events: dict[tuple[str, str], int] = {}
        self.scrapes = 0
        self.last_scrape: float | None = None
        self.last_from = ""

    # ---------- the measurements ----------
    def collect(self) -> str:
        m, s = Metrics(), self.ctx.status()
        m.add("info", 1, "NetMaster version", {"version": __version__})
        for part in ("lan", "wan"):
            st = (s.get(part) or {}).get("state")
            if st in UP:
                m.add(f"{part}_up", UP[st], f"1 when the {part.upper()} side works")
        if (u := s.get("uplink")) and u.get("state") in UP:
            m.add("uplink_up", UP[u["state"]], "1 when the uplink (e.g. an access point) answers",
                  {"name": u.get("name"), "host": u.get("host")})
        for t in (s.get("targets") or []) + ((s.get("dns") or {}).get("targets") or []):
            lab = {"name": t.get("name"), "host": t.get("host"), "kind": t.get("kind")}
            if t.get("state") in UP:
                m.add("target_up", UP[t["state"]], "1 when the target answers (router, internet, DNS ...)", lab)
            if t.get("median_ms") is not None:
                m.add("target_latency_seconds", t["median_ms"] / 1000, "Median response time", lab)
            if t.get("loss_pct") is not None:
                m.add("target_loss_ratio", t["loss_pct"] / 100, "Share of lost pings or lookups (0-1)", lab)
        for sv in s.get("services") or []:
            lab = {"name": sv.get("name"), "url": sv.get("url")}
            if sv.get("state") in UP:
                m.add("service_up", UP[sv["state"]], "1 when the service answers", lab)
            if sv.get("ms") is not None:
                m.add("service_latency_seconds", sv["ms"] / 1000, "Service response time", lab)
        for c in s.get("checks") or []:
            lab = {"name": c.get("name"), "ip": c.get("ip"), "service": c.get("service"), "port": c.get("port") or ""}
            if c.get("state") in UP:
                m.add("check_up", UP[c["state"]], "1 when the device's uptime check answers", lab)
            if c.get("median_ms") is not None:
                m.add("check_latency_seconds", c["median_ms"] / 1000, "Uptime check response time", lab)
        if last := (s.get("speedtest") or {}).get("last"):
            m.add("speedtest_download_bits_per_second", (last.get("down_mbps") or 0) * 1e6, "Last speed test, download")
            m.add("speedtest_upload_bits_per_second", (last.get("up_mbps") or 0) * 1e6, "Last speed test, upload")
            if last.get("ping_ms") is not None:
                m.add("speedtest_ping_seconds", last["ping_ms"] / 1000, "Last speed test, ping")
            m.add("speedtest_timestamp_seconds", last.get("ts"), "When the last speed test ran")
        if (f := s.get("freeze")) and f.get("host"):
            m.add("uplink_freezes_24h", f.get("last_24h", 0), "Short freezes of the uplink in the last 24 hours")
        # devices
        now, devs = time.time(), self.ctx.devices()
        online = {mac for mac, d in devs.items() if now - (d.get("last_seen") or 0) < ONLINE_S}
        m.add("devices", len(devs), "Known devices", {"state": "known"})
        m.add("devices", len(online), "Known devices", {"state": "online"})
        m.add("devices", sum(1 for d in devs.values() if not d.get("trusted")), "Known devices", {"state": "not_approved"})
        m.add("devices_paused", len(self.ctx.paused()), "Devices whose internet is paused")
        if self.settings.get("per_device", True):
            for mac, d in devs.items():
                lab = {"mac": mac, "ip": d.get("ip"), "name": d.get("name") or d.get("hostname") or "",
                       "vendor": d.get("vendor") or "", "approved": "yes" if d.get("trusted") else "no"}
                m.add("device_online", 1 if mac in online else 0, "1 when the device was seen in the last 10 minutes", lab)
                m.add("device_last_seen_timestamp_seconds", d.get("last_seen"), "When the device was last seen", {"mac": mac})
                if t := self.ctx.traffic(mac):
                    m.add("device_download_bytes_per_second", t.get("down"), "Live download (from the router module)", {"mac": mac})
                    m.add("device_upload_bytes_per_second", t.get("up"), "Live upload (from the router module)", {"mac": mac})
                    if t.get("signal") is not None:
                        m.add("device_wifi_signal_dbm", t["signal"], "Wi-Fi signal (from the router module)", {"mac": mac})
        for (cat, sev), n in sorted(self.events.items()):
            m.add("events_total", n, "Events since NetMaster started", {"category": cat, "severity": sev}, "counter")
        return m.text()

    # ---------- the web server ----------
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            lines = head.decode("latin-1").split("\r\n")
            method, path = (lines[0].split(" ") + ["", ""])[:2]
            hdr = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ":" in ln)}
            token = str(self.settings.get("token") or "")
            given = hdr.get("authorization", "")
            given = given[7:].strip() if given.lower().startswith("bearer ") else ""
            if token and not hmac.compare_digest(given.encode(), token.encode()):
                status, body, ctype = "401 Unauthorized", b"Missing or wrong token\n", "text/plain"
            elif method not in ("GET", "HEAD"):
                status, body, ctype = "405 Method Not Allowed", b"", "text/plain"
            elif path.split("?")[0] == "/metrics":
                body = self.collect().encode()
                status, ctype = "200 OK", "text/plain; version=0.0.4; charset=utf-8"
                self.scrapes += 1
                self.last_scrape, self.last_from = time.time(), (writer.get_extra_info("peername") or ("",))[0]
                self.ok()
            else:
                status, ctype = "404 Not Found", "text/html"
                body = b'<a href="/metrics">NetMaster metrics</a>\n'
            writer.write(f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                         f"Connection: close\r\n\r\n".encode() + (body if method != "HEAD" else b""))
            await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            pass
        except Exception as e:
            self.error(e)
        finally:
            writer.close()

    async def run(self) -> None:
        host = str(self.settings.get("listen") or "0.0.0.0")
        port = int(float(self.settings.get("port") or 9877))
        try:
            self.server = await asyncio.start_server(self.handle, host, port)
        except OSError as e:
            self.last_error = f"Could not open port {port}: {e.strerror or e}. Pick another port."
            raise
        self.address = f"http://{self.ctx.local_ip if host == '0.0.0.0' else host}:{port}/metrics"
        self.ok()
        q = self.ctx.subscribe_events()
        try:
            while True:
                ev = await q.get()
                k = (ev.get("category") or "other", ev.get("severity") or "info")
                self.events[k] = self.events.get(k, 0) + 1
        finally:
            self.stop()

    def stop(self) -> None:
        if self.server:
            self.server.close()
            self.server = None

    def status(self) -> dict:
        if not getattr(self, "address", None):
            return {}
        read = f"read {self.scrapes} times" + (f" · last from {self.last_from}" if self.last_from else "")
        return {"rows": [{"label": self.address, "value": read if self.scrapes else "not read yet",
                          "state": "up" if self.server else "down"}]}
