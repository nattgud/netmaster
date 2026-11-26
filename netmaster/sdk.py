"""Module SDK: everything a NetMaster module needs.

A module is a folder with two files:

    my_module/
        module.json   # name, version, settings the user fills in, what it provides
        module.py     # a class called Module

module.py:

    from netmaster.sdk import ModuleBase

    class Module(ModuleBase):
        async def run(self):            # runs in the background while the module is enabled
            while True:
                text = await self.ctx.to_thread(fetch_log, self.settings["host"])
                for line in text.splitlines():
                    self.ctx.add_log(line, self.settings["host"])
                self.ok()                # shows "working" in the Modules list
                await self.ctx.sleep(300)

        def status(self) -> dict:        # optional extra info shown in the UI
            return {}

What a module can provide (module.json "provides"), and the methods/attributes that come with it:

    "logs"    - nothing extra, just call ctx.add_log(...) for each log line.
    "router"  - call ctx.report_clients([...]) with connected clients and their traffic.
                Optional: self.blocked (list of MACs), self.audit (list of checks), self.public_ip,
                block(mac, on, name) -> list of blocked MACs.
    "dns"     - a DNS filter (e.g. AdGuard Home, Pi-hole).
                top(hours) -> {ip: {"top": [...], "blocked": n, "total": n, "sites": n}}
                device(ip, hours) -> {"domains": [...], "total": n, "blocked": n, "distinct": n}
                Optional: rules(), add_rule(domain, action, client_ip), remove_rule(rule), protect() -> {ip: reason}

Any module may also return {"service": ServiceWatch(...).status()} from status() to show up in the
Services panel, and protect() -> {ip: reason} for devices that must never be paused.

Raise Busy when the device refuses because someone else is logged in. NetMaster then waits and
never forces its way in (it must never log the user out of their router's web page).
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path


class Busy(Exception):
    """The device is busy (for example: someone else is logged in to its web page). Try again later."""


class Context:
    """What NetMaster gives a module. Use these instead of reaching into NetMaster's internals."""

    def __init__(self, manager, module_id: str, data_dir: Path):
        self._m = manager
        self.id = module_id
        self.data_dir = data_dir          # a private folder the module may write to
        self.log = logging.getLogger(f"netmaster.module.{module_id}")
        self.db = manager.db              # Database: query(sql, args), execute(sql, rows), get_meta/set_meta
        self.cfg = manager.cfg            # NetMaster's settings (read only)

    # --- the network ---
    @property
    def gateway(self) -> str | None:
        """IP address of the main router."""
        net = self._m.net
        return net.gateway.host if net and net.gateway else None

    @property
    def local_ip(self) -> str | None:
        """IP address of the computer NetMaster runs on."""
        return self._m.local_ip()

    def router_name(self, ip: str) -> str:
        """The name the user gave a router or access point, or the IP."""
        return self.cfg.routers.get(ip, ip)

    def devices(self) -> dict[str, dict]:
        """Known devices by MAC address: {"ip", "name", "hostname", "vendor", ...}."""
        return self._m.inventory.devices

    def device_by_ip(self, ip: str) -> tuple[str, str]:
        """(MAC, display name) for an IP address, or (ip, ip) when unknown."""
        for mac, d in self._m.inventory.devices.items():
            if d.get("ip") == ip:
                return mac, d.get("name") or d.get("hostname") or d.get("vendor") or ip
        return ip, ip

    # --- reporting ---
    def emit(self, category: str, severity: str, title: str, detail: str = "", key: str = "") -> None:
        """An event. category: security|disruption|presence|system. severity: info|notice|warning|critical."""
        self._m.events.emit(category, severity, title, detail, key or self.id)

    def add_log(self, line: str, host: str, alarm: bool = True, ts: float | None = None) -> None:
        """One log line from a device. alarm=False stores it without raising alerts (use for old history)."""
        self._m.syslog._line(line, host, alarm=alarm, ts=ts)

    def report_clients(self, clients: list[dict]) -> None:
        """Clients connected to the router. Each: {"ip", "mac", "hostname", "down", "up" (bytes/s),
        "usage" (bytes), "signal", "online_s", "ssid", "conn"}. Only ip and mac are required."""
        self._m.report_clients(self.id, clients)

    # --- helpers ---
    @staticmethod
    async def to_thread(fn, *args, **kwargs):
        """Run blocking code (HTTP calls, libraries without async) without freezing NetMaster."""
        return await asyncio.to_thread(fn, *args, **kwargs)

    @staticmethod
    async def sleep(seconds: float) -> None:
        await asyncio.sleep(seconds)


def http_get(url: str, headers: dict | None = None, timeout: float = 8, verify_tls: bool = True) -> tuple[int, bytes]:
    """A simple blocking GET (run it with ctx.to_thread). Returns (status, body); HTTP errors are not raised."""
    import ssl
    import urllib.error
    import urllib.request
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "NetMaster", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(5_000_000)
    except urllib.error.HTTPError as e:
        return e.code, b""


class ServiceWatch:
    """Up/down tracking for a service, with the same alerts as NetMaster's own service checks.

        watch = ServiceWatch(ctx, "Jellyfin", url)
        await watch.check(lambda: http_get(url + "/health"))   # in your run() loop
    """
    FAILS_BEFORE_ALERT = 2  # a single miss is not an alert

    def __init__(self, ctx: "Context", name: str, url: str):
        self.ctx, self.name, self.url = ctx, name, url
        self.state, self.ms, self.since, self.error, self.fails = "unknown", None, None, None, 0

    async def check(self, probe) -> bool:
        """probe: a blocking function that raises (or returns an HTTP status >= 500) when the service is down."""
        t = time.perf_counter()
        try:
            r = await asyncio.to_thread(probe)
            if isinstance(r, tuple) and isinstance(r[0], int) and r[0] >= 500:
                raise RuntimeError(f"HTTP {r[0]}")
            self.ms, self.error, self.fails = round((time.perf_counter() - t) * 1000, 1), None, 0
            if self.state != "up":
                if self.state == "down":
                    self.ctx.emit("disruption", "info", f"{self.name} is back up",
                                  f"Down for {(time.time() - self.since) / 60:.0f} min.", self.url)
                self.state, self.since = "up", time.time()
            return True
        except Exception as e:
            self.fails += 1
            self.error = f"{type(e).__name__}: {e}"[:160]
            if self.fails >= self.FAILS_BEFORE_ALERT and self.state != "down":
                self.state, self.since = "down", time.time()
                self.ctx.emit("disruption", "critical", f"{self.name} is down", self.error, self.url)
            return False

    def status(self) -> dict:
        """Put this under "service" in your module's status() to show it with the other services."""
        return {"name": self.name, "url": self.url, "state": self.state, "ms": self.ms, "since": self.since,
                "error": self.error}


class ModuleBase:
    """Base class for modules. Override run() and optionally status()."""

    def __init__(self, ctx: Context, settings: dict, meta: dict):
        self.ctx, self.settings, self.meta = ctx, settings, meta
        self.last_ok: float | None = None
        self.last_error: str | None = None

    async def run(self) -> None:
        """Runs in the background. Usually a loop: fetch, report, self.ok(), sleep."""

    def status(self) -> dict:
        """Extra info for the UI."""
        return {}

    def ok(self) -> None:
        """Call after each successful round."""
        self.last_ok, self.last_error = time.time(), None

    def error(self, e: Exception | str) -> None:
        """Call when a round failed. Shown in the Modules list."""
        self.last_error = (f"{type(e).__name__}: {e}" if isinstance(e, Exception) else str(e))[:300]
        self.ctx.log.warning("%s", self.last_error)

    def stop(self) -> None:
        """Called when the module is disabled or NetMaster stops. Close connections here if needed."""
