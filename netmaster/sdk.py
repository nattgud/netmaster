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

    "smart_home" - shares devices the user picked ("Show in ...", devices()[mac]["share"]) with a smart-home
                system. Use subscribe_events(), traffic(), top_domains(), paused() and pause(mac, on).

Several router modules may run at once (a firewall and a Wi-Fi controller): their clients are merged and
the one with block() is used for pausing.

Helpers: HttpSession / http_request (JSON, forms, Basic auth, cookies, self-signed certificates),
http_get, ServiceWatch. ctx.record(key, value, label, unit) keeps history and draws a graph in the card.
device_info(mac, ip) adds lines to a device's details in the device list. ctx.status() returns what
GET /api/status does. A setting of type "select" with "options" shows a drop-down list.

module.json may also declare
    "notifications": [{"id": "on_battery", "group": "Power", "label": "UPS on battery",
                       "desc": "...", "match": "regex for the event titles", "default": true}]
so the user can turn the module's alerts on and off, and the module folder may hold a strings.tsv
(first row: en<TAB>sv<TAB>... , then one row per English text) with its translations.

Any module may also return {"service": ServiceWatch(...).status()} from status() to show up in the
Services panel ({"services": [...]} for several, each optionally with "value" and "detail" text),
{"rows": [{"label", "value", "state": "up"|"degraded"|"down"}]} to list what it watches in its card,
and protect() -> {ip: reason} for devices that must never be paused.

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
        self._listeners: list = []

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

    def status(self) -> dict:
        """Everything the overview shows, as GET /api/status returns it: "targets" (internet, router ...
        with state, median_ms, loss_pct), "uplink", "services", "checks", "speedtest", "router" and more."""
        return self._m.status_fn()

    def device_by_ip(self, ip: str) -> tuple[str, str]:
        """(MAC, display name) for an IP address, or (ip, ip) when unknown."""
        for mac, d in self._m.inventory.devices.items():
            if d.get("ip") == ip:
                return mac, d.get("name") or d.get("hostname") or d.get("vendor") or ip
        return ip, ip

    def traffic(self, mac: str) -> dict | None:
        """Live traffic for a device from the router module: {"down", "up" (bytes/s), "usage", "signal", "ssid", "conn"}."""
        return self._m.traffic.get(mac)

    def top_domains(self, ip: str, hours: float = 24, n: int = 3) -> list[dict] | None:
        """The sites a device looked up most, from the DNS filter module: [{"domain", "n", "blocked"}].
        None when no DNS filter module runs. Blocking: call it with to_thread."""
        d = self._m.provider("dns")
        if not d or not ip:
            return None
        return (d.device(ip, hours).get("domains") or [])[:n]

    # --- pausing internet for a device ---
    @property
    def can_pause(self) -> bool:
        """True when a router module that can pause devices is running."""
        return bool(self._m.pause_fn and any(hasattr(r, "block") for r in self._m.providers("router")))

    def paused(self) -> set[str]:
        """MAC addresses whose internet is paused right now (by any router module)."""
        return self._m.blocked()

    def protected(self) -> dict[str, str]:
        """{mac: reason} for devices that can never be paused (the router, the NetMaster server ...)."""
        return self._m.protected_fn()

    async def pause(self, mac: str, paused: bool) -> bool:
        """Pause or resume internet for a device. Returns whether it is paused now.
        Raises an exception with a readable message when it is not allowed or the router refuses."""
        if not self._m.pause_fn:
            raise RuntimeError("Pausing is not available")
        return await self._m.pause_fn(mac.lower(), paused, self._m.installed().get(self.id, {}).get("name", self.id))

    # --- events ---
    def subscribe_events(self, maxsize: int = 500) -> asyncio.Queue:
        """A queue that gets every new event as a dict: {"id", "ts", "category", "severity", "title", "detail",
        "source", "kind"}. Call it from run(). It stops when the module stops."""
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)

        def put(ev):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass

        def listener(ev):
            loop.call_soon_threadsafe(put, dict(ev))

        self._m.events.listeners.append(listener)
        self._listeners.append(listener)
        return q

    def _close(self) -> None:
        for fn in self._listeners:
            try:
                self._m.events.listeners.remove(fn)
            except ValueError:
                pass
        self._listeners.clear()

    # --- reporting ---
    def emit(self, category: str, severity: str, title: str, detail: str = "", key: str = "", kind: str = "") -> None:
        """An event. category: security|disruption|presence|system. severity: info|notice|warning|critical.
        kind: a fixed id for the type of alert (lowercase, _), used by automations such as Home Assistant."""
        self._m.events.emit(category, severity, title, detail, key or self.id, kind=kind)

    def record(self, key: str, value: float, label: str = "", unit: str = "") -> None:
        """A measurement to keep history for (at most one per minute is stored, kept 30 days). Every key gets
        a small graph in the module's card. key: a fixed id such as "battery"; label: what the user sees."""
        self._m.record(self.id, key, value, label, unit)

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


class HttpResponse:
    """What http_request returns. HTTP errors are not raised: check .status (or call .check())."""

    def __init__(self, status: int, headers: dict, body: bytes, url: str):
        self.status, self.headers, self.body, self.url = status, headers, body, url

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        import json
        return json.loads(self.body) if self.body.strip() else None

    def check(self) -> "HttpResponse":
        """Raises a readable error for 4xx/5xx, e.g. "Login refused (HTTP 401)"."""
        if not self.ok:
            what = {401: "Login refused", 403: "Access denied", 404: "Not found"}.get(self.status, "The device answered")
            raise RuntimeError(f"{what} (HTTP {self.status})")
        return self


class HttpSession:
    """Blocking HTTP client for a device's API (run it with ctx.to_thread). Keeps cookies between calls,
    so it works for web logins (UniFi, pfSense), and can use HTTP Basic auth (OPNsense, routers).

        api = HttpSession("https://192.168.1.1", verify_tls=False, auth=(key, secret))
        r = api.get("/api/core/firmware/status").check().json()
        api.post("/api/login", json={"username": u, "password": p})
    """

    def __init__(self, base_url: str = "", verify_tls: bool = True, auth: tuple[str, str] | None = None,
                 headers: dict | None = None, timeout: float = 15):
        import http.cookiejar
        import ssl
        import urllib.request
        self.base = base_url.rstrip("/")
        self.timeout, self.headers = timeout, {"User-Agent": "NetMaster", **(headers or {})}
        ctx = ssl.create_default_context()
        if not verify_tls:   # devices in the home network often have self-signed certificates
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        self.cookies = http.cookiejar.CookieJar()
        self._open = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                                 urllib.request.HTTPCookieProcessor(self.cookies)).open
        if auth:
            import base64
            self.headers["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()

    def request(self, method: str, path: str, json=None, data: bytes | dict | None = None,
                headers: dict | None = None, timeout: float | None = None, limit: int = 20_000_000) -> HttpResponse:
        import json as _json
        import urllib.error
        import urllib.parse
        import urllib.request
        url = path if "://" in path else self.base + "/" + path.lstrip("/")
        h = {**self.headers, **(headers or {})}
        if json is not None:
            data, h["Content-Type"] = _json.dumps(json).encode(), "application/json"
        elif isinstance(data, dict):
            data, h["Content-Type"] = urllib.parse.urlencode(data).encode(), "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, headers=h, method=method.upper())
        try:
            with self._open(req, timeout=timeout or self.timeout) as r:
                return HttpResponse(r.status, dict(r.headers), r.read(limit), r.url)
        except urllib.error.HTTPError as e:
            return HttpResponse(e.code, dict(e.headers or {}), e.read(limit) if e.fp else b"", url)

    def get(self, path: str, **kw) -> HttpResponse:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> HttpResponse:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw) -> HttpResponse:
        return self.request("PUT", path, **kw)

    def delete(self, path: str, **kw) -> HttpResponse:
        return self.request("DELETE", path, **kw)


def http_request(method: str, url: str, json=None, data=None, headers: dict | None = None,
                 auth: tuple[str, str] | None = None, timeout: float = 15, verify_tls: bool = True) -> HttpResponse:
    """One blocking request (run it with ctx.to_thread). For several calls with a login, use HttpSession."""
    return HttpSession("", verify_tls, auth, timeout=timeout).request(method, url, json=json, data=data, headers=headers)


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

    def device_info(self, mac: str, ip: str | None) -> list[dict] | None:
        """Optional: what this module knows about one device, shown when the user opens it in the device
        list: [{"label": "Switch port", "value": "Core switch, port 5"}]. Called often: use data you
        already have from run(), never ask the device here."""
        return None

    # Buttons in the module's card. Declare them in module.json:
    #   "actions": [{"id": "test", "label": "Send a test", "help": "optional"}]
    def action_options(self, action_id: str) -> list[dict] | None:
        """Optional choices shown as a list next to the button: [{"value": ..., "label": ...}]."""
        return None

    async def action(self, action_id: str, value: str | None = None) -> str:
        """Runs when the button is pressed (value = the chosen option). Return a short message for the user;
        raise an exception to show an error."""
        raise ValueError("This module has no such action")
