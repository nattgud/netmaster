from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import time
from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import WEB_DIR, load_config
from .db import Database
from .guards import DhcpGuard, DnsGuard, PassiveSniffer
from .hub import EventService, Hub
from .inventory import Inventory
from .l2 import L2
from .monitors import CallQuality, DnsMonitor, FreezeWatch, NetworkMonitor
from .oui import OuiDb
from .push import Push
from .syslog import SyslogServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("netmaster")


async def _prune_loop(cfg, db) -> None:
    while True:
        with contextlib.suppress(Exception):
            db.prune(cfg.sample_retention_days, cfg.syslog_retention_days)
        if auth := getattr(app.state, "auth", None):
            auth.prune()
        if mods := getattr(app.state, "modules", None):
            with contextlib.suppress(Exception):
                mods.prune_metrics()
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = load_config()
    db = Database(cfg.db_path)
    hub = Hub()
    events = EventService(db, hub)

    push = Push(cfg, db)
    try:
        push.setup()
        events.listeners.append(push.on_event)
    except Exception:
        log.exception("Push could not be started")

    net = NetworkMonitor(cfg, db, hub, events)
    await net.setup()
    dnsm = DnsMonitor(cfg, db, hub, events, net)
    dnsm.setup()
    freeze = FreezeWatch(net, events)

    oui = OuiDb(cfg.db_path.parent / "manuf.txt")
    await asyncio.to_thread(oui.load)
    l2 = L2()
    await asyncio.to_thread(l2.init, net.gateway.host if net.gateway else None)
    inventory = Inventory(cfg, db, hub, events, net, oui, l2)
    await inventory.setup()
    dhcp = DhcpGuard(cfg, events, net, l2, oui)
    dnsguard = DnsGuard(cfg, db, events, net)
    sniffer = PassiveSniffer(l2, inventory, dhcp)

    syslog = SyslogServer(cfg, db, hub, events, inventory)
    await syslog.start()

    s = app.state
    s.cfg, s.db, s.hub, s.events, s.push = cfg, db, hub, events, push
    from .auth import Auth
    from .config import DATA_DIR
    s.auth = Auth(db, DATA_DIR)
    if s.auth.needs_setup:
        log.warning("No password set yet. Open NetMaster on this computer, or use the setup code in %s",
                    s.auth.code_file)
    s.net, s.dns, s.syslog = net, dnsm, syslog
    s.freeze = freeze
    s.l2, s.inventory, s.dhcp, s.dnsguard = l2, inventory, dhcp, dnsguard
    from .modules import ModuleManager
    s.modules = await asyncio.to_thread(ModuleManager, cfg, db, events, syslog, inventory, net,
                                        lambda: s.hostflows.local_ip)
    from .insights import Exposure, PortScanner, Services, SpeedTest, Usage, WifiWatch
    s.modules.pause_fn = lambda mac, on, via: set_paused(s, mac, on, via)
    s.modules.protected_fn = lambda: _protected(s)
    s.usage = s.modules.usage = Usage(db, events, inventory)
    s.wifi = s.modules.wifi = WifiWatch(db, events, inventory)
    s.calls = CallQuality(net, events, s.modules.load_mbps, db)
    s.ports = PortScanner(cfg, db, events, inventory)
    s.exposure = Exposure(cfg, db, events, s.modules)
    s.speed = SpeedTest(cfg, db, events, hub, s.modules)
    s.services = Services(cfg, events)
    from .hostchecks import HostChecks
    s.checks = HostChecks(db, events, inventory, net)
    from .hostflows import HostFlows
    from .geo import Geo
    s.geo = Geo(db)
    s.hostflows = HostFlows(db, events, l2, s.geo, lambda: s.modules.public_ip)
    # The frontend's version: changes when any web file changes, so open apps reload themselves.
    from .updater import Updater
    s.updater = Updater(events, cfg.db_path.parent)
    s.build = hashlib.sha1("".join(f"{p}{p.stat().st_mtime_ns}" for p in sorted(WEB_DIR.rglob("*"))
                                   if p.is_file()).encode()).hexdigest()[:12]

    async def refresh_oui():
        await asyncio.to_thread(oui.ensure)
        for d in inventory.devices.values():  # fill in missing vendors
            if not d.get("vendor") and (v := oui.lookup(d["mac"])):
                d["vendor"] = v
                inventory._save(d)

    tasks = [asyncio.create_task(c) for c in (
        net.run(), dnsm.run(), freeze.run(), _prune_loop(cfg, db), _status_loop(app),
        inventory.run_poll(), inventory.run_sweep(), dhcp.run(), dnsguard.run(), refresh_oui(),
        s.ports.run(), s.exposure.run(), s.speed.run(), s.services.run(), s.hostflows.run(),
        s.calls.run(), inventory.run_presence(), s.updater.run(), s.checks.run(),
    )]
    s.modules.start_all()
    sniffer.start()
    s.hostflows.start()
    events.emit("system", "info", "NetMaster started",
                f"Version {__version__}. Npcap: {'active' if l2.available else l2.reason}.", "netmaster")
    try:
        yield
    finally:
        s.modules.stop_all()
        for t in tasks:
            t.cancel()
        l2.stop()
        syslog.stop()
        db.close()


def _status(app: FastAPI) -> dict:
    s = app.state
    return {
        **s.net.status(), "dns": s.dns.status(), "freeze": s.freeze.status(), "dnsfilter": s.modules.dns_status(), "protected": _protected(s), "calls": s.calls.status(), "syslog": s.syslog.status(), "version": __version__,
        "build": s.build, "router": s.modules.router_status(), "modules": s.modules.status(),
        "security": {
            "l2": {"available": s.l2.available, "reason": s.l2.reason, "iface": s.l2.iface_name},
            "inventory": s.inventory.status(), "dhcp": s.dhcp.status(), "dns": s.dnsguard.status(),
        },
        "push": s.push.status(),
        "services": s.services.status() + s.modules.services(), "speedtest": s.speed.status(), "update": s.updater.status(),
        "checks": s.checks.status(), "ports": s.ports.status(), "exposure": s.exposure.status(), "host_flows": s.hostflows.status(),
    }


async def _status_loop(app: FastAPI) -> None:
    while True:
        await asyncio.sleep(app.state.cfg.ping_interval)
        app.state.hub.publish("status", _status(app))


app = FastAPI(title="NetMaster", version=__version__, lifespan=lifespan)


@app.get("/api/status")
def status(request: Request):
    return _status(request.app)


@app.get("/api/events")
def events(request: Request, limit: int = Query(200, le=1000), category: str | None = None,
           before_id: int | None = None):
    from .push import classify
    return [r | {"ntype": classify(r)} for r in request.app.state.db.events(limit, category, before_id)]


@app.get("/api/samples")
def samples(request: Request, minutes: int = Query(60, ge=5, le=60 * 24 * 7)):
    return request.app.state.db.samples(minutes)


@app.get("/api/syslog")
def syslog(request: Request, limit: int = Query(300, le=2000), host: str | None = None):
    return request.app.state.db.syslog(limit, host)


# --- devices ---
@app.get("/api/devices")
def devices(request: Request):
    return sorted(request.app.state.inventory.devices.values(),
                  key=lambda d: (d["trusted"], -(d["last_seen"] or 0)))


@app.patch("/api/devices/{mac}")
def update_device(request: Request, mac: str, body: dict = Body(...)):
    name = body.get("name")
    trusted = body.get("trusted")
    watch, share = body.get("watch"), body.get("share")
    d = request.app.state.inventory.update(mac.lower(), name=name if isinstance(name, str) else None,
                                           trusted=bool(trusted) if trusted is not None else None,
                                           watch=bool(watch) if watch is not None else None,
                                           share=bool(share) if share is not None else None)
    if not d:
        raise HTTPException(404, "Unknown device")
    return d


@app.post("/api/checks")
def add_check(request: Request, body: dict = Body(...)):
    """Watch a device with ping (port 0 or left out) or a TCP port."""
    try:
        return request.app.state.checks.add(str(body.get("mac") or ""), int(body.get("port") or 0))
    except (TypeError, ValueError) as e:
        raise HTTPException(400, str(e))


@app.delete("/api/checks/{cid}")
def remove_check(request: Request, cid: str):
    if not request.app.state.checks.remove(cid):
        raise HTTPException(404, "Unknown check")
    return {"ok": True}


@app.delete("/api/devices/{mac}")
def forget_device(request: Request, mac: str):
    if not request.app.state.inventory.forget(mac.lower()):
        raise HTTPException(404, "Unknown device")
    for c in [c for c in request.app.state.checks.checks if c["mac"] == mac.lower()]:
        request.app.state.checks.remove(c["id"])
    return {"ok": True}


@app.post("/api/devices/{mac}/investigate")
async def investigate_device(request: Request, mac: str):
    import json

    from fastapi.responses import StreamingResponse

    from .investigate import investigate_stream
    s = request.app.state
    d = s.inventory.devices.get(mac.lower())
    if not d:
        raise HTTPException(404, "Unknown device")
    t = s.modules.traffic.get(mac.lower()) or {}
    extra = {"First seen": time.strftime("%Y-%m-%d %H:%M", time.localtime(d["first_seen"])) if d.get("first_seen") else None,
             "Connection": " · ".join(str(v) for v in (t.get("conn"), t.get("ssid"),
                                                       f"signal {t['signal']}" if t.get("signal") is not None else None) if v)}

    async def gen():
        async for ev in investigate_stream(d, extra):
            yield json.dumps(ev) + "\n"
    return StreamingResponse(gen(), media_type="application/x-ndjson", headers={"Cache-Control": "no-cache"})


@app.post("/api/devices/trust-all")
def trust_all(request: Request):
    return {"trusted": request.app.state.inventory.trust_all()}


@app.post("/api/devices/scan")
async def scan(request: Request):
    await request.app.state.inventory.sweep()
    return {"count": len(request.app.state.inventory.devices)}


# --- insights ---
@app.get("/api/usage")
def usage(request: Request, hours: float = Query(24, gt=0, le=24 * 30)):
    return request.app.state.usage.totals(hours)


@app.get("/api/wifi/{mac}")
def wifi_device(request: Request, mac: str, hours: float = Query(24, gt=0, le=24 * 30)):
    return request.app.state.wifi.series(mac.lower(), hours)


def _dns(s, need: str | None = None):
    d = s.modules.provider("dns")
    if not d or (need and not hasattr(d, need)):
        raise HTTPException(400, "No DNS filter module is set up" if not d else "The DNS filter module cannot do this")
    return d


@app.get("/api/dnsfilter/rules")
async def dnsfilter_rules(request: Request):
    d = _dns(request.app.state, "rules")
    try:
        return {"rules": await asyncio.to_thread(d.rules)}
    except Exception as e:
        raise HTTPException(502, f"DNS filter: {e}")


@app.post("/api/dnsfilter/rules")
async def dnsfilter_add_rule(request: Request, body: dict = Body(...)):
    s = request.app.state
    d = _dns(s, "add_rule")
    client = None
    if body.get("mac"):
        client = (s.inventory.devices.get(str(body["mac"]).lower()) or {}).get("ip")
        if not client:
            raise HTTPException(400, "The device has no IP address")
    try:
        rules = await asyncio.to_thread(d.add_rule, str(body.get("domain", "")), str(body.get("action", "")), client)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"DNS filter: {e}")
    return {"rules": rules}


@app.post("/api/dnsfilter/rules/remove")
async def dnsfilter_remove_rule(request: Request, body: dict = Body(...)):
    d = _dns(request.app.state, "remove_rule")
    try:
        return {"rules": await asyncio.to_thread(d.remove_rule, str(body.get("rule", "")))}
    except Exception as e:
        raise HTTPException(502, f"DNS filter: {e}")


@app.get("/api/dns-top")
def dns_top(request: Request, hours: float = Query(24, gt=0, le=24 * 7)):
    d = request.app.state.modules.provider("dns")
    return d.top(hours) if d else {}


@app.get("/api/dns/{mac}")
def dns_device(request: Request, mac: str, hours: float = Query(24, gt=0, le=24 * 30)):
    s = request.app.state
    d = s.modules.provider("dns")
    if not d:
        return {"enabled": False, "domains": [], "total": 0, "blocked": 0}
    return d.device((s.inventory.devices.get(mac.lower()) or {}).get("ip"), hours)


@app.get("/api/calls")
def call_quality(request: Request, hours: float = Query(24, gt=0, le=24)):
    return request.app.state.calls.history(hours)


def _protected(s) -> dict[str, str]:
    """Devices that can never be paused, so you can't lock out the network or NetMaster itself."""
    ips = {s.inventory.local_ip: "the NetMaster server",
           s.net.gateway.host if s.net.gateway else None: "the main router",
           s.net.uplink_target.host if s.net.uplink_target else None: "the device this server is connected through"}
    ips.update(s.cfg.protect)
    ips.update(s.modules.protected())
    return {mac: ips[d["ip"]] for mac, d in s.inventory.devices.items() if d.get("ip") in ips and d["ip"]}


class PauseError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


async def set_paused(s, mac: str, paused: bool, via: str = "NetMaster") -> bool:
    """Pauses or resumes internet for a device through the router module. Returns whether it is paused now.
    Used by the app and by modules (ctx.pause). Raises PauseError with an HTTP-like status."""
    from .sdk import Busy
    mac = mac.lower()
    d = s.inventory.devices.get(mac)
    if not d:
        raise PauseError(404, "Unknown device")
    if paused and (why := _protected(s).get(mac)):
        raise PauseError(403, f"This is {why}. Pausing it would lock up the network, so it is not allowed.")
    router = s.modules.pauser(mac)   # with several router modules: the one that can pause (or has it paused)
    if not router:
        raise PauseError(400, "No router module that can pause devices is set up")
    try:
        blocked = await asyncio.to_thread(router.block, mac, bool(paused), d.get("name") or d.get("hostname") or "")
    except Busy:
        raise PauseError(409, "Someone is logged in to the router's web page. Log out there and try again.")
    except Exception as e:
        raise PauseError(502, f"The router refused: {e}")
    on = mac in blocked
    s.events.emit("system", "info", f"Internet {'paused' if on else 'resumed'} for {d.get('name') or d.get('hostname') or mac}",
                  f"Changed from {via}.", mac)
    return on


@app.post("/api/devices/{mac}/block")
async def block_device(request: Request, mac: str, body: dict = Body(...)):
    try:
        return {"blocked": await set_paused(request.app.state, mac, bool(body.get("blocked")))}
    except PauseError as e:
        raise HTTPException(e.status, str(e))


@app.post("/api/devices/{mac}/wake")
def wake_device(request: Request, mac: str):
    import socket

    from .probes import local_ip_for
    d = request.app.state.inventory.devices.get(mac.lower())
    if not d:
        raise HTTPException(404, "Unknown device")
    # Wake-on-LAN: "magic packet" = 6 x FF followed by the MAC address 16 times, as broadcast.
    pkt = b"\xff" * 6 + bytes.fromhex(mac.lower().replace(":", "").replace("-", "")) * 16
    ip = d.get("ip") or ""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if ip and (src := local_ip_for(ip)):
            s.bind((src, 0))
        for addr in {"255.255.255.255", ip.rsplit(".", 1)[0] + ".255" if ip else "255.255.255.255"}:
            for port in (7, 9):
                s.sendto(pkt, (addr, port))
    return {"ok": True}


@app.get("/api/usage/{mac}")
def usage_device(request: Request, mac: str, hours: float = Query(24, gt=0, le=24 * 30)):
    return request.app.state.usage.series(mac.lower(), hours)


@app.get("/api/speedtests")
def speedtests(request: Request, hours: float = Query(24, gt=0, le=24 * 90)):
    return request.app.state.speed.history(hours)


@app.post("/api/speedtest")
async def speedtest_now(request: Request):
    await request.app.state.speed.test()
    return request.app.state.speed.status()


@app.get("/api/geo/{ip}")
async def geo_ip(request: Request, ip: str):
    import ipaddress
    import socket
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    geo = request.app.state.geo
    await geo.lookup([ip])

    def rdns():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    return {"ip": ip, "geo": geo.get(ip), "host": await asyncio.to_thread(rdns)}


@app.post("/api/trace/{ip}")
async def trace(request: Request, ip: str):
    try:
        return await request.app.state.geo.trace(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")


@app.post("/api/portscan")
async def portscan_now(request: Request):
    await request.app.state.ports.scan()
    return request.app.state.ports.status()


# --- security ---
@app.post("/api/security/accept-gateway")
def accept_gateway(request: Request):
    return {"gateway_mac": request.app.state.inventory.accept_gateway()}


@app.post("/api/security/check")
async def security_check(request: Request):
    s = request.app.state
    await s.dnsguard.check()
    if s.l2.available:
        await s.dhcp.check()
    return {"dns": s.dnsguard.status(), "dhcp": s.dhcp.status()}


# --- push ---
@app.get("/api/push/key")
def push_key(request: Request):
    return {"key": request.app.state.push.public_key}


@app.post("/api/push/subscribe")
def push_subscribe(request: Request, sub: dict = Body(...)):
    try:
        request.app.state.push.subscribe(sub, request.headers.get("user-agent", ""))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/api/push/unsubscribe")
def push_unsubscribe(request: Request, body: dict = Body(...)):
    request.app.state.push.unsubscribe(body.get("endpoint", ""))
    return {"ok": True}


@app.get("/api/push/prefs")
def push_prefs(request: Request):
    push = request.app.state.push
    return {"types": push.catalog(), "muted": push.prefs()["muted"]}


@app.put("/api/push/prefs")
def push_set_prefs(request: Request, body: dict = Body(...)):
    push = request.app.state.push
    return push.set_prefs(body.get("types"), body.get("muted"))


@app.post("/api/push/mute")
def push_mute(request: Request, body: dict = Body(...)):
    """Add (mute: true) or remove a mute rule: {title?, type?, device?}. A plain {"title"} mutes just that kind of title."""
    from .push import _rules
    push = request.app.state.push
    rule = _rules([body.get("rule") or {"title": str(body.get("title", ""))}])
    if not rule:
        raise HTTPException(400, "Empty mute rule")
    muted = [m for m in push.prefs()["muted"] if m != rule[0]] + (rule if body.get("mute", True) else [])
    return push.set_prefs(muted=muted)


@app.post("/api/push/test")
async def push_test(request: Request, body: dict = Body(default={})):
    sent = await request.app.state.push.send_all(
        {"title": "NetMaster test notification", "body": "Notifications are working.", "tag": "nm-test", "url": "./"},
        only=body.get("endpoint"))
    return {"sent": sent, "error": request.app.state.push.last_error if not sent else None}


# --- settings ---
@app.get("/api/settings")
def get_settings(request: Request):
    from .config import settings_view
    return settings_view(request.app.state.cfg)


@app.put("/api/settings")
def put_settings(request: Request, body: dict = Body(...)):
    from .config import SETTINGS, load_config, save_settings
    try:
        save_settings(body)
    except ValueError as e:
        raise HTTPException(400, str(e))
    fresh, cfg = load_config(), request.app.state.cfg
    restart = any(s.get("restart") and getattr(fresh, s["key"]) != getattr(cfg, s["key"]) for s in SETTINGS)
    for s in SETTINGS:  # most settings take effect at once
        if not s.get("restart"):
            setattr(cfg, s["key"], getattr(fresh, s["key"]))
    return {"ok": True, "restart_needed": restart}


@app.post("/api/restart")
async def restart(request: Request):
    """Stops NetMaster. The service (or scripts/run.ps1) starts it again within seconds."""
    import os

    async def later():
        await asyncio.sleep(0.5)
        os._exit(3)
    asyncio.create_task(later())
    return {"ok": True}


# --- first-run guide and access ---
def _tailscale() -> dict:
    """Is Tailscale installed and logged in, and what is this computer's name in the tailnet?"""
    import json
    import shutil
    import subprocess
    import os
    path = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Tailscale", "tailscale.exe")
    exe = shutil.which("tailscale") or (path if os.path.exists(path) else None)
    if not exe:
        return {"installed": False}
    try:
        st = json.loads(subprocess.run([exe, "status", "--json"], capture_output=True, text=True, timeout=10,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout or "{}")
        name = (st.get("Self") or {}).get("DNSName", "").rstrip(".")
        return {"installed": True, "exe": exe, "running": st.get("BackendState") == "Running", "name": name}
    except Exception as e:
        return {"installed": True, "exe": exe, "running": False, "error": str(e)}


@app.get("/api/setup/info")
async def setup_info(request: Request):
    s, cfg = request.app.state, request.app.state.cfg
    ts = await asyncio.to_thread(_tailscale)
    https = bool(cfg.https_cert and cfg.https_key)
    scheme, ip = "https" if https else "http", s.inventory.local_ip
    urls = {"this_computer": f"{scheme}://localhost:{cfg.http_port}",
            "home_network": f"{scheme}://{ip}:{cfg.http_port}" if ip and cfg.http_host == "0.0.0.0" else None,
            "tailscale": f"https://{ts['name']}" if ts.get("running") and ts.get("name") else None}
    return {"gateway": s.net.gateway.host if s.net.gateway else None, "local_ip": ip, "lan_cidr": cfg.lan_cidr,
            "http_host": cfg.http_host, "http_port": cfg.http_port, "https": https, "tailscale": ts, "urls": urls}


@app.post("/api/setup/tailscale")
async def setup_tailscale(request: Request):
    """Publishes NetMaster in your tailnet with HTTPS (tailscale serve). Only reachable by your own devices."""
    import subprocess
    ts = await asyncio.to_thread(_tailscale)
    if not ts.get("running"):
        raise HTTPException(400, "Tailscale is not installed or not logged in on this computer")
    port = request.app.state.cfg.http_port
    r = await asyncio.to_thread(subprocess.run, [ts["exe"], "serve", "--bg", str(port)], capture_output=True, text=True,
                                timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0:
        raise HTTPException(502, (r.stderr or r.stdout or "tailscale serve failed")[-300:])
    return {"url": f"https://{ts['name']}"}


@app.post("/api/setup/done")
def setup_done(request: Request):
    request.app.state.db.set_meta("setup_done", str(time.time()))
    return {"ok": True}


# --- NetMaster updates ---
@app.get("/api/update")
async def update_status(request: Request, check: bool = False):
    u = request.app.state.updater
    return await u.check() if check else u.status()


@app.post("/api/update")
async def update_start(request: Request):
    try:
        await asyncio.to_thread(request.app.state.updater.start)
    except Exception as e:
        raise HTTPException(400, str(e))
    return request.app.state.updater.status()


# --- modules ---
@app.get("/api/modules")
async def modules_list(request: Request, refresh: bool = False):
    m = request.app.state.modules
    return {"modules": await asyncio.to_thread(m.catalog, refresh), "source": request.app.state.cfg.module_source,
            "source_error": m.source_error, "jobs": m.jobs}


@app.post("/api/modules/{mid}/install")
async def module_install(request: Request, mid: str):
    """Starts installing (or updating) a module. Follow the progress with GET /api/modules/jobs."""
    request.app.state.modules.start_install(mid)
    return {"ok": True}


@app.get("/api/modules/jobs")
def module_jobs(request: Request):
    return request.app.state.modules.jobs


@app.post("/api/modules/{mid}/uninstall")
async def module_uninstall(request: Request, mid: str):
    request.app.state.modules.uninstall(mid)
    return {"ok": True}


@app.post("/api/modules/{mid}/action/{aid}")
async def module_action(request: Request, mid: str, aid: str, body: dict = Body(default={})):
    """Presses a module's button (declared under "actions" in its module.json)."""
    try:
        msg = await request.app.state.modules.run_action(mid, aid, (body or {}).get("value"))
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"message": msg}


@app.get("/api/modules/{mid}/metrics")
def module_metrics(request: Request, mid: str, hours: float = 24):
    """History of the values a module records with ctx.record(), for the graphs in its card."""
    return request.app.state.modules.metrics(mid, hours)


@app.get("/api/i18n/modules.tsv")
def module_strings(request: Request):
    """The installed modules' own translations, in the same format as web/i18n/strings.tsv."""
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(request.app.state.modules.strings(), media_type="text/tab-separated-values; charset=utf-8")


@app.get("/api/devices/{mac}/modules")
def device_module_info(request: Request, mac: str):
    """What modules know about a device (switch port, access point, containers ...)."""
    return request.app.state.modules.device_info(mac.lower())


@app.put("/api/modules/{mid}")
async def module_configure(request: Request, mid: str, body: dict = Body(...)):
    try:
        request.app.state.modules.configure(mid, body.get("settings"), body.get("enabled"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


# --- login ---
def _token(request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else request.cookies.get("nm_session")


def _is_local(request: Request) -> bool:
    """A request from this computer itself, not forwarded by a proxy (tailscale serve, nginx, ...)."""
    proxied = any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip", "tailscale-user-login"))
    return bool(request.client) and request.client.host in ("127.0.0.1", "::1") and not proxied


def _login_response(request: Request, token: str):
    from fastapi.responses import JSONResponse
    from .auth import COOKIE, SESSION_DAYS
    resp = JSONResponse({"ok": True})
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="lax", secure=https, path="/")
    return resp


@app.get("/api/auth/state")
def auth_state(request: Request):
    a = request.app.state.auth
    logged_in = a.valid(_token(request))
    return {"setup_needed": a.needs_setup, "logged_in": logged_in,
            "setup_local": a.needs_setup and _is_local(request),
            "wizard_needed": logged_in and not request.app.state.db.get_meta("setup_done")}


@app.get("/api/auth/setup-code")
def auth_setup_code(request: Request):
    """The one-time setup code, for the tray icon and the installer. Only on this computer, only before setup."""
    a = request.app.state.auth
    if not (a.needs_setup and _is_local(request)):
        raise HTTPException(403, "Only available on the NetMaster computer before a password is set")
    return {"code": a.setup_code()}


@app.post("/api/auth/setup")
def auth_setup(request: Request, body: dict = Body(...)):
    a, ip = request.app.state.auth, request.client.host if request.client else "?"
    if not a.needs_setup:
        raise HTTPException(409, "A password is already set")
    if a.limited(ip):
        raise HTTPException(429, "Too many attempts. Wait 15 minutes.")
    import hmac
    import secrets
    if not _is_local(request) and not hmac.compare_digest(str(body.get("code", "")).strip(), a.setup_code() or secrets.token_hex(16)):
        a.failed(ip)
        raise HTTPException(403, "Wrong setup code. It is in data/setup-code.txt on the NetMaster computer.")
    try:
        a.set_password(str(body.get("password", "")))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _login_response(request, a.new_session(request.headers.get("user-agent", "")))


@app.post("/api/auth/login")
def auth_login(request: Request, body: dict = Body(...)):
    a, ip = request.app.state.auth, request.client.host if request.client else "?"
    if a.limited(ip):
        raise HTTPException(429, "Too many failed attempts. Wait 15 minutes.")
    if a.needs_setup or not a.check(str(body.get("password", ""))):
        a.failed(ip)
        raise HTTPException(401, "Wrong password")
    return _login_response(request, a.new_session(request.headers.get("user-agent", "")))


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    from fastapi.responses import JSONResponse
    request.app.state.auth.end(_token(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("nm_session", path="/")
    return resp


@app.post("/api/auth/password")
def auth_password(request: Request, body: dict = Body(...)):
    a, ip = request.app.state.auth, request.client.host if request.client else "?"
    if not a.valid(_token(request)):
        raise HTTPException(401, "Not logged in")
    if a.limited(ip):
        raise HTTPException(429, "Too many failed attempts. Wait 15 minutes.")
    if not a.check(str(body.get("current", ""))):
        a.failed(ip)
        raise HTTPException(403, "The current password is wrong")
    try:
        a.set_password(str(body.get("new", "")))
    except ValueError as e:
        raise HTTPException(400, str(e))
    a.end_all(keep=_token(request))  # everyone else has to log in with the new password
    return {"ok": True}


@app.post("/api/auth/logout-all")
def auth_logout_all(request: Request):
    a = request.app.state.auth
    if not a.valid(_token(request)):
        raise HTTPException(401, "Not logged in")
    a.end_all(keep=_token(request))
    return {"ok": True}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    if not websocket.app.state.auth.valid(_token(websocket)):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    hub: Hub = websocket.app.state.hub
    q = hub.subscribe()
    try:
        await websocket.send_json({"type": "status", "data": _status(websocket.app)})
        while True:
            await websocket.send_json(await q.get())
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(q)


@app.middleware("http")
async def require_login(request: Request, call_next):
    """Everything under /api needs a login, except the login endpoints themselves."""
    from fastapi.responses import JSONResponse
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/"):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            # Block cross-site requests (CSRF): the browser always sends Origin on those.
            origin = request.headers.get("origin")
            if origin:
                from urllib.parse import urlparse
                if urlparse(origin).netloc != request.headers.get("host"):
                    return JSONResponse({"detail": "Cross-site request refused"}, status_code=403)
        if not request.app.state.auth.valid(_token(request)):
            return JSONResponse({"detail": "Not logged in"}, status_code=401)
    return await call_next(request)


@app.middleware("http")
async def no_stale_frontend(request: Request, call_next):
    """Browsers and the PWA must always ask the server for new app files (cheap: 304 when unchanged)."""
    resp = await call_next(request)
    if not request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
