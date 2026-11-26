"""Web Push: notifications to phone and computer even when the app is closed."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
import urllib.parse
from collections import deque

from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from pywebpush import WebPushException, webpush

log = logging.getLogger("netmaster.push")
RANK = {"info": 0, "notice": 1, "warning": 2, "critical": 3}
from .rules import RULES

# Notification types that can be turned on/off. The order matters: the first match wins.
_T = lambda id_, group, label, desc, rx, default=True: {"id": id_, "group": group, "label": label, "desc": desc,
                                                        "rx": re.compile(rx), "default": default}
NOTIF_TYPES = [
    _T("internet_down", "Internet", "Internet is down", "The connection to the internet is lost or disrupted.",
       r"^Internet down|^Internet connection disrupted"),
    _T("internet_slow", "Internet", "Internet is slow", "Speed tests show much lower speed than usual.", r"much slower than usual"),
    _T("call_quality", "Internet", "Poor call quality", "High delay, jitter or lost packets for 2 minutes (bad for video calls).",
       r"^Poor call quality"),
    _T("main_router", "Routers and access points", "Main router unreachable", "The server lost contact with the main router.",
       r"main router"),
    _T("gear_down", "Routers and access points", "Router or access point down or restarted",
       "Lost contact with an access point or other monitored device, or it restarted.",
       r"lost contact with|is not responding|restarted$|No DHCP server responded"),
    _T("gear_unstable", "Routers and access points", "Short freezes and unstable connections",
       "Brief freezes (a few seconds) or packet loss to an access point or monitored device.",
       r"froze for|^Unstable connection to|is slow$"),
    _T("services_down", "Routers and access points", "Your services are down", "A web service you monitor (for example a home server or media server) stops answering.",
       r" is down$"),
    _T("wifi", "Devices", "Wi-Fi problems on a device", "A device keeps switching Wi-Fi or has weak signal while in use.",
       r"keeps switching Wi-Fi|weak Wi-Fi"),
    _T("presence", "Devices", "Device comes online or goes offline", "Only for devices where you turned on 🔔 in the device list.",
       r" came online$| went offline$"),
    _T("new_device", "Security", "New device on the network", "An unknown device connects to your network.", r"^New device on the network"),
    _T("dangerous_site", "Security", "Dangerous or odd sites", "A device contacts a dangerous site, a mining pool, a tunnel service or a random-looking name.",
       r"dangerous site| contacted (?!a new site)|random-looking site|suspicious domain"),
    _T("new_site", "Security", "Quiet device contacts a new site", "A device that normally talks to few sites starts contacting a new one.",
       r"contacted a new site", False),
    _T("open_port", "Security", "New open port on a device", "A device in the network starts accepting connections on a new port.",
       r"^New open port on", False),
    _T("risky_services", "Security", "Risky services in the network", "Summary when a port scan finds risky services such as Telnet or SMB.",
       r"^Risky services found"),
    _T("exposure", "Security", "Open to the internet", "A new port is visible from the internet, or known vulnerabilities are reported for your IP.",
       r"visible from the internet|Known vulnerabilities"),
    _T("router_change", "Security", "Router or DNS settings changed", "Settings changed in the main router, the server's DNS changed, or a new main router appeared.",
       r"^Router setting changed|DNS servers have changed|New main router MAC"),
    _T("new_program", "Security", "New program on the server uses the internet", "A program on the server connects to the internet for the first time.",
       r"^New program on the server"),
    _T("traffic", "Security", "Unusual traffic from a device", "Heavy upload, or activity at night.", r"^Heavy upload from| is active at night", False),
    _T("router_log", "Security", "Alerts from the router logs", "Failed logins, attacks, reboots and similar lines in the router logs.",
       "^(?:" + "|".join(re.escape(r.title) for r in RULES if r.title) + r"|Logs from unknown source)$"),
    _T("system", "NetMaster", "Problems with NetMaster itself", "NetMaster cannot read a router, receive logs or find the gateway.", r".", True),
]


def classify(ev: dict) -> str:
    if ev.get("category") == "system":
        return "system"
    for t in NOTIF_TYPES[:-1]:
        if t["rx"].search(ev["title"]):
            return t["id"]
    return "other"
_NUM = re.compile(r"\d+(?:[.,]\d+)?(?:\s*(?:ms|s|min|h|d|%|Mbit/s|kbit/s))?")


def type_key(title: str) -> str:
    """Notification type: the title without numbers, so "froze for 10 s" and "froze for 11 s" count as the same type."""
    k = _NUM.sub("#", title)
    return re.sub(r"#(?:\s+#)+", "#", k).strip()
MAX_PER_10MIN = 20


class Push:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db
        self.key_path = cfg.db_path.parent / "vapid_private.pem"
        self.vapid: Vapid | None = None
        self.public_key = ""
        self._sent: deque[float] = deque()
        self.last_error: str | None = None

    def setup(self) -> None:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            v = Vapid()
            v.generate_keys()
            v.save_key(str(self.key_path))
            log.info("Nya VAPID-nycklar skapade")
        self.vapid = Vapid.from_file(str(self.key_path))
        raw = self.vapid.public_key.public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
        self.public_key = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    # --- prenumerationer ---
    def subscribe(self, sub: dict, user_agent: str) -> None:
        if not sub.get("endpoint") or not sub.get("keys"):
            raise ValueError("Ogiltig prenumeration")
        self.db.push_add(sub["endpoint"], json.dumps(sub), user_agent[:200])

    def unsubscribe(self, endpoint: str) -> None:
        self.db.push_delete(endpoint)

    # --- sending ---
    # --- which notifications are sent ---
    def prefs(self) -> dict:
        try:
            p = json.loads(self.db.get_meta("push_prefs") or "{}")
        except ValueError:
            p = {}
        on = {t["id"]: t["default"] for t in NOTIF_TYPES} | {k: bool(v) for k, v in (p.get("types") or {}).items()}
        return {"types": on, "muted": list(p.get("muted") or [])}

    def set_prefs(self, types: dict | None = None, muted: list | None = None) -> dict:
        p = self.prefs()
        if types is not None:
            ids = {t["id"] for t in NOTIF_TYPES}
            p["types"] |= {k: bool(v) for k, v in types.items() if k in ids}
        if muted is not None:
            p["muted"] = sorted({type_key(str(m)) for m in muted if str(m).strip()})
        self.db.set_meta("push_prefs", json.dumps(p))
        return p

    def wanted(self, ev: dict) -> bool:
        if ev["severity"] == "info":  # information only, never a notification
            return False
        p = self.prefs()
        return p["types"].get(classify(ev), True) and type_key(ev["title"]) not in p["muted"]

    def catalog(self, days: int = 30) -> list[dict]:
        """All notification types with on/off and how often they have occurred."""
        p = self.prefs()
        stats: dict[str, dict] = {}
        for r in self.db.query("SELECT ts, category, title FROM events WHERE ts > ? AND severity != 'info' ORDER BY ts DESC",
                               (time.time() - days * 86400,)):
            st = stats.setdefault(classify(r), {"n": 0, "last": r["ts"], "example": r["title"]})
            st["n"] += 1
        return [{k: t[k] for k in ("id", "group", "label", "desc")} | {"on": p["types"].get(t["id"], True)}
                | stats.get(t["id"], {"n": 0, "last": None, "example": None}) for t in NOTIF_TYPES]

    def on_event(self, ev: dict) -> None:
        if not self.wanted(ev):
            return
        payload = {"title": ev["title"], "body": ev.get("detail") or "", "tag": f"nm-{ev['id']}",
                   "severity": ev["severity"], "url": "./#events"}
        prefix = "New program on the server is using the internet: "
        if ev["title"].startswith(prefix):  # open the program on the map straight from the notification
            payload["url"] = "./#proc=" + urllib.parse.quote(ev["title"][len(prefix):])
            m = re.search(r"Talking to (\d+\.\d+\.\d+\.\d+)", ev.get("detail") or "")
            if m:
                payload["url"] += "&ip=" + m.group(1)
        asyncio.get_running_loop().create_task(self.send_all(payload, urgent=ev["severity"] == "critical"))

    async def send_all(self, payload: dict, urgent: bool = False, only: str | None = None) -> int:
        now = time.time()
        while self._sent and now - self._sent[0] > 600:
            self._sent.popleft()
        if only is None and len(self._sent) >= MAX_PER_10MIN:
            log.warning("Push limit reached, skipping: %s", payload["title"])
            return 0
        self._sent.append(now)
        subs = [s for s in self.db.push_subs() if only is None or s["endpoint"] == only]
        results = await asyncio.gather(*(asyncio.to_thread(self._send, s, payload, urgent) for s in subs))
        return sum(results)

    def _send(self, sub: dict, payload: dict, urgent: bool) -> bool:
        try:
            webpush(subscription_info=json.loads(sub["data"]), data=json.dumps(payload),
                    vapid_private_key=self.vapid, vapid_claims={"sub": self.cfg.push_contact},
                    ttl=24 * 3600, timeout=15, headers={"Urgency": "high" if urgent else "normal"})
            return True
        except WebPushException as e:
            status = e.response.status_code if e.response is not None else None
            if status in (404, 410):
                log.info("Push subscription expired, removing")
                self.db.push_delete(sub["endpoint"])
            else:
                self.last_error = f"{status}: {e}"
                log.warning("Push misslyckades (%s): %s", status, e)
        except Exception as e:
            self.last_error = str(e)
            log.warning("Push misslyckades: %s", e)
        return False

    def status(self) -> dict:
        return {"subscribers": len(self.db.push_subs()),
                "last_error": self.last_error}
