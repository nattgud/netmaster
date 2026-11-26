"""Syslog receiver (UDP). ASUS, TP-Link and many other routers can send their logs here."""
from __future__ import annotations

import asyncio
import logging
import re
import time

from . import rules

log = logging.getLogger("netmaster.syslog")

_PRI = re.compile(r"^<(\d{1,3})>(?:1 )?")
_TS3164 = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d\s+")
COOLDOWN_S = 60


def parse(line: str) -> tuple[int, int, str]:
    """Returns (facility, severity, message) for RFC 3164/5424 lines."""
    m = _PRI.match(line)
    pri = int(m.group(1)) if m else 13
    rest = line[m.end():] if m else line
    rest = _TS3164.sub("", rest, count=1)
    return pri // 8, pri % 8, rest.strip()


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, handler):
        self.handler = handler

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            self.handler(data, addr[0])
        except Exception:
            log.exception("Could not handle syslog packet")


class SyslogServer:
    def __init__(self, cfg, db, hub, events, inventory=None):
        self.cfg, self.db, self.hub, self.events = cfg, db, hub, events
        self.inventory = inventory
        self.transport = None
        self.error: str | None = None
        self.sources: dict[str, dict] = {}
        self._cooldown: dict[tuple[str, str], list] = {}  # (rule, host) -> [last, suppressed]

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: _Proto(self.handle), local_addr=(self.cfg.syslog_host, self.cfg.syslog_port))
            log.info("Syslog listening on udp/%s", self.cfg.syslog_port)
        except OSError as e:
            self.error = str(e)
            self.events.emit("system", "warning", f"Cannot receive router logs (udp/{self.cfg.syslog_port})",
                             f"{e}. Is NetMaster running twice? Otherwise change the port in config.toml.", "netmaster")

    def stop(self) -> None:
        if self.transport:
            self.transport.close()

    def handle(self, data: bytes, host: str) -> None:
        text = data.decode("utf-8", errors="replace").strip("\x00\r\n ")
        for line in text.splitlines():
            if line.strip():
                self._line(line, host)

    def _line(self, line: str, host: str, alarm: bool = True, ts: float | None = None) -> None:
        ts = ts or time.time()
        facility, severity, msg = parse(line)
        name = self.cfg.routers.get(host)

        src = self.sources.get(host)
        if src is None:
            src = self.sources[host] = {"host": host, "name": name or host, "count": 0, "first_seen": ts}
            if name:
                self.events.emit("system", "info", f"Receiving logs from {name}", host, host)
            else:
                self.events.emit("security", "notice", "Logs from unknown source",
                                 f"{host} sends syslog but is not listed under [routers] in config.toml.", host, kind="unknown_log_source")
        src["count"] += 1
        src["last_seen"] = ts

        sid = self.db.insert_syslog(ts, host, facility, severity, msg)
        self.hub.publish("syslog", {"id": sid, "ts": ts, "host": host, "facility": facility,
                                    "severity": severity, "message": msg})

        if self.inventory and (lease := rules.dhcp_lease(msg)):
            self.inventory.observe_dhcp(*lease)

        rule = rules.match(msg) if alarm else None
        if not rule or rule.severity == "ignore":
            return
        key = (rule.id, host)
        cd = self._cooldown.get(key)
        if cd and ts - cd[0] < COOLDOWN_S:
            cd[1] += 1
            return
        suppressed = cd[1] if cd else 0
        self._cooldown[key] = [ts, 0]

        detail = f"{name or host}: {msg}"
        if suppressed:
            detail += f"  (+{suppressed} similar since the last alert)"
        ips = [ip for ip in rules.extract_ips(msg) if ip != host]
        if ips and rule.category == "security":
            detail += f"\nAddresses involved: {', '.join(ips)}"
        kind = "router_" + rule.id.removeprefix("ax_") if rule.category == "security" else ""
        self.events.emit(rule.category, rule.severity, rule.title, detail, host, kind=kind)

    def status(self) -> dict:
        return {"port": self.cfg.syslog_port, "listening": self.transport is not None,
                "error": self.error, "sources": list(self.sources.values())}
