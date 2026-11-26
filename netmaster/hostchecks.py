"""Uptime checks for devices you pick in the device list: ping, or a TCP port (for example SSH, RDP or a NAS).

The device is followed by its MAC, so a new IP from DHCP does not break the check. Alerts go out after a few
missed checks in a row, and nothing is alerted while the server itself has lost its connection.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time

from .insights import PORTS
from .monitors import fmt_duration
from .probes import ping_once

log = logging.getLogger("netmaster.checks")
META_KEY = "host_checks"
INTERVAL_S = 30
FAILS_BEFORE_ALERT = 3  # about 1.5 min without answer
SLOW_MS = 300           # median over the last checks, for "slow" in the UI only


def _tcp(ip: str, port: int, timeout: float = 3.0) -> float | None:
    t = time.perf_counter()
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
    except OSError:
        return None
    return (time.perf_counter() - t) * 1000


class HostChecks:
    def __init__(self, db, events, inventory, net):
        self.db, self.events, self.inventory, self.net = db, events, inventory, net
        self.checks: list[dict] = self._load()
        self.state: dict[str, dict] = {}
        self._wake: asyncio.Event | None = None

    # ---------- the list of checks ----------
    def _load(self) -> list[dict]:
        try:
            items = json.loads(self.db.get_meta(META_KEY) or "[]")
        except ValueError:
            items = []
        return [{"id": str(c["id"]), "mac": str(c["mac"]).lower(), "port": int(c.get("port") or 0)}
                for c in items if isinstance(c, dict) and c.get("id") and c.get("mac")]

    def _save(self) -> None:
        self.db.set_meta(META_KEY, json.dumps(self.checks))

    def add(self, mac: str, port: int = 0) -> dict:
        mac, port = mac.lower(), int(port or 0)
        if mac not in self.inventory.devices:
            raise ValueError("Unknown device")
        if not 0 <= port <= 65535:
            raise ValueError("The port must be between 1 and 65535")
        cid = f"{mac}:{port}"
        if not any(c["id"] == cid for c in self.checks):
            self.checks.append({"id": cid, "mac": mac, "port": port})
            self._save()
            if self._wake:   # check the new one right away instead of waiting up to 30 s
                self._wake.set()
        return self._row(next(c for c in self.checks if c["id"] == cid))

    def remove(self, cid: str) -> bool:
        before = len(self.checks)
        self.checks = [c for c in self.checks if c["id"] != cid]
        self.state.pop(cid, None)
        if len(self.checks) != before:
            self._save()
            return True
        return False

    # ---------- checking ----------
    def _name(self, c: dict) -> str:
        d = self.inventory.devices.get(c["mac"]) or {}
        name = d.get("name") or d.get("hostname") or d.get("vendor") or c["mac"]
        if not c["port"]:
            return name
        return f"{name}: {PORTS.get(c['port']) or 'port ' + str(c['port'])}"

    async def _check(self, c: dict) -> None:
        st = self.state.setdefault(c["id"], {"state": "unknown", "since": time.time(), "ms": None, "fails": 0,
                                             "recent": [], "checked": None})
        ip = (self.inventory.devices.get(c["mac"]) or {}).get("ip")
        if not ip:
            return
        ms = await asyncio.to_thread(_tcp, ip, c["port"]) if c["port"] else await asyncio.to_thread(ping_once, ip, 1500)
        st["checked"], st["ms"] = time.time(), None if ms is None else round(ms, 1)
        if ms is not None:
            st["recent"] = (st["recent"] + [ms])[-10:]
        st["fails"] = 0 if ms is not None else st["fails"] + 1
        if self.net.local_down:
            return  # the server itself is cut off: the device is probably fine
        new = "down" if st["fails"] >= FAILS_BEFORE_ALERT else "up" if ms is not None else st["state"]
        if new == st["state"]:
            return
        prev, dur = st["state"], time.time() - st["since"]
        st["state"], st["since"] = new, time.time()
        name, what = self._name(c), (f"port {c['port']}" if c["port"] else "ping")
        if new == "down":
            self.events.emit("disruption", "warning", f"{name} stopped answering",
                             f"{ip} has not answered {what} for the last {st['fails']} checks "
                             f"({fmt_duration(st['fails'] * INTERVAL_S)}).", c["mac"], kind="host_down")
        elif prev == "down":
            self.events.emit("disruption", "info", f"{name} answers again",
                             f"It was down for {fmt_duration(dur)}.", c["mac"], kind="host_up")

    async def run(self) -> None:
        self._wake = asyncio.Event()
        next_round = 0.0
        while True:
            if time.monotonic() >= next_round:
                todo, next_round = list(self.checks), time.monotonic() + INTERVAL_S
            else:   # woken by add(): only the new ones, so the others keep their pace
                todo = [c for c in self.checks if c["id"] not in self.state]
            self._wake.clear()
            try:
                await asyncio.gather(*(self._check(c) for c in todo))
            except Exception:
                log.exception("Host checks failed")
            try:
                await asyncio.wait_for(self._wake.wait(), max(0.5, next_round - time.monotonic()))
            except asyncio.TimeoutError:
                pass

    # ---------- for the UI ----------
    def _row(self, c: dict) -> dict:
        st = self.state.get(c["id"]) or {}
        recent = sorted(st.get("recent") or [])
        med = recent[len(recent) // 2] if recent else None
        state = st.get("state", "unknown")
        if state == "up" and med is not None and med > SLOW_MS:
            state = "slow"
        return {"id": c["id"], "mac": c["mac"], "port": c["port"], "name": self._name(c),
                "service": (PORTS.get(c["port"]) or "Port") if c["port"] else "Ping",
                "ip": (self.inventory.devices.get(c["mac"]) or {}).get("ip"), "state": state,
                "since": st.get("since"), "ms": st.get("ms"), "median_ms": None if med is None else round(med, 1),
                "checked": st.get("checked")}

    def status(self) -> list[dict]:
        return [self._row(c) for c in self.checks]
