"""Device inventory and ARP protection.

Sources: ARP scan (Npcap) or UDP sweep + the OS ARP table, passive ARP listening (Npcap),
         DHCP lines in the router log.
Alerts:  new unknown device, changed MAC for the main router (ARP spoofing), an IP address flipping between MACs.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections import deque

from .monitors import fmt_duration
from .oui import is_randomized
from .probes import local_ip_for, ptr_lookup, read_arp_table, udp_sweep

log = logging.getLogger("netmaster.inventory")
SAVE_EVERY_S = 60
REALERT_S = 3600


class Inventory:
    _present: dict[str, bool] = {}

    def __init__(self, cfg, db, hub, events, net, oui, l2):
        self.cfg, self.db, self.hub, self.events, self.net = cfg, db, hub, events, net
        self.oui, self.l2 = oui, l2
        self.devices: dict[str, dict] = {}
        self._saved: dict[str, float] = {}
        self.gateway_ip: str | None = None
        self.gateway_mac: str | None = None
        self.current_gateway_mac: str | None = None
        self.local_ip: str | None = None
        self.network: ipaddress.IPv4Network | None = None
        self.baseline_until = 0.0
        self.last_sweep: float | None = None
        self._ip_mac: dict[str, str] = {}
        self._flaps: dict[str, deque] = {}
        self._alerted: dict[tuple, float] = {}

    # ---------- uppstart ----------
    async def setup(self) -> None:
        self.gateway_ip = self.net.gateway.host if self.net.gateway else None
        self.local_ip = await asyncio.to_thread(local_ip_for, self.gateway_ip or "1.1.1.1")
        cidr = self.cfg.lan_cidr if self.cfg.lan_cidr != "auto" else f"{self.local_ip or '192.168.1.1'}/24"
        self.network = ipaddress.ip_network(cidr, strict=False)
        until = self.db.get_meta("baseline_until")
        if until is None:
            until = str(time.time() + self.cfg.baseline_minutes * 60)
            self.db.set_meta("baseline_until", until)
        self.baseline_until = float(until)
        self.gateway_mac = self.db.get_meta("gateway_mac")
        self.devices = {d["mac"]: d for d in self.db.devices()}
        log.info("Network %s, local IP %s, %d known devices", self.network, self.local_ip, len(self.devices))

    @property
    def in_baseline(self) -> bool:
        return time.time() < self.baseline_until

    # ---------- loopar ----------
    async def run_poll(self) -> None:
        """Reads the ARP table often: cheap, and catches ARP poisoning of this computer."""
        while True:
            try:
                rows = await asyncio.to_thread(read_arp_table, self.local_ip)
                self.ingest(rows, "arp-tabell")
                self._check_baseline_done()
            except Exception:
                log.exception("ARP read failed")
            await asyncio.sleep(self.cfg.arp_poll_s)

    # ---------- watched devices: alert when they come and go ----------
    OFFLINE_S = 600  # same limit as "online" in the app

    def _online(self, d: dict) -> bool:
        return time.time() - (d.get("last_seen") or 0) < self.OFFLINE_S

    async def run_presence(self) -> None:
        self._present = {m: self._online(d) for m, d in self.devices.items() if d.get("watch")}
        while True:
            await asyncio.sleep(30)
            try:
                for mac, d in list(self.devices.items()):
                    if not d.get("watch"):
                        continue
                    on, was = self._online(d), self._present.get(mac)
                    self._present[mac] = on
                    if was is None or on == was:
                        continue
                    name = d.get("name") or d.get("hostname") or d.get("vendor") or mac
                    if on:
                        self.events.emit("presence", "notice", f"{name} came online", f"IP {d.get('ip')}.", mac)
                    else:
                        seen = time.strftime("%H:%M", time.localtime(d.get("last_seen") or 0))
                        self.events.emit("presence", "notice", f"{name} went offline",
                                         f"Last seen {seen} (no sign of it for {self.OFFLINE_S // 60} min).", mac)
            except Exception:
                log.exception("Presence check failed")

    async def run_sweep(self) -> None:
        while True:
            try:
                await self.sweep()
            except Exception:
                log.exception("Network sweep failed")
            await asyncio.sleep(self.cfg.sweep_interval_s)

    async def sweep(self) -> None:
        if self.net.local_down:
            return
        if self.l2.available:
            rows = await asyncio.to_thread(self.l2.arping, str(self.network))
            src = "arp-skanning"
        else:
            hosts = [str(h) for h in self.network.hosts() if str(h) != self.local_ip]
            await asyncio.to_thread(udp_sweep, hosts)
            await asyncio.sleep(3)
            rows = await asyncio.to_thread(read_arp_table, self.local_ip)
            src = "svep"
        self.last_sweep = time.time()
        self.ingest(rows, src)
        if self.l2.available and self.l2.mac and self.local_ip:
            self.observe(self.local_ip, self.l2.mac, "self", hostname=None, name="NetMaster server")

    # ---------- inmatning ----------
    def _valid(self, ip: str, mac: str) -> bool:
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or int(mac[:2], 16) & 0x01:
            return False  # broadcast/multicast
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr in self.network and addr not in (self.network.network_address, self.network.broadcast_address)

    def ingest(self, rows, source: str) -> None:
        for ip, mac in rows:
            if self._valid(ip, mac):
                self.check_arp(ip, mac, source)
                self.observe(ip, mac, source)

    def check_arp(self, ip: str, mac: str, source: str) -> None:
        """Detects ARP spoofing: the main router's IP with the wrong MAC, or an IP that keeps changing MAC."""
        now = time.time()
        if ip == self.gateway_ip:
            self.current_gateway_mac = mac
            if self.gateway_mac is None:
                self.gateway_mac = mac
                self.db.set_meta("gateway_mac", mac)
                log.info("Main router MAC learned: %s", mac)
            elif mac != self.gateway_mac:
                claimed = [i for i, m in self._ip_mac.items() if m == mac and i != ip]
                vendor = self.oui.lookup(mac) or "unknown vendor"
                detail = (f"{ip} should have MAC {self.gateway_mac} but now answers with {mac} ({vendor}).")
                if claimed:
                    detail += f" The same MAC is used by {', '.join(claimed)} – that device is probably impersonating the router."
                detail += (f" Source: {source}. Did you replace the main router? Accept the new one under Settings.")
                self._alert(("gw", mac), "security", "critical", "Possible ARP spoofing: router MAC has changed",
                            detail, ip, kind="arp_spoofing")

        prev = self._ip_mac.get(ip)
        if prev and prev != mac:
            q = self._flaps.setdefault(ip, deque(maxlen=10))
            q.append(now)
            recent = [t for t in q if now - t < 600]
            if len(recent) >= 3 and ip != self.gateway_ip:
                self._alert(("flap", ip), "security", "warning", f"{ip} keeps changing MAC address",
                            f"Latest {prev} → {mac}. May be an IP conflict or ARP spoofing.", ip, kind="mac_flapping")
        self._ip_mac[ip] = mac

    def _alert(self, key: tuple, category: str, severity: str, title: str, detail: str, source: str,
               kind: str = "") -> None:
        now = time.time()
        if now - self._alerted.get(key, 0) < REALERT_S:
            return
        self._alerted[key] = now
        self.events.emit(category, severity, title, detail, source, kind=kind)

    def observe(self, ip: str, mac: str, source: str, hostname: str | None = None, name: str | None = None) -> None:
        now = time.time()
        d = self.devices.get(mac)
        if d is None:
            name = name or getattr(self.cfg, "routers", {}).get(ip)
            d = {"mac": mac, "ip": ip, "hostname": hostname, "vendor": self.oui.lookup(mac), "name": name,
                 "trusted": 1 if (self.in_baseline or name) else 0, "randomized": int(is_randomized(mac)),
                 "first_seen": now, "last_seen": now}
            self.devices[mac] = d
            self._save(d)
            if not d["trusted"]:
                self.events.emit("security", "warning", "New device on the network", self.describe(d), ip, kind="new_device")
            if not hostname and self.gateway_ip:
                asyncio.get_running_loop().create_task(self._resolve_name(mac))
            return
        changed = False
        if d["ip"] != ip:
            d["ip"] = ip
            changed = True
        if hostname and d.get("hostname") != hostname:
            d["hostname"] = hostname
            changed = True
        if name and not d.get("name"):
            d["name"] = name
            changed = True
        d["last_seen"] = now
        if changed or now - self._saved.get(mac, 0) > SAVE_EVERY_S:
            self._save(d)

    def observe_dhcp(self, ip: str, mac: str, hostname: str | None) -> None:
        """From the router log (DHCPACK). Often gives the device's own name."""
        mac = mac.lower().replace("-", ":")
        if self._valid(ip, mac):
            self.observe(ip, mac, "dhcp", hostname=hostname if hostname and hostname != "*" else None)

    def _save(self, d: dict) -> None:
        self._saved[d["mac"]] = time.time()
        self.db.device_upsert(d)
        self.hub.publish("device", d)

    async def _resolve_name(self, mac: str) -> None:
        d = self.devices.get(mac)
        if not d:
            return
        host = await asyncio.to_thread(ptr_lookup, d["ip"], self.gateway_ip)
        if host and not d.get("hostname"):
            d["hostname"] = host
            self._save(d)

    def _check_baseline_done(self) -> None:
        if self.in_baseline or self.db.get_meta("baseline_done"):
            return
        self.db.set_meta("baseline_done", str(time.time()))
        n = len(self.devices)
        self.events.emit("system", "info", "Inventory complete",
                         f"{n} devices were registered as known during the first "
                         f"{fmt_duration(self.cfg.baseline_minutes * 60)}. New devices will raise alerts from now on.",
                         "inventory")

    # ---------- user actions ----------
    def update(self, mac: str, name: str | None = None, trusted: bool | None = None,
               watch: bool | None = None, share: bool | None = None) -> dict | None:
        d = self.devices.get(mac)
        if not d:
            return None
        if share is not None:
            d["share"] = int(share)
        if watch is not None:
            d["watch"] = int(watch)
            self._present[mac] = self._online(d)
        if name is not None:
            d["name"] = name.strip() or None
        if trusted is not None:
            d["trusted"] = int(trusted)
        self._save(d)
        return d

    def trust_all(self) -> int:
        n = 0
        for d in self.devices.values():
            if not d["trusted"]:
                d["trusted"] = 1
                self._save(d)
                n += 1
        return n

    def forget(self, mac: str) -> bool:
        if self.devices.pop(mac, None) is None:
            return False
        self.db.device_delete(mac)
        self.hub.publish("device_removed", {"mac": mac})
        return True

    def accept_gateway(self) -> str | None:
        if self.current_gateway_mac:
            self.gateway_mac = self.current_gateway_mac
            self.db.set_meta("gateway_mac", self.gateway_mac)
            self._alerted = {k: v for k, v in self._alerted.items() if k[0] != "gw"}
            self.events.emit("system", "notice", "New main router MAC accepted", self.gateway_mac, self.gateway_ip or "")
        return self.gateway_mac

    # ---------- presentation ----------
    def describe(self, d: dict) -> str:
        parts = [f"IP {d['ip']}", f"MAC {d['mac']}"]
        if d.get("vendor"):
            parts.append(d["vendor"])
        if d.get("hostname"):
            parts.append(f"name {d['hostname']}")
        text = " · ".join(parts)
        if d.get("randomized"):
            text += ("\nRandomised MAC address: usually a phone, tablet or computer using a private Wi-Fi address. "
                     "The same phone may get a new address per Wi-Fi network.")
        return text

    def status(self) -> dict:
        devs = self.devices.values()
        return {
            "network": str(self.network) if self.network else None,
            "count": len(self.devices),
            "untrusted": sum(1 for d in devs if not d["trusted"]),
            "online": sum(1 for d in devs if time.time() - (d["last_seen"] or 0) < 600),
            "in_baseline": self.in_baseline,
            "baseline_until": self.baseline_until,
            "last_sweep": self.last_sweep,
            "gateway_mac": self.gateway_mac,
            "current_gateway_mac": self.current_gateway_mac,
            "arp_ok": not (self.gateway_mac and self.current_gateway_mac and self.gateway_mac != self.current_gateway_mac),
        }
