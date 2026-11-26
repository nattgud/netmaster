"""Protection against rogue DHCP servers and tampered DNS, plus passive listening via Npcap."""
from __future__ import annotations

import asyncio
import logging
import secrets
import time

from .probes import dns_answers, system_dns_servers

log = logging.getLogger("netmaster.guards")
REALERT_S = 3600

# Names whose answers never change. If the router's DNS gives another answer, DNS traffic is being tampered with.
FIXED_ANSWERS = {
    "one.one.one.one": {"1.1.1.1", "1.0.0.1"},
    "dns.google": {"8.8.8.8", "8.8.4.4"},
    "dns.quad9.net": {"9.9.9.9", "149.112.112.112"},
}


class _Alerts:
    def __init__(self, events):
        self.events = events
        self._sent: dict[tuple, float] = {}

    def alert(self, key, category, severity, title, detail, source, every=REALERT_S) -> None:
        now = time.time()
        if now - self._sent.get(key, 0) < every:
            return
        self._sent[key] = now
        self.events.emit(category, severity, title, detail, source)

    def clear(self, prefix) -> None:
        self._sent = {k: v for k, v in self._sent.items() if k[0] != prefix}


class DhcpGuard:
    def __init__(self, cfg, events, net, l2, oui):
        self.cfg, self.net, self.l2, self.oui = cfg, net, l2, oui
        self.alerts = _Alerts(events)
        self.events = events
        self.last_check: float | None = None
        self.servers: dict[str, dict] = {}  # server-ip -> senaste erbjudande
        self.rogue: set[str] = set()
        self.no_answer = False

    @property
    def allowed(self) -> set[str]:
        if self.cfg.dhcp_servers:
            return set(self.cfg.dhcp_servers)
        return {self.net.gateway.host} if self.net.gateway else set()

    async def run(self) -> None:
        if not self.l2.available:
            return
        await asyncio.sleep(20)  # let everything else start first
        while True:
            try:
                await self.check()
            except Exception:
                log.exception("Fel i DHCP-kontroll")
            await asyncio.sleep(self.cfg.dhcp_check_interval_s)

    async def check(self) -> None:
        if self.net.local_down:
            return
        offers = await asyncio.to_thread(self.l2.dhcp_probe)
        self.last_check = time.time()
        seen = set()
        for o in offers:
            self.handle(o, "aktiv kontroll")
            if o.get("server_id"):
                seen.add(o["server_id"])
        if not seen:
            if not self.no_answer:
                self.no_answer = True
                self.events.emit("disruption", "notice", "No DHCP server responded",
                                 "NetMaster got no DHCP offer. New devices may have trouble connecting.", "dhcp")
        elif self.no_answer:
            self.no_answer = False
            self.events.emit("disruption", "info", "DHCP server is responding again", ", ".join(sorted(seen)), "dhcp")
        # Servers that no longer answer are no longer "rogue"
        self.rogue &= seen | {s for s, o in self.servers.items() if time.time() - o["ts"] < 3600}

    def handle(self, offer: dict, source: str) -> None:
        sid = offer.get("server_id")
        if not sid or offer.get("type") not in ("offer", "ack"):
            return
        self.servers[sid] = {**offer, "ts": time.time()}
        if sid in self.allowed:
            return
        self.rogue.add(sid)
        mac = offer.get("src_mac") or "?"
        vendor = self.oui.lookup(mac) if mac != "?" else None
        detail = (f"{sid} (MAC {mac}{', ' + vendor if vendor else ''}) is handing out addresses. "
                  f"It offers gateway {offer.get('router') or '?'} and DNS {offer.get('dns') or '?'}. "
                  "A rogue DHCP server can redirect all traffic. Common cause: a router plugged in "
                  "without being in access point mode.")
        detail += f" Detected via {source}."
        self.alerts.alert(("dhcp", sid), "security", "critical", "Unknown DHCP server on the network", detail, sid)

    def status(self) -> dict:
        return {"enabled": self.l2.available, "last_check": self.last_check, "allowed": sorted(self.allowed),
                "servers": sorted(self.servers), "rogue": sorted(self.rogue),
                "ok": None if self.last_check is None and not self.rogue else not self.rogue}


class DnsGuard:
    def __init__(self, cfg, db, events, net):
        self.cfg, self.db, self.net = cfg, db, net
        self.alerts = _Alerts(events)
        self.events = events
        self.last_check: float | None = None
        self.problems: list[str] = []
        self.system_dns: list[str] | None = None
        self.nx_redirect = False

    async def run(self) -> None:
        await asyncio.sleep(15)
        while True:
            try:
                await self.check()
            except Exception:
                log.exception("Fel i DNS-kontroll")
            await asyncio.sleep(self.cfg.dns_check_interval_s)

    def _servers(self) -> list[str]:
        gw = self.net.gateway.host if self.net.gateway else None
        out = []
        for s in self.cfg.dns_servers:
            h = gw if s == "auto" else s
            if h and h not in out:
                out.append(h)
        return out

    async def check(self) -> None:
        if self.net.local_down:
            return
        problems = []
        gw = self.net.gateway.host if self.net.gateway else None

        # 1. Known names must give known answers
        for server in self._servers():
            for name, expected in FIXED_ANSWERS.items():
                got = await asyncio.to_thread(dns_answers, server, name)
                if got is None or not got:
                    continue  # no answer is handled by the DNS monitor
                if not got <= expected:
                    problems.append(f"{server}: {name} → {', '.join(sorted(got))}")
                    self.alerts.alert(("dns", server, name), "security", "critical", "DNS answers are tampered",
                                      f"{server} answers {', '.join(sorted(got))} for {name}, but the correct answer is "
                                      f"{', '.join(sorted(expected))}. Someone may be redirecting your traffic to fake sites. "
                                      "Check the router DNS settings and change the router admin password.", server)

        # 2. Made-up names must not exist (otherwise someone redirects mistyped addresses)
        if gw:
            got = await asyncio.to_thread(dns_answers, gw, f"nm-{secrets.token_hex(6)}.google.com")
            redirect = bool(got)
            if redirect and not self.nx_redirect:
                self.alerts.alert(("nx",), "security", "notice", "Router DNS redirects non-existent names",
                                  f"A made-up name resolved to {', '.join(sorted(got))}. Often an ISP feature, "
                                  "but it can also be tampering.", gw, every=86400)
            self.nx_redirect = redirect

        # 3. The computer's own DNS servers must not change silently (e.g. via rogue DHCP)
        current = await asyncio.to_thread(system_dns_servers)
        if current:
            learned = self.db.get_meta("system_dns")
            cur_s = ",".join(current)
            if learned is None:
                self.db.set_meta("system_dns", cur_s)
            elif learned != cur_s:
                self.db.set_meta("system_dns", cur_s)
                self.events.emit("security", "warning", "Server DNS servers have changed",
                                 f"From {learned} to {cur_s}. If you did not change this yourself, it may "
                                 "indicate a rogue DHCP server.", "dns")
            self.system_dns = current

        self.problems = problems
        self.last_check = time.time()

    def status(self) -> dict:
        return {"last_check": self.last_check, "problems": self.problems, "system_dns": self.system_dns,
                "nx_redirect": self.nx_redirect, "ok": None if self.last_check is None else not self.problems}


class PassiveSniffer:
    """Receives packets from the Npcap thread and passes them into the event loop."""

    def __init__(self, l2, inventory, dhcp: DhcpGuard):
        self.l2, self.inventory, self.dhcp = l2, inventory, dhcp
        self.loop: asyncio.AbstractEventLoop | None = None
        self.packets = 0

    def start(self) -> None:
        if not self.l2.available:
            return
        self.loop = asyncio.get_running_loop()
        try:
            self.l2.start_sniffer(self._on_packet)
            log.info("Passive ARP and DHCP sniffing started")
        except Exception as e:
            log.warning("Could not start sniffing: %s", e)

    def _on_packet(self, p) -> None:  # runs in the Npcap thread
        self.packets += 1
        try:
            from scapy.all import ARP, BOOTP
            from .l2 import norm_mac, parse_dhcp
            if p.haslayer(ARP) and p[ARP].op == 2:  # is-at (replies and gratuitous)
                row = (p[ARP].psrc, norm_mac(p[ARP].hwsrc))
                self.loop.call_soon_threadsafe(self.inventory.ingest, [row], "avlyssning")
            elif p.haslayer(BOOTP):
                offer = parse_dhcp(p)
                self.loop.call_soon_threadsafe(self.dhcp.handle, offer, "avlyssning")
        except Exception:
            log.debug("Could not parse packet", exc_info=True)
