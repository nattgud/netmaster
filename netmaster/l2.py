"""Layer 2 access via scapy + Npcap: ARP scans, passive listening and DHCP probes.

All of this is optional. Without Npcap the app falls back to the Windows ARP table.
"""
from __future__ import annotations

import logging
import random
import threading
import time

log = logging.getLogger("netmaster.l2")


def norm_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


class L2:
    def __init__(self) -> None:
        self.available = False
        self.reason: str | None = None
        self.iface = None
        self.iface_name: str | None = None
        self.mac: str | None = None
        self._sniffer = None
        self._lock = threading.Lock()  # scapy is not thread safe for concurrent srp

    def init(self, gateway: str | None) -> None:
        """Blocking. Checks that Npcap exists and that we may open the network adapter."""
        try:
            from scapy.all import conf, get_if_hwaddr
        except Exception as e:  # pragma: no cover
            self.reason = f"scapy could not be loaded: {e}"
            return
        if not conf.use_pcap and conf.L2listen is None:
            self.reason = "Npcap missing"
            return
        try:
            self.iface = conf.route.route(gateway or "1.1.1.1")[0]
            sock = conf.L2listen(iface=self.iface, filter="arp")
            sock.close()
            self.mac = norm_mac(get_if_hwaddr(self.iface))
            dev = conf.ifaces.dev_from_networkname(self.iface) if hasattr(conf.ifaces, "dev_from_networkname") else None
            self.iface_name = getattr(dev, "description", None) or getattr(dev, "name", None) or str(self.iface)
            self.available = True
            log.info("Npcap active on %s (%s)", self.iface_name, self.mac)
        except Exception as e:
            self.reason = f"Npcap could not open the network adapter: {e}"
            log.warning(self.reason)

    # --- active probes (blocking, run in threads) ---
    def arping(self, cidr: str, timeout: float = 3.0) -> list[tuple[str, str]]:
        from scapy.all import ARP, Ether, srp
        with self._lock:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=timeout,
                         iface=self.iface, verbose=0)
        return [(r.psrc, norm_mac(r.hwsrc)) for _, r in ans]

    def dhcp_probe(self, timeout: float = 5.0) -> list[dict]:
        """Sends a DHCPDISCOVER with a made-up client MAC and collects all offers.

        No DHCPREQUEST is sent, so no address is leased.
        """
        from scapy.all import BOOTP, DHCP, IP, UDP, AsyncSniffer, Ether, sendp
        fake = bytes([0x02] + [random.randint(0, 255) for _ in range(5)])
        xid = random.randint(1, 0xFFFFFFFF)
        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac)
               / IP(src="0.0.0.0", dst="255.255.255.255")
               / UDP(sport=68, dport=67)
               / BOOTP(chaddr=fake + b"\0" * 10, xid=xid, flags=0x8000)
               / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6]), "end"]))
        with self._lock:
            sn = AsyncSniffer(iface=self.iface, filter="udp and src port 67", store=True,
                              lfilter=lambda p: p.haslayer(BOOTP) and p[BOOTP].xid == xid)
            sn.start()
            time.sleep(0.3)
            sendp(pkt, iface=self.iface, verbose=0)
            time.sleep(timeout)
            pkts = sn.stop() or []
        return [parse_dhcp(p) for p in pkts]

    # --- passiv avlyssning ---
    def start_sniffer(self, on_packet) -> None:
        from scapy.all import AsyncSniffer
        self._sniffer = AsyncSniffer(iface=self.iface, filter="arp or (udp and src port 67)",
                                     store=False, prn=on_packet)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass


def parse_dhcp(p) -> dict:
    from scapy.all import BOOTP, DHCP, IP, Ether
    opts = {}
    for o in p[DHCP].options if p.haslayer(DHCP) else []:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1]
    types = {1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak"}
    return {
        "server_id": opts.get("server_id") or (p[IP].src if p.haslayer(IP) else None),
        "src_ip": p[IP].src if p.haslayer(IP) else None,
        "src_mac": norm_mac(p[Ether].src) if p.haslayer(Ether) else None,
        "type": types.get(opts.get("message-type"), str(opts.get("message-type"))),
        "offered": p[BOOTP].yiaddr,
        "router": opts.get("router"),
        "dns": opts.get("name_server"),
    }
