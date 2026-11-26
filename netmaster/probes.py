"""Low-level measurements: ping, DNS lookups and gateway discovery. All are blocking and run in threads."""
from __future__ import annotations

import os
import re
import socket
import subprocess
import time

import dns.exception
import dns.resolver
import dns.reversename

IS_WIN = os.name == "nt"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WIN else 0

_TTL = re.compile(r"ttl[=:]", re.I)
_LAT = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def ping_once(host: str, timeout_ms: int = 1000) -> float | None:
    """Returns the response time in ms, or None if there is no answer.

    Uses the system ping (needs no admin rights). Success is decided by "TTL=",
    because Windows ping exits with 0 even for "Destination host unreachable".
    """
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), host]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout_ms / 1000 + 2, creationflags=NO_WINDOW,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return None
    if not _TTL.search(out):
        return None
    m = _LAT.search(out)
    return float(m.group(1).replace(",", ".")) if m else 0.5


def dns_query(server: str, name: str, timeout_s: float = 3.0) -> float | None:
    """Asks a specific DNS server directly (bypassing the OS cache). Returns the response time in ms."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.lifetime = timeout_s
    r.cache = None
    t0 = time.perf_counter()
    try:
        r.resolve(name, "A")
    except (dns.exception.DNSException, OSError):
        return None
    return (time.perf_counter() - t0) * 1000


# Windows: "192.168.0.1   ac-15-a2-51-6b-b8   dynamic"   Linux: "192.168.0.1 dev eth0 lladdr ac:15:... REACHABLE"
_ARP_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s.*?\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b", re.I)


def read_arp_table(local_ip: str | None = None) -> list[tuple[str, str]]:
    """Reads the OS ARP table. Returns (ip, mac) with mac in the form aa:bb:cc:dd:ee:ff."""
    try:
        if IS_WIN:
            cmd = ["arp", "-a"] + (["-N", local_ip] if local_ip else [])
        else:
            cmd = ["ip", "neigh", "show"]
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5,
                             creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows = []
    for line in out.splitlines():
        m = _ARP_LINE.search(line)
        if m:
            rows.append((m.group(1), m.group(2).lower().replace("-", ":")))
    return rows


def udp_sweep(hosts: list[str]) -> None:
    """Makes the OS ARP-query every address by sending an empty UDP packet (port 9, discard)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for ip in hosts:
            try:
                s.sendto(b"", (ip, 9))
            except OSError:
                pass
    finally:
        s.close()


def local_ip_for(target: str) -> str | None:
    """The local IP address the OS would use to reach target (nothing is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def ptr_lookup(ip: str, server: str) -> str | None:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.lifetime = 2
    try:
        ans = r.resolve(dns.reversename.from_address(ip), "PTR")
        name = str(ans[0]).rstrip(".")
        return name or None
    except (dns.exception.DNSException, OSError):
        return None


def dns_answers(server: str, name: str, timeout_s: float = 3.0) -> set[str] | None:
    """A records for name according to server. Empty set = does not exist (NXDOMAIN). None = no answer."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.lifetime = timeout_s
    try:
        return {str(a) for a in r.resolve(name, "A")}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return set()
    except (dns.exception.DNSException, OSError):
        return None


def system_dns_servers() -> list[str] | None:
    """DNS servers the OS uses on the adapter with the default route."""
    try:
        if IS_WIN:
            ps = ("$i=(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric,InterfaceMetric | "
                  "Select-Object -First 1).InterfaceIndex; "
                  "(Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ','")
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                 capture_output=True, text=True, errors="replace", timeout=20,
                                 creationflags=NO_WINDOW).stdout.strip()
            return [s for s in out.split(",") if _IPV4.match(s.strip())] or None
        servers = []
        with open("/etc/resolv.conf") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    servers.append(p[1])
        return servers or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def detect_gateway() -> str | None:
    try:
        if IS_WIN:
            out = subprocess.run(
                ["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True,
                errors="replace", timeout=5, creationflags=NO_WINDOW,
            ).stdout
            best: tuple[int, str] | None = None
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0" and _IPV4.match(p[2]):
                    metric = int(p[4]) if p[4].isdigit() else 9999
                    if best is None or metric < best[0]:
                        best = (metric, p[2])
            return best[1] if best else None
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"default via (\S+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None
