"""Investigate a device on the network: collects everything that can be found out about what it is.

Runs on request (the Investigate button). Everything is passive reading: name lookups, mDNS, UPnP,
NetBIOS, open ports and what the services say about themselves.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import struct
import subprocess
import urllib.request

from .insights import PORTS

EXTRA_PORTS = {62078: "iPhone/iPad sync", 548: "AFP (Mac)", 7000: "AirPlay", 8008: "Chromecast",
               8009: "Chromecast", 1400: "Sonos", 5000: "UPnP/Synology", 631: "Printer (IPP)",
               32400: "Plex", 8123: "Home Assistant", 9000: "HTTP-alt", 8081: "HTTP-alt", 515: "Printer (LPD)",
               49152: "UPnP", 6668: "Tuya smart device", 6466: "Android TV remote", 8060: "Roku",
               9197: "Samsung TV", 8001: "Samsung TV", 3000: "HTTP-alt", 5555: "Android debug (ADB)", 10001: "Ubiquiti"}
ALL_PORTS = {**PORTS, **EXTRA_PORTS}
HTTP_PORTS = {80, 8000, 8080, 8081, 8096, 8123, 9000, 3000, 5000, 8008, 1400, 8060, 32400, 49152, 7000, 8001}
TLS_PORTS = {443, 8443, 8009}
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Hints in names/services -> what the device probably is.
HINTS = [(r"iphone|ipad|_apple-mobdev|62078", "Apple iPhone/iPad"), (r"macbook|imac|_afpovertcp|\bmac\b", "Apple Mac"),
         (r"_airplay|_raop|apple ?tv", "Apple TV / AirPlay device"), (r"_googlecast|chromecast|8008|8009", "Google Cast (Chromecast/Google TV/Nest)"),
         (r"android|galaxy|pixel|oneplus|xiaomi|redmi", "Android phone/tablet"), (r"_hap\b|homekit", "HomeKit smart-home device"),
         (r"sonos|_sonos", "Sonos speaker"), (r"_ipp|_printer|_pdl-datastream|printer|9100|laserjet|epson|brother|canon", "Printer"),
         (r"_spotify-connect", "Spotify Connect speaker"), (r"roku", "Roku"), (r"samsung.*tv|tizen", "Samsung TV"),
         (r"lg.*tv|webos", "LG TV"), (r"playstation|ps[45]", "PlayStation"), (r"xbox", "Xbox"), (r"nintendo|switch", "Nintendo Switch"),
         (r"tuya|6668|smart ?life", "Tuya smart device (plug/bulb)"), (r"shelly", "Shelly smart relay"), (r"esphome|esp32|esp8266|espressif", "ESP-based DIY/smart device"),
         (r"hikvision|dahua|camera|ipcam|rtsp|554", "IP camera"), (r"home ?assistant|8123", "Home Assistant"),
         (r"synology|diskstation|qnap|nas", "NAS"), (r"windows|desktop-[a-z0-9]+|3389|msrpc", "Windows PC"),
         (r"raspberry|raspberrypi", "Raspberry Pi"), (r"router|netgear|tp-?link|asus|ubiquiti|unifi|archer|deco", "Network equipment"),
         (r"echo|amazon|alexa|kindle|fire ?tv", "Amazon device"), (r"nest|google home", "Google Nest"),
         (r"\bwatch\b", "Smartwatch (often Apple Watch)"), (r"\bre[2-9]\d\d\b|extender|repeater", "Wi-Fi range extender"),
         (r"laptop|desktop-|notebook|thinkpad", "Laptop/PC")]


# ------------------------------------------------ helpers
async def _run(cmd: list[str], timeout: float = 6) -> str:
    def go():
        try:
            return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                                   creationflags=NOWIN).stdout
        except Exception:
            return ""
    return await asyncio.to_thread(go)


async def ping_ttl(ip: str) -> int | None:
    m = re.search(r"TTL=(\d+)", await _run(["ping", "-n", "2", "-w", "800", ip]), re.I)
    return int(m.group(1)) if m else None


def os_from_ttl(ttl: int | None) -> str | None:
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Android/Apple/embedded (TTL 64)"
    if ttl <= 128:
        return "Windows (TTL 128)"
    return "Network equipment/RTOS (TTL 255)"


async def rdns(ip: str) -> str | None:
    def go():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    return await asyncio.to_thread(go)


async def netbios(ip: str) -> dict:
    out = await _run(["nbtstat", "-A", ip], 8)
    names = re.findall(r"^\s*(\S[^\r\n<]*?)\s*<(\w\w)>\s+(UNIQUE|GROUP)", out, re.M)
    host = next((n for n, code, kind in names if code == "00" and kind == "UNIQUE"), None)
    group = next((n for n, code, kind in names if code == "00" and kind == "GROUP"), None)
    return {k: v for k, v in {"name": host, "workgroup": group}.items() if v}


# ---- mDNS (unicast query straight to the device on port 5353)
def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def _read_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    parts, jumped, end = [], False, off
    while depth < 20:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        parts.append(buf[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(parts), (end if jumped else off)


def _mdns_query(ip: str, names: list[tuple[str, int]]) -> list[tuple[str, int, str]]:
    """Returns (name, type, data) for all answers. Type 12=PTR, 16=TXT, 33=SRV, 1=A."""
    pkt = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    for n, t in names:
        pkt += _qname(n) + struct.pack(">HH", t, 0x8001)  # QU-bit: svara unicast
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    out = []
    try:
        s.sendto(pkt, (ip, 5353))
        while True:
            try:
                buf, _ = s.recvfrom(9000)
            except OSError:
                break
            _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
            off = 12
            for _ in range(qd):
                _, off = _read_name(buf, off)
                off += 4
            for _ in range(an + ns + ar):
                name, off = _read_name(buf, off)
                typ, _, _, ln = struct.unpack(">HHIH", buf[off:off + 10])
                off += 10
                rd = buf[off:off + ln]
                if typ == 12:
                    data = _read_name(buf, off)[0]
                elif typ == 33:
                    data = _read_name(buf, off + 6)[0]
                elif typ == 16:
                    items, i = [], 0
                    while i < len(rd):
                        items.append(rd[i + 1:i + 1 + rd[i]].decode("utf-8", "replace"))
                        i += 1 + rd[i]
                    data = " ".join(x for x in items if x)
                elif typ == 1 and ln == 4:
                    data = socket.inet_ntoa(rd)
                else:
                    data = ""
                out.append((name, typ, data))
                off += ln
    except Exception:
        pass
    finally:
        s.close()
    return out


async def mdns(ip: str) -> dict:
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    ans = await asyncio.to_thread(_mdns_query, ip, [(rev, 12), ("_services._dns-sd._udp.local", 12)])
    host = next((d for n, t, d in ans if t == 12 and n == rev), None)
    services = sorted({d.replace(".local", "") for n, t, d in ans if t == 12 and n.startswith("_services")})
    info = {}
    if services:
        # Ask for the instances; they often have the model name in TXT (md=, model=, fn=).
        ans2 = await asyncio.to_thread(_mdns_query, ip, [(s + ".local", 12) for s in services[:8]])
        inst = sorted({d for n, t, d in ans2 if t == 12})
        txt = [d for n, t, d in ans2 if t == 16 and d]
        info = {"instances": inst[:10], "txt": txt[:6]}
    return {k: v for k, v in {"hostname": host, "services": services, **info}.items() if v}


# ---- UPnP/SSDP
def _ssdp(ip: str) -> dict:
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
           "ST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    loc = server = None
    try:
        s.sendto(msg, (ip, 1900))
        while not loc:
            buf, _ = s.recvfrom(4096)
            text = buf.decode("utf-8", "replace")
            loc = loc or (re.search(r"^location:\s*(\S+)", text, re.I | re.M) or [None, None])[1]
            server = server or (re.search(r"^server:\s*(.+?)\r?$", text, re.I | re.M) or [None, None])[1]
    except Exception:
        pass
    finally:
        s.close()
    out = {"server": server} if server else {}
    if loc and loc.startswith(f"http://{ip}"):
        try:
            with urllib.request.urlopen(loc, timeout=3) as r:
                xml = r.read(200_000).decode("utf-8", "replace")
            for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "serialNumber"):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", xml)
                if m:
                    out[tag] = m.group(1).strip()
        except Exception:
            pass
    return out


# ---- ports and what the services say about themselves
async def _open(ip: str, port: int, sem) -> bool:
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 0.8)
            w.close()
            return True
        except Exception:
            return False


def _banner(ip: str, port: int) -> str | None:
    try:
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with socket.create_connection((ip, port), 2) as raw, ctx.wrap_socket(raw) as s:
                der = s.getpeercert(binary_form=True)
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)
            return f"certificate: {c.subject.rfc4514_string()} (issuer {c.issuer.rfc4514_string()})"[:200]
        if port in HTTP_PORTS:
            req = urllib.request.Request(f"http://{ip}:{port}/", headers={"User-Agent": "NetMaster"})
            try:
                r = urllib.request.urlopen(req, timeout=2.5)
                body, hdr = r.read(60_000).decode("utf-8", "replace"), r.headers
            except urllib.error.HTTPError as e:
                body, hdr = "", e.headers
            title = re.search(r"<title[^>]*>([^<]{1,120})", body, re.I)
            parts = [f"server: {hdr.get('Server')}" if hdr.get("Server") else None,
                     f"title: {title.group(1).strip()}" if title else None,
                     f"realm: {hdr.get('WWW-Authenticate')}" if hdr.get("WWW-Authenticate") else None]
            return " · ".join(p for p in parts if p) or None
        with socket.create_connection((ip, port), 2) as s:  # SSH, FTP, Telnet, SMTP and others greet on their own
            s.settimeout(2)
            data = s.recv(200).decode("utf-8", "replace").strip()
            return re.sub(r"[^\x20-\x7e]", "", data.splitlines()[0])[:150] if data else None
    except Exception:
        return None


async def ports(ip: str) -> list[dict]:
    sem = asyncio.Semaphore(40)
    found = [p for p, ok in zip(ALL_PORTS, await asyncio.gather(*(_open(ip, p, sem) for p in ALL_PORTS))) if ok]
    banners = await asyncio.gather(*(asyncio.to_thread(_banner, ip, p) for p in found))
    return [{"port": p, "name": ALL_PORTS[p], "banner": b} for p, b in zip(found, banners)]


def guess(text: str) -> list[str]:
    t = text.lower()
    return list(dict.fromkeys(label for pat, label in HINTS if re.search(pat, t)))[:4]


STEPS = [("ping", "Ping and OS hint"), ("dns", "DNS name"), ("netbios", "Windows name (NetBIOS)"),
         ("mdns", "mDNS services"), ("upnp", "UPnP description"), ("ports", f"Scanning {len(ALL_PORTS)} ports + service banners")]


def _summary(step: str, v) -> str:
    if step == "ping":
        return f"reply, TTL {v}" if v else "no reply"
    if step == "mdns":
        n = len(v.get("services", []))
        return f"{n} service{'s' if n != 1 else ''}" if v.get("services") else (v.get("hostname") or "nothing")
    if step == "upnp":
        return v.get("modelName") or v.get("friendlyName") or v.get("server") or "nothing"
    if step == "netbios":
        return v.get("name") or "nothing"
    if step == "ports":
        return f"{len(v)} open" if v else "none open"
    return v or "nothing"


async def investigate_stream(dev: dict, extra: dict):
    """Yields {"steps": [...]} first, then {"step", "summary"} as each part finishes, and last {"result"}."""
    ip = dev.get("ip")
    if not ip:
        yield {"result": {"error": "No IP address known for this device."}}
        return
    yield {"steps": [{"id": k, "label": l} for k, l in STEPS]}
    jobs = {"ping": ping_ttl(ip), "dns": rdns(ip), "netbios": netbios(ip), "mdns": mdns(ip),
            "upnp": asyncio.to_thread(_ssdp, ip), "ports": ports(ip)}
    tasks = {asyncio.ensure_future(c): k for k, c in jobs.items()}
    res: dict = {}
    for fut in asyncio.as_completed(list(tasks)):
        await fut
        for t, k in tasks.items():
            if t.done() and k not in res:
                res[k] = t.result()
                yield {"step": k, "summary": str(_summary(k, res[k]))}
    yield {"result": _report(dev, extra, ip, res["ping"], res["dns"], res["netbios"], res["mdns"], res["upnp"], res["ports"])}


async def investigate(dev: dict, extra: dict) -> dict:
    out = {}
    async for ev in investigate_stream(dev, extra):
        out = ev.get("result", out)
    return out


def _report(dev, extra, ip, ttl, rd, nb, md, up, pts) -> dict:
    facts: list[list[str]] = []

    def add(label, value):
        if value:
            facts.append([label, str(value)])
    add("Reachable", "yes" if ttl else "no reply to ping (may block it, or is asleep)")
    add("OS hint", os_from_ttl(ttl))
    add("Vendor (from MAC)", dev.get("vendor"))
    if dev.get("randomized"):
        add("MAC", "randomized (private Wi-Fi address): typical for phones, tablets and laptops")
    add("DHCP hostname", dev.get("hostname"))
    add("DNS name", rd)
    add("mDNS name", md.get("hostname"))
    add("Advertised services", ", ".join(md.get("services", [])))
    add("Service names", ", ".join(md.get("instances", [])))
    add("Service details", " | ".join(md.get("txt", [])))
    add("Windows name", " / ".join(v for v in (nb.get("name"), nb.get("workgroup")) if v))
    add("UPnP device", " · ".join(v for v in (up.get("friendlyName"), up.get("manufacturer"),
                                               up.get("modelName"), up.get("modelNumber")) if v))
    add("UPnP description", up.get("modelDescription"))
    add("UPnP server", up.get("server"))
    for k, v in extra.items():
        add(k, v)
    skip = {"Reachable", "OS hint", "MAC"}
    text = " ".join(b for a, b in facts if a not in skip) + " " + " ".join(f"{p['port']} {p['name']} {p['banner'] or ''}" for p in pts)
    return {"ip": ip, "guess": guess(text), "facts": facts, "ports": pts}
