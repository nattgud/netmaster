"""Which programs on the server itself use the internet, and where they connect.

Npcap counts bytes per (protocol, local port, remote address). psutil maps local ports to processes.
Packets are parsed as raw bytes instead of with scapy, so it copes with heavy traffic (e.g. a media server).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import time
from collections import defaultdict, deque

log = logging.getLogger("netmaster.hostflows")

_PRIVATE = "net 10.0.0.0/8 or net 172.16.0.0/12 or net 192.168.0.0/16 or net 169.254.0.0/16"
# Internet traffic only: at least one side outside the private networks, and no multicast.
BPF = (f"ip and not (({_PRIVATE.replace('net', 'src net')}) and ({_PRIVATE.replace('net', 'dst net')})) "
       "and not dst net 224.0.0.0/4")
# Traffic that cannot be tied to a process gets a name from its protocol/port when possible.
KNOWN_PORTS = {53: "DNS lookups", 123: "Time sync (NTP)", 5353: "mDNS", 1900: "UPnP/SSDP",
               3478: "STUN (calls/VPN)", 41641: "tailscaled.exe", 67: "DHCP", 137: "NetBIOS"}
UNKNOWN = "Unidentified"
SUSPICIOUS_DIRS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\")


class HostFlows:
    WINDOW_S = 10
    BASELINE_S = 3600  # the first hour it learns which programs normally use the network

    def __init__(self, db, events, l2, geo=None, home_ip=lambda: None):
        self.db, self.events, self.l2, self.geo, self.home_ip = db, events, l2, geo, home_ip
        self.local_ip: str | None = None
        self.error: str | None = None
        self._lock = threading.Lock()
        self._cur: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])  # (proto, lport, rip, rport) -> [ner, upp]
        self._ports: dict[tuple[int, int], tuple[int, float]] = {}       # (proto, lport) -> (pid, senast sedd)
        self._pinfo: dict[int, dict] = {}
        self._minutes: deque = deque(maxlen=60)                          # (minut, {proc: {rip: [ner, upp]}})
        self.now: dict[str, list[float]] = {}
        self._rdns: dict[str, str | None] = {}
        known = db.get_meta("host_programs")
        self.known: set[str] = set(json.loads(known)) if known else set()
        self._learn_until = 0 if known else time.time() + self.BASELINE_S

    # ------------------------------------------------ collection (Npcap thread)
    def start(self) -> None:
        if not self.l2.available:
            self.error = "Npcap missing"
            return
        try:
            import psutil  # noqa: F401
            from scapy.all import conf
            self.local_ip = conf.route.route("1.1.1.1")[1]
            sock = conf.L2listen(iface=self.l2.iface, filter=BPF)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
            return
        threading.Thread(target=self._capture, args=(sock,), daemon=True, name="hostflows").start()
        threading.Thread(target=self._port_loop, daemon=True, name="hostflows-ports").start()
        log.info("Per-program traffic capture started (%s)", self.local_ip)

    def _capture(self, sock) -> None:
        while True:
            try:
                data = sock.recv_raw(65535)[1]
                if data:
                    self._parse(data)
            except Exception:
                time.sleep(0.01)

    def _parse(self, d: bytes) -> None:
        off, et = 14, d[12:14]
        if et == b"\x81\x00":  # VLAN-tagg
            off, et = 18, d[16:18]
        if et != b"\x08\x00" or len(d) < off + 20:
            return
        ip = d[off:]
        ihl, size, proto = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big"), ip[9]
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        sp = dp = 0
        if proto in (6, 17) and len(ip) >= ihl + 4:
            sp, dp = int.from_bytes(ip[ihl:ihl + 2], "big"), int.from_bytes(ip[ihl + 2:ihl + 4], "big")
        if src == self.local_ip:
            key, i = (proto, sp, dst, dp), 1
        elif dst == self.local_ip:
            key, i = (proto, dp, src, sp), 0
        else:
            return
        with self._lock:
            self._cur[key][i] += size

    # ------------------------------------------------ summary (event loop)
    def _port_loop(self) -> None:
        import psutil
        while True:
            try:
                now = time.time()
                ports = {k: v for k, v in self._ports.items() if now - v[1] < 300}
                for c in psutil.net_connections("inet4"):
                    if c.pid and c.laddr:
                        ports[(6 if c.type == socket.SOCK_STREAM else 17, c.laddr.port)] = (c.pid, now)
                self._ports = ports
            except Exception as e:
                self.error = f"psutil: {e}"
            time.sleep(1)

    def _owner(self, proto: int, lport: int, rport: int) -> dict:
        owner = self._ports.get((proto, lport))
        if owner:
            return self._proc(owner[0])
        if proto == 1:
            return {"name": "Ping (ICMP)", "exe": ""}
        label = KNOWN_PORTS.get(rport) or KNOWN_PORTS.get(lport)
        return {"name": label or UNKNOWN, "exe": ""}

    def _proc(self, pid: int) -> dict:
        if pid not in self._pinfo:
            import psutil
            try:
                p = psutil.Process(pid)
                name = p.name()
                try:
                    exe = p.exe()
                except Exception:
                    exe = ""
            except Exception:
                name, exe = f"pid {pid}", ""
            if pid == os.getpid():
                name = "NetMaster (speed test, checks)"
            self._pinfo[pid] = {"name": name, "exe": exe}
        return self._pinfo[pid]

    def _flush(self) -> None:
        with self._lock:
            cur, self._cur = self._cur, defaultdict(lambda: [0, 0])
        minute = time.time() // 60 * 60
        if not self._minutes or self._minutes[-1][0] != minute:
            self._minutes.append((minute, defaultdict(lambda: defaultdict(lambda: [0, 0]))))
        bucket = self._minutes[-1][1]
        now: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        for (proto, lport, rip, rport), (down, up) in cur.items():
            info = self._owner(proto, lport, rport)
            name = info["name"]
            now[name][0] += down / self.WINDOW_S
            now[name][1] += up / self.WINDOW_S
            proto_s = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
            b = bucket[name][(rip, f"{proto_s} {rport}" if rport else proto_s)]
            b[0] += down
            b[1] += up
            if info["exe"]:
                self._check_new(info, rip, down + up)
        self.now = dict(now)
        if len(self._pinfo) > 2000:
            self._pinfo.clear()

    def _check_new(self, info: dict, rip: str, size: int) -> None:
        key = (info["exe"] or info["name"]).lower()
        if key in self.known:
            return
        self.known.add(key)
        self.db.set_meta("host_programs", json.dumps(sorted(self.known)))
        if time.time() < self._learn_until:
            return
        asyncio.get_running_loop().create_task(self._report_new(info, rip, key))

    @staticmethod
    def _signer(exe: str) -> tuple[str, str]:
        """(status, publisher) of the file's Authenticode signature."""
        import subprocess
        ps = ("$s = Get-AuthenticodeSignature -LiteralPath $env:NM_FILE; "
              "\"$($s.Status)|$($s.SignerCertificate.GetNameInfo('SimpleName', $false))\"")
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                 env={**os.environ, "NM_FILE": exe}, capture_output=True, text=True,
                                 timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip()
            status, _, signer = out.partition("|")
            return status or "Unknown", signer
        except Exception:
            return "Unknown", ""

    async def _report_new(self, info: dict, rip: str, key: str) -> None:
        status, signer = await asyncio.to_thread(self._signer, info["exe"])
        signed = status == "Valid"
        odd = any(s in key for s in SUSPICIOUS_DIRS)
        sig = f"Signed by {signer}." if signed else f"Not validly signed ({status})."
        # Warn only when it is unsigned, or signed but running from a typical malware folder without being Microsoft.
        warn = not signed or (odd and "microsoft" not in signer.lower())
        self.events.emit("security", "warning" if warn else "info",
                         f"New program on the server is using the internet: {info['name']}",
                         f"{info['exe']}\nTalking to {rip}. {sig}"
                         + ("\nRuns from a user/temp folder, which is typical for malware." if odd and warn else ""),
                         "netmaster", kind="new_server_program")

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self.WINDOW_S)
            if self.local_ip:
                try:
                    self._flush()
                    await self._resolve()
                except Exception:
                    log.exception("hostflows")

    # ------------------------------------------------ names of remote addresses
    def _hour(self) -> dict[str, dict[str, list[int]]]:
        tot: dict = defaultdict(lambda: defaultdict(lambda: [0, 0]))
        for _, b in self._minutes:
            for name, remotes in b.items():
                for rip, (d, u) in remotes.items():
                    tot[name][rip][0] += d
                    tot[name][rip][1] += u
        return tot

    async def _resolve(self) -> None:
        todo = list(dict.fromkeys(r[0] for remotes in self._hour().values()
                                  for r, _ in sorted(remotes.items(), key=lambda x: -sum(x[1]))[:5] if r[0] not in self._rdns))[:10]

        def look(ip):
            try:
                return socket.gethostbyaddr(ip)[0]
            except Exception:
                return None
        for ip in todo:
            self._rdns[ip] = await asyncio.to_thread(look, ip)
        if self.geo:
            await self.geo.lookup([self.home_ip() or ""] + [r[0] for remotes in self._hour().values()
                                                            for r, _ in sorted(remotes.items(), key=lambda x: -sum(x[1]))[:6]])
        if len(self._rdns) > 5000:
            self._rdns.clear()

    def status(self) -> dict:
        hour = self._hour()
        exe = {i["name"]: i["exe"] for i in self._pinfo.values()}
        procs = []
        for name, remotes in hour.items():
            down = sum(v[0] for v in remotes.values())
            up = sum(v[1] for v in remotes.values())
            top = sorted(remotes.items(), key=lambda x: -sum(x[1]))[:6]
            procs.append({"name": name, "exe": exe.get(name, ""), "down": down, "up": up,
                          "now": self.now.get(name, [0, 0]),
                          "remotes": [{"ip": ip, "port": port, "host": self._rdns.get(ip), "down": d, "up": u,
                                       "geo": self.geo.get(ip) if self.geo else None}
                                      for (ip, port), (d, u) in top]})
        procs.sort(key=lambda p: -(p["now"][0] + p["now"][1] + (p["down"] + p["up"]) / 3600))
        return {"enabled": bool(self.local_ip), "error": self.error, "ip": self.local_ip,
                "learning": time.time() < self._learn_until, "procs": procs[:10],
                "home": self.geo.get(self.home_ip() or "") if self.geo else None}
