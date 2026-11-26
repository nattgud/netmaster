"""Where an IP address is and who owns it (ip-api.com, cached in the database), plus traceroute."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import subprocess
import time
import urllib.request

log = logging.getLogger("netmaster.geo")

FIELDS = "status,country,countryCode,city,lat,lon,isp,org,as,query"
TTL_S = 30 * 86400


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class Geo:
    def __init__(self, db):
        self.db = db
        db.execute("CREATE TABLE IF NOT EXISTS geo(ip TEXT PRIMARY KEY, data TEXT, ts REAL)", [()])
        self.cache: dict[str, dict | None] = {}
        for r in db.query("SELECT ip, data FROM geo WHERE ts >= ?", (time.time() - TTL_S,)):
            self.cache[r["ip"]] = json.loads(r["data"])
        self._backoff = 0.0

    def get(self, ip: str) -> dict | None:
        return self.cache.get(ip)

    def _fetch(self, ips: list[str]) -> list[dict]:
        req = urllib.request.Request(f"http://ip-api.com/batch?fields={FIELDS}", data=json.dumps(ips).encode(),
                                     headers={"Content-Type": "application/json", "User-Agent": "NetMaster"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)

    async def lookup(self, ips) -> None:
        """Looks up the addresses missing from the cache (max 100 per call; the free limit is 15 calls/min)."""
        todo = [ip for ip in dict.fromkeys(ips) if ip not in self.cache and is_public(ip)][:100]
        if not todo or time.time() < self._backoff:
            return
        try:
            rows = await asyncio.to_thread(self._fetch, todo)
        except Exception as e:
            log.warning("Geo lookup failed: %s", e)
            self._backoff = time.time() + 120
            return
        now, save = time.time(), []
        for r in rows:
            ip = r.get("query")
            if not ip:
                continue
            g = None if r.get("status") != "success" else {
                "cc": r.get("countryCode"), "country": r.get("country"), "city": r.get("city"),
                "lat": r.get("lat"), "lon": r.get("lon"), "org": r.get("org") or r.get("isp"), "as": r.get("as")}
            self.cache[ip] = g
            save.append((ip, json.dumps(g), now))
        self.db.execute("INSERT OR REPLACE INTO geo(ip, data, ts) VALUES (?,?,?)", save)

    # ------------------------------------------------ traceroute
    @staticmethod
    def _tracert(ip: str) -> list[dict]:
        out = subprocess.run(["tracert", "-d", "-h", "20", "-w", "600", ip], capture_output=True, timeout=90,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.decode("cp850", "replace")
        hops = []
        for line in out.splitlines():
            m = re.match(r"^\s*(\d+)\s+(.*?)(\d{1,3}(?:\.\d{1,3}){3})\s*$", line)
            if not m:
                continue
            ms = [int(x) for x in re.findall(r"<?(\d+) ms", m.group(2))]
            hops.append({"n": int(m.group(1)), "ip": m.group(3), "ms": min(ms) if ms else None})
        return hops

    async def trace(self, ip: str) -> list[dict]:
        ipaddress.ip_address(ip)  # only valid addresses reach tracert
        hops = await asyncio.to_thread(self._tracert, ip)
        await self.lookup(h["ip"] for h in hops)
        return [{**h, "geo": self.get(h["ip"])} for h in hops]
