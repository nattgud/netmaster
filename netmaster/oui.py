"""Vendor lookup from MAC address (Wireshark's manuf file, downloaded and cached in data/)."""
from __future__ import annotations

import logging
import time
import urllib.request
from pathlib import Path

log = logging.getLogger("netmaster.oui")
URL = "https://www.wireshark.org/download/automated/data/manuf"
MAX_AGE_S = 30 * 86400


def is_randomized(mac: str) -> bool:
    """Lokalt administrerad MAC = slumpad 'privat wifi-adress' (iOS/Android/Windows)."""
    return bool(int(mac[:2], 16) & 0x02)


class OuiDb:
    def __init__(self, path: Path):
        self.path = path
        self._by_bits: dict[int, dict[int, str]] = {}

    def ensure(self) -> None:
        """Downloads the file if it is missing or old. Runs in a thread; errors are ignored."""
        fresh = self.path.exists() and time.time() - self.path.stat().st_mtime < MAX_AGE_S
        if not fresh:
            try:
                req = urllib.request.Request(URL, headers={"User-Agent": "NetMaster"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = r.read()
                if len(data) > 100_000:
                    tmp = self.path.with_suffix(".tmp")
                    tmp.write_bytes(data)
                    tmp.replace(self.path)
                    log.info("Vendor list downloaded (%d kB)", len(data) // 1024)
            except Exception as e:
                log.warning("Could not download vendor list: %s", e)
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        by_bits: dict[int, dict[int, str]] = {}
        for line in self.path.read_text("utf-8", errors="replace").splitlines():
            if not line or line[0] == "#":
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            prefix = parts[0].strip()
            name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
            hexpart, _, bits = prefix.partition("/")
            bits_n = int(bits) if bits else 24
            h = hexpart.replace(":", "").replace("-", "").lower()
            try:
                val = int(h.ljust(12, "0")[:12], 16) >> (48 - bits_n)
            except ValueError:
                continue
            by_bits.setdefault(bits_n, {})[val] = name
        self._by_bits = dict(sorted(by_bits.items(), reverse=True))  # longest prefix first
        log.info("Vendor list: %d entries", sum(len(v) for v in by_bits.values()))

    def lookup(self, mac: str) -> str | None:
        if is_randomized(mac):
            return None
        v = int(mac.replace(":", ""), 16)
        for bits, table in self._by_bits.items():
            name = table.get(v >> (48 - bits))
            if name:
                return name
        return None
