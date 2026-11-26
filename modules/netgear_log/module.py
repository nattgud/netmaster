"""NETGEAR router log, read from its web page (FW_log.htm)."""
from __future__ import annotations

import base64
import http.cookiejar
import re
import time
import urllib.error
import urllib.request
from datetime import datetime

from netmaster.sdk import Busy, ModuleBase

LINE = re.compile(r"^\[(?P<msg>.+?)\](?P<rest>.*?)\s+\w+day, (?P<date>\w+ \d+,\d{4} \d\d:\d\d:\d\d)\s*$")


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.host = (settings.get("host") or "").strip()
        self.resyncs: list[float] = []  # times the router restarted its network (NTP sync)

    def _fetch(self) -> str:
        user, pw = self.settings.get("username") or "admin", self.settings.get("password") or ""
        auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def get(path: str) -> tuple[int, str]:
            req = urllib.request.Request(f"http://{self.host}/{path}",
                                         headers={"Authorization": auth, "User-Agent": "NetMaster"})
            try:
                with opener.open(req, timeout=15) as r:
                    return r.status, r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                return e.code, ""
        mine = False  # only log out if we got in ourselves, otherwise we could log out whoever is logged in
        try:
            for _ in range(3):  # the first request gives 401 + a session cookie
                status, body = get("FW_log.htm")
                if status == 200:
                    break
            if status != 200:
                raise RuntimeError(f"Login failed (HTTP {status}): check the password")
            m = re.search(r"<textarea[^>]*>(.*?)</textarea>", body, re.S | re.I)
            if not m:
                raise Busy("Paused: someone is logged in to the router's web page")
            mine = True
            return m.group(1)
        finally:
            if mine:
                get("LGO_logout.htm")

    def _parse(self, text: str) -> list[tuple[float, str]]:
        me = self.ctx.local_ip or ""
        rows = []
        for line in text.splitlines():
            m = LINE.match(line.strip())
            if not m:
                continue
            if m["msg"] == "remote login" and me and me in m["rest"]:
                continue  # NetMaster's own logins
            try:
                ts = datetime.strptime(m["date"], "%B %d,%Y %H:%M:%S").timestamp()
            except ValueError:
                continue
            rows.append((ts, f"[{m['msg']}]{m['rest']}".strip()))
        return sorted(rows)

    def _handle(self, rows: list[tuple[float, str]]) -> None:
        db = self.ctx.db
        last = float(db.get_meta("netgear_last_ts") or 0)
        first = last == 0
        name = self.ctx.router_name(self.host)
        for ts, msg in rows:
            if ts <= last:
                continue
            self.ctx.add_log(msg, self.host, alarm=not first, ts=ts)
            if first:
                continue
            if msg.startswith("[Initialized"):
                self.ctx.emit("disruption", "warning", f"{name} restarted",
                              f"The router rebooted at {time.strftime('%H:%M', time.localtime(ts))}.", self.host)
            elif msg.startswith("[Time synchronized") and not any(abs(ts - t) < 120 for t in self.resyncs):
                self.resyncs.append(ts)
        if rows:
            db.set_meta("netgear_last_ts", str(max(last, rows[-1][0])))
        if first:
            self.resyncs = [ts for ts, msg in rows if msg.startswith("[Time synchronized")]
        self.resyncs = [t for t in self.resyncs if time.time() - t < 7 * 86400][-200:]

    async def run(self) -> None:
        while True:
            if not self.host or not self.settings.get("password"):
                self.last_error = "Set the IP address and password in the module settings"
            else:
                try:
                    self._handle(self._parse(await self.ctx.to_thread(self._fetch)))
                    self.ok()
                except Busy as e:
                    self.last_error = str(e)
                except Exception as e:
                    self.error(e)
            await self.ctx.sleep(max(60.0, float(self.settings.get("interval_s") or 300)))

    def status(self) -> dict:
        return {"host": self.host, "name": self.ctx.router_name(self.host),
                "resyncs_24h": sum(1 for t in self.resyncs if time.time() - t < 86400)}
