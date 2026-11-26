"""Jellyfin: up/down alerts and active streams."""
from __future__ import annotations

import json
import urllib.parse

from netmaster.sdk import ModuleBase, ServiceWatch, http_get


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.url = (settings.get("url") or "").strip().rstrip("/")
        self.watch = ServiceWatch(ctx, "Jellyfin", self.url)
        self.streams: list[dict] = []

    def _probe(self):
        st, body = http_get(f"{self.url}/health")
        if st != 200:
            raise RuntimeError(f"HTTP {st}")
        return st, body

    def _sessions(self) -> None:
        st, body = http_get(f"{self.url}/Sessions?activeWithinSeconds=120", {"X-Emby-Token": self.settings["api_key"]})
        if st == 401:
            raise RuntimeError("The API key was refused")
        if st == 200:
            self.streams = [{"user": s.get("UserName"), "device": s.get("DeviceName"), "client": s.get("RemoteEndPoint"),
                             "title": (s.get("NowPlayingItem") or {}).get("Name"),
                             "transcoding": bool(s.get("TranscodingInfo"))}
                            for s in json.loads(body) if s.get("NowPlayingItem")]

    async def run(self) -> None:
        while True:
            if not self.url:
                self.last_error = "Set the Jellyfin address in the module settings"
            elif await self.watch.check(self._probe):
                try:
                    if self.settings.get("api_key"):
                        await self.ctx.to_thread(self._sessions)
                    self.ok()
                except Exception as e:
                    self.error(e)
            else:
                self.last_error = self.watch.error
            await self.ctx.sleep(max(10.0, float(self.settings.get("interval_s") or 30)))

    def status(self) -> dict:
        return {"host": urllib.parse.urlparse(self.url).hostname, "name": "Jellyfin", "streams": self.streams,
                "service": self.watch.status()}
