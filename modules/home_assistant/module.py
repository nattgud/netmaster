"""Home Assistant: up/down alerts, version and pending updates."""
from __future__ import annotations

import json
import urllib.parse

from netmaster.sdk import ModuleBase, ServiceWatch, http_get


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.url = (settings.get("url") or "").strip().rstrip("/")
        self.watch = ServiceWatch(ctx, "Home Assistant", self.url)
        self.version: str | None = None
        self.updates: list[str] = []

    def _headers(self) -> dict:
        t = self.settings.get("token")
        return {"Authorization": f"Bearer {t}"} if t else {}

    def _probe(self):
        # Without a token /api/ answers 401, which still proves Home Assistant is up.
        return http_get(f"{self.url}/api/", self._headers(), verify_tls=False)

    def _details(self) -> None:
        st, body = http_get(f"{self.url}/api/config", self._headers(), verify_tls=False)
        if st == 401:
            raise RuntimeError("The access token was refused")
        if st == 200:
            self.version = json.loads(body).get("version")
        st, body = http_get(f"{self.url}/api/states", self._headers(), timeout=20, verify_tls=False)
        if st == 200:
            self.updates = [s.get("attributes", {}).get("friendly_name") or s["entity_id"]
                            for s in json.loads(body) if s.get("entity_id", "").startswith("update.") and s.get("state") == "on"]

    async def run(self) -> None:
        n = 0
        while True:
            if not self.url:
                self.last_error = "Set the Home Assistant address in the module settings"
            elif await self.watch.check(self._probe):
                try:
                    if self.settings.get("token") and n % 20 == 0:  # details every ~10 minutes
                        before = set(self.updates)
                        await self.ctx.to_thread(self._details)
                        if new := [u for u in self.updates if u not in before] if before or n else []:
                            self.ctx.emit("system", "info", f"Home Assistant: {len(new)} new update(s) available",
                                          ", ".join(new)[:300], self.url)
                    self.ok()
                except Exception as e:
                    self.error(e)
                n += 1
            else:
                self.last_error = self.watch.error
            await self.ctx.sleep(max(10.0, float(self.settings.get("interval_s") or 30)))

    @property
    def host(self) -> str | None:
        return urllib.parse.urlparse(self.url).hostname

    def protect(self) -> dict[str, str]:
        return {self.host: "Home Assistant"} if self.host and self.settings.get("protect", True) else {}

    def status(self) -> dict:
        return {"host": self.host, "name": "Home Assistant", "version": self.version, "updates": self.updates,
                "service": self.watch.status()}
