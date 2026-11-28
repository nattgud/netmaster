"""Webhook: sends every NetMaster alert to another system as an HTTP POST.

Works with anything that takes a webhook: ServiceNow, PagerDuty, Opsgenie, Jira, n8n, Power Automate,
Zapier, Home Assistant, Microsoft Teams (Workflows), Slack and Discord.

The "NetMaster JSON" body:
    {"type": "netmaster.event", "id": 123, "time": "2026-11-28T10:15:00+01:00", "ts": 1795800000.0,
     "category": "security", "severity": "warning", "title": "...", "detail": "...",
     "kind": "new_device", "source": "...", "netmaster": "192.168.0.34"}
With a secret, the header X-NetMaster-Signature is "sha256=" + HMAC-SHA256(secret, body) in hex.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from netmaster.sdk import ModuleBase, http_request

SEVERITIES = ["info", "notice", "warning", "critical"]
COLORS = {"info": "#3b82f6", "notice": "#3b82f6", "warning": "#f59e0b", "critical": "#ef4444"}
ICONS = {"info": "ℹ️", "notice": "ℹ️", "warning": "⚠️", "critical": "🚨"}
RETRY_S = (5, 30, 120)   # wait before each new try when the receiver fails


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.sent = self.failed = 0
        self.last_sent: float | None = None
        self.queue_len = 0

    # ---------- settings ----------
    @property
    def url(self) -> str:
        return str(self.settings.get("url") or "").strip()

    def wanted(self, ev: dict) -> bool:
        sev = ev.get("severity", "info")
        lowest = str(self.settings.get("min_severity") or "warning")
        if SEVERITIES.index(sev if sev in SEVERITIES else "info") < SEVERITIES.index(lowest if lowest in SEVERITIES else "warning"):
            return False
        return bool(self.settings.get(f"send_{ev.get('category', 'system')}", True))

    # ---------- the request ----------
    def body(self, ev: dict) -> bytes:
        fmt = self.settings.get("format") or "json"
        ts = float(ev.get("ts") or time.time())
        title, detail = str(ev.get("title", "")), str(ev.get("detail", ""))
        sev = ev.get("severity", "info")
        if fmt == "slack":
            data = {"text": f"{ICONS.get(sev, '')} *{title}*" + (f"\n{detail}" if detail else "")}
        elif fmt == "discord":
            data = {"embeds": [{"title": title[:256], "description": detail[:4000],
                                "color": int(COLORS.get(sev, "#3b82f6")[1:], 16),
                                "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat()}]}
        elif fmt == "teams":   # Teams "Workflows" webhook: an Adaptive Card
            body = [{"type": "TextBlock", "text": f"{ICONS.get(sev, '')} {title}", "weight": "Bolder", "wrap": True,
                     "color": "Attention" if sev == "critical" else "Warning" if sev == "warning" else "Default"}]
            if detail:
                body.append({"type": "TextBlock", "text": detail, "wrap": True})
            body.append({"type": "TextBlock", "isSubtle": True, "size": "Small", "wrap": True,
                         "text": f"NetMaster · {ev.get('category', '')} · {datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')}"})
            data = {"type": "message", "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "type": "AdaptiveCard", "version": "1.4", "body": body}}]}
        else:
            data = {"type": "netmaster.event", "id": ev.get("id"),
                    "time": datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds"), "ts": ts,
                    "category": ev.get("category"), "severity": sev, "title": title, "detail": detail,
                    "kind": ev.get("kind") or None, "source": ev.get("source") or None,
                    "netmaster": self.ctx.local_ip}
        return json.dumps(data, ensure_ascii=False).encode()

    def post(self, ev: dict) -> None:
        if not self.url.startswith(("https://", "http://")):
            raise ValueError("Set the webhook address (it starts with https://)")
        body = self.body(ev)
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if self.settings.get("secret"):
            sig = hmac.new(str(self.settings["secret"]).encode(), body, hashlib.sha256).hexdigest()
            headers["X-NetMaster-Signature"] = f"sha256={sig}"
        if self.settings.get("auth_header"):
            headers["Authorization"] = str(self.settings["auth_header"]).strip()
        r = http_request("POST", self.url, data=body, headers=headers, timeout=15,
                         verify_tls=bool(self.settings.get("verify_tls", True)))
        if not r.ok:
            raise RuntimeError(f"The receiver answered HTTP {r.status}" + (f": {r.text[:120]}" if r.text.strip() else ""))

    async def deliver(self, ev: dict) -> None:
        for wait in (*RETRY_S, None):
            try:
                await self.ctx.to_thread(self.post, ev)
                self.sent += 1
                self.last_sent = time.time()
                self.ok()
                return
            except Exception as e:
                self.error(str(e) if isinstance(e, (RuntimeError, ValueError)) else e)
                if wait is None:
                    self.failed += 1
                    self.ctx.log.warning("Webhook gave up on event %s: %s", ev.get("id"), e)
                    return
                await asyncio.sleep(wait)

    # ---------- running ----------
    async def run(self) -> None:
        q = self.ctx.subscribe_events()
        if not self.url:
            self.last_error = "Set the webhook address in the module settings"
        else:
            self.ok()
        while True:
            ev = await q.get()
            self.queue_len = q.qsize()
            if self.url and self.wanted(ev):
                await self.deliver(ev)

    async def action(self, action_id: str, value: str | None = None) -> str:
        if action_id != "test":
            raise ValueError("This module has no such action")
        await self.ctx.to_thread(self.post, {"id": 0, "ts": time.time(), "category": "system", "severity": "info",
                                             "title": "NetMaster test message",
                                             "detail": "The webhook works.", "kind": "test", "source": "webhook"})
        self.ok()
        return "Sent. Check that it arrived."

    def status(self) -> dict:
        if not self.url:
            return {}
        sent = f"{self.sent} sent" + (f" · {self.failed} failed" if self.failed else "")
        # only the host: Teams, Slack and Discord keep their secret in the rest of the address
        return {"rows": [{"label": urlparse(self.url).netloc or self.url[:40], "value": sent,
                          "state": "down" if self.last_error else "up"}]}
