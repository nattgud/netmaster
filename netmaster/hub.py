from __future__ import annotations

import asyncio
import logging
import time


class Hub:
    """Sends real-time messages to every connected WebSocket client."""

    def __init__(self) -> None:
        self._clients: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    def publish(self, type_: str, data) -> None:
        msg = {"type": type_, "data": data}
        for q in list(self._clients):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # slow client: it reloads when it reconnects


class EventService:
    """Stores and broadcasts events (alerts)."""

    SEVERITIES = ("info", "notice", "warning", "critical")

    def __init__(self, db, hub: Hub) -> None:
        self.db = db
        self.hub = hub
        self.listeners: list = []  # e.g. push notifications, modules

    def emit(self, category: str, severity: str, title: str, detail: str = "", source: str = "",
             kind: str = "") -> dict:
        """kind: a fixed id for the type of alert (e.g. "arp_spoofing"), for automations. Titles may change."""
        ts = time.time()
        eid = self.db.insert_event(ts, category, severity, title, detail, source)
        ev = {"id": eid, "ts": ts, "category": category, "severity": severity,
              "title": title, "detail": detail, "source": source, "kind": kind}
        self.hub.publish("event", ev)
        for listener in self.listeners:
            try:
                listener(ev)
            except Exception:
                logging.getLogger("netmaster.events").exception("Event listener failed")
        return ev
