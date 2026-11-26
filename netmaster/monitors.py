"""Disruption monitoring: router (LAN), internet (WAN), access points and DNS."""
from __future__ import annotations

import asyncio
import logging
import statistics
import time
from collections import deque

from .probes import detect_gateway, dns_query, ping_once

log = logging.getLogger("netmaster.monitor")

KNOWN_NAMES = {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google", "9.9.9.9": "Quad9",
               "1.0.0.1": "Cloudflare", "8.8.4.4": "Google"}
RANK = {"up": 0, "degraded": 1, "down": 2}


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    if sec < 60:
        return f"{sec} s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m} min {s} s"
    h, m = divmod(m, 60)
    return f"{h} h {m} min"


class Target:
    def __init__(self, key: str, name: str, host: str, kind: str, window: int, fail_threshold: int,
                 latency_warn: float, loss_warn: float):
        self.key, self.name, self.host, self.kind = key, name, host, kind
        self.window, self.fail_threshold = window, fail_threshold
        self.latency_warn, self.loss_warn = latency_warn, loss_warn
        self.samples: deque[float | None] = deque(maxlen=window)
        self.consec_fail = 0
        self.last_ms: float | None = None
        self.last_ts: float | None = None
        self.state: str | None = None
        self.since = time.time()

    def add(self, ts: float, ms: float | None) -> None:
        self.samples.append(ms)
        self.consec_fail = 0 if ms is not None else self.consec_fail + 1
        self.last_ms, self.last_ts = ms, ts

    @property
    def loss_pct(self) -> float:
        if not self.samples:
            return 0.0
        return 100.0 * sum(1 for s in self.samples if s is None) / len(self.samples)

    @property
    def median_ms(self) -> float | None:
        recent = [s for s in list(self.samples)[-12:] if s is not None]
        return statistics.median(recent) if recent else None

    def evaluate(self) -> str:
        if self.consec_fail >= self.fail_threshold:
            return "down"
        if self.consec_fail:
            # Ongoing loss streak: wait and see whether it becomes an outage, instead of
            # first alerting "degraded" and then "down" for the same incident.
            return self.state or "up"
        if self.state == "down":
            return "up"  # the window is reset in set_state, old losses do not count
        if len(self.samples) >= 10:
            med = self.median_ms
            if self.loss_pct >= self.loss_warn or (med is not None and med > self.latency_warn):
                return "degraded"
        return "up"

    def set_state(self, new: str) -> str | None:
        """Sets a new state; returns the previous one if it changed."""
        prev = self.state
        if new == prev:
            return None
        if prev == "down":
            # Restart the window after an outage so old losses do not give a false "degraded".
            self.samples = deque([s for s in self.samples if s is not None][-1:], maxlen=self.window)
        self.state, self.since = new, time.time()
        return prev or "init"

    def problem(self) -> str:
        parts = [f"loss {self.loss_pct:.0f} %"]
        if self.median_ms is not None:
            parts.append(f"median {self.median_ms:.0f} ms")
        return ", ".join(parts)

    def to_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "host": self.host, "kind": self.kind,
                "state": self.state or "unknown", "since": self.since, "last_ms": self.last_ms,
                "median_ms": self.median_ms, "loss_pct": round(self.loss_pct, 1)}


class NetworkMonitor:
    def __init__(self, cfg, db, hub, events):
        self.cfg, self.db, self.hub, self.events = cfg, db, hub, events
        self.gateway: Target | None = None
        self.uplink_target: Target | None = None
        self.devices: list[Target] = []
        self.internet: list[Target] = []
        self.uplink = {"state": "unknown", "since": time.time()}
        self.lan = {"state": "unknown", "since": time.time()}
        self.wan = {"state": "unknown", "since": time.time()}

    @property
    def local_down(self) -> bool:
        """The server itself is cut off: then every other measurement is meaningless."""
        return self.uplink["state"] == "down" or self.lan["state"] == "down"

    def _target(self, host: str, name: str, kind: str) -> Target:
        return Target(f"ping:{host}", name, host, kind, self.cfg.window, 3,
                      self.cfg.latency_warn_ms, self.cfg.loss_warn_pct)

    @property
    def targets(self) -> list[Target]:
        return ([self.gateway] if self.gateway else []) + self.devices + self.internet

    async def setup(self) -> None:
        gw = self.cfg.gateway or await asyncio.to_thread(detect_gateway)
        if gw:
            self.gateway = self._target(gw, self.cfg.routers.get(gw, "Router (gateway)"), "gateway")
        else:
            self.events.emit("system", "warning", "No gateway found",
                             "Set [monitor] gateway in config.toml.", "netmaster")
        for ip, name in self.cfg.routers.items():
            if ip != gw:
                self.devices.append(self._target(ip, name, "device"))
        up = self.cfg.uplink
        if up and up != gw:
            self.uplink_target = next((d for d in self.devices if d.host == up), None)
            if not self.uplink_target:
                self.uplink_target = self._target(up, "Serverns anslutning", "device")
                self.devices.insert(0, self.uplink_target)
        for host in self.cfg.internet_targets:
            self.internet.append(self._target(host, KNOWN_NAMES.get(host, host), "internet"))
        log.info("Gateway: %s, devices: %s", gw, [d.host for d in self.devices])

    async def run(self) -> None:
        while True:
            t0 = time.monotonic()
            try:
                await self._cycle()
            except Exception:  # the monitor must never die
                log.exception("Fel i pingcykel")
            await asyncio.sleep(max(0.5, self.cfg.ping_interval - (time.monotonic() - t0)))

    async def _cycle(self) -> None:
        targets = self.targets
        results = await asyncio.gather(
            *(asyncio.to_thread(ping_once, t.host, self.cfg.ping_timeout_ms) for t in targets))
        ts = time.time()
        for t, ms in zip(targets, results):
            t.add(ts, ms)
        self.db.insert_samples([(ts, t.key, ms) for t, ms in zip(targets, results)])
        self._evaluate()
        self.hub.publish("samples", {"ts": ts, "values": {t.key: ms for t, ms in zip(targets, results)}})

    def _evaluate(self) -> None:
        others = [t for t in self.devices if t is not self.uplink_target]
        for t in self.targets:
            if t not in others:
                t.set_state(t.evaluate())

        # Hierarki: uplink (serverns egen anslutning) → huvudrouter → internet.
        # A fault higher up silences alerts further down, so one outage gives one alert, not five.
        if self.uplink_target:
            st = self.uplink_target.state
            # If the main router answers through the uplink, the server's connection is intact; the uplink
            # itself staying silent is a freeze in it, which FreezeWatch alerts about.
            if st != "up" and self.gateway and self.gateway.consec_fail == 0:
                st = "up"
            self._transition(self.uplink, st, self._uplink_messages)
        uplink_down = self.uplink["state"] == "down"

        if self.gateway and not uplink_down:
            self._transition(self.lan, self.gateway.state, self._lan_messages)

        # Other access points are only judged while the server itself has contact, so that an
        # outage still going on when the server regains contact is still alerted.
        if not self.local_down:
            for t in others:
                prev = t.set_state(t.evaluate())
                if prev:
                    self._device_event(t, prev)

        # WAN = the best of the internet targets.
        if self.internet and not self.local_down:
            best = min((t.state for t in self.internet), key=lambda s: RANK[s])
            self._transition(self.wan, best, self._wan_messages)

    def _transition(self, scope: dict, new: str, messages) -> None:
        prev = scope["state"]
        if new == prev:
            return
        duration = time.time() - scope["since"]
        scope["state"], scope["since"] = new, time.time()
        if prev == "unknown" and new == "up":
            return  # normal uppstart
        msg = messages(prev, new, duration)
        if msg:
            self.events.emit(*msg)

    def _uplink_messages(self, prev, new, duration):
        u = self.uplink_target
        if new == "down":
            return ("disruption", "critical", f"Server lost contact with {u.name}",
                    f"{u.host} is not responding. Check the cable and power to {u.name}. "
                    "Other checks are paused until contact is restored.", u.host)
        if new == "degraded":
            return ("disruption", "warning", f"Unstable connection to {u.name}", u.problem(), u.host)
        if prev == "down":
            return ("disruption", "info", f"Contact with {u.name} restored",
                    f"The outage lasted {fmt_duration(duration)}.", u.host)
        return ("disruption", "info", f"Connection to {u.name} is stable again",
                f"The disruption lasted {fmt_duration(duration)}.", u.host)

    def _lan_messages(self, prev, new, duration):
        gw = self.gateway
        src = gw.host
        if new == "down":
            if self.uplink_target:
                where = (f"{self.uplink_target.name} responds but {gw.name} ({gw.host}) does not. The fault is in "
                         f"{gw.name} or in the link between {self.uplink_target.name} and {gw.name}.")
            else:
                where = f"The server cannot reach {gw.name} ({gw.host}). The fault is local: Wi-Fi, cable or the router itself."
            return ("disruption", "critical", "No contact with the main router", where, src)
        if new == "degraded":
            return ("disruption", "warning", "Unstable connection to the main router",
                    f"{gw.name}: {gw.problem()}. Often Wi-Fi interference or weak signal.", src)
        if prev == "down":
            return ("disruption", "info", "Contact with the main router restored",
                    f"The outage lasted {fmt_duration(duration)}.", src)
        return ("disruption", "info", "Connection to the main router is stable again",
                f"The disruption lasted {fmt_duration(duration)}.", src)

    def _wan_messages(self, prev, new, duration):
        names = ", ".join(t.name for t in self.internet)
        if new == "down":
            return ("disruption", "critical", "Internet down (WAN outage)",
                    f"The router responds but none of {names} do. The fault is probably with "
                    "your ISP or the router WAN connection.", "wan")
        if new == "degraded":
            worst = max(self.internet, key=lambda t: t.loss_pct)
            return ("disruption", "warning", "Internet connection disrupted",
                    f"{worst.name}: {worst.problem()}.", "wan")
        if prev == "down":
            return ("disruption", "info", "Internet is back", f"The outage lasted {fmt_duration(duration)}.", "wan")
        return ("disruption", "info", "Internet connection is stable again",
                f"The disruption lasted {fmt_duration(duration)}.", "wan")

    def _device_event(self, t: Target, prev: str) -> None:
        if prev == "init" and t.state == "up":
            return
        if t.state == "down":
            self.events.emit("disruption", "warning", f"{t.name} is not responding",
                             f"{t.host} has not answered ping for the last {t.consec_fail} attempts.", t.host)
        elif prev == "down":
            self.events.emit("disruption", "info", f"{t.name} is responding again", "", t.host)

    def status(self) -> dict:
        uplink = None
        if self.uplink_target:
            uplink = {**self.uplink, "name": self.uplink_target.name, "host": self.uplink_target.host}
        return {"uplink": uplink, "lan": self.lan, "wan": self.wan,
                "targets": [t.to_dict() for t in self.targets]}


class DnsMonitor:
    def __init__(self, cfg, db, hub, events, net: NetworkMonitor):
        self.cfg, self.db, self.hub, self.events, self.net = cfg, db, hub, events, net
        self.targets: list[Target] = []
        self._i = 0

    def setup(self) -> None:
        gw = self.net.gateway.host if self.net.gateway else None
        for s in self.cfg.dns_servers:
            host = gw if s == "auto" else s
            if not host or any(t.host == host for t in self.targets):
                continue
            from urllib.parse import urlparse
            svc = next((n for n, u in self.cfg.services.items() if urlparse(u).hostname == host), None)
            name = ("Router DNS" if host == gw else f"DNS on {svc}" if svc
                    else f"DNS {KNOWN_NAMES.get(host, host)}")
            self.targets.append(Target(f"dns:{host}", name, host, "dns", 20, 2,
                                       self.cfg.dns_latency_warn_ms, 25))

    async def run(self) -> None:
        while True:
            try:
                await self._cycle()
            except Exception:
                log.exception("Fel i DNS-cykel")
            await asyncio.sleep(self.cfg.dns_interval)

    async def _cycle(self) -> None:
        if not self.targets or not self.cfg.dns_names:
            return
        name = self.cfg.dns_names[self._i % len(self.cfg.dns_names)]
        self._i += 1
        results = await asyncio.gather(*(asyncio.to_thread(dns_query, t.host, name) for t in self.targets))
        ts = time.time()
        for t, ms in zip(self.targets, results):
            t.add(ts, ms)
        self.db.insert_samples([(ts, t.key, ms) for t, ms in zip(self.targets, results)])
        self.hub.publish("samples", {"ts": ts, "values": {t.key: ms for t, ms in zip(self.targets, results)}})

        lan_down = self.net.local_down
        for t in self.targets:
            new = t.evaluate()
            if lan_down:
                continue  # no point alerting about DNS when the router cannot be reached
            prev = t.set_state(new)
            if not prev or (prev == "init" and new == "up"):
                continue
            if new == "down":
                gw = self.net.gateway and self.net.gateway.host
                local = t.host == gw or t.name.startswith("DNS on ") or t.host.startswith(("192.168.", "10.", "172."))
                extra = " Web pages may stop loading even though the internet works." if local else ""
                if local and t.host != gw:
                    extra += (f" Every device that uses {t.host} for DNS is affected. Restart the DNS service there, "
                              "or temporarily set the router's DNS to a public one such as 1.1.1.1.")
                self.events.emit("disruption", "warning", f"{t.name} is not responding",
                                 f"Lookups against {t.host} fail.{extra}", t.host)
            elif new == "degraded":
                self.events.emit("disruption", "notice", f"{t.name} is slow", t.problem(), t.host)
            elif prev in ("down", "degraded"):
                self.events.emit("disruption", "info", f"{t.name} is working again", "", t.host)

    def status(self) -> dict:
        return {"targets": [t.to_dict() for t in self.targets]}


class FreezeWatch:
    """Pings the server's uplink (e.g. an access point) every second and logs short freezes.

    The main router is pinged at the same time. If it answers while the uplink is silent, it is the
    uplink's own processor that hangs (Wi-Fi freezes, wired traffic passes), not the cable beyond it.
    """
    MIN_LOST = 2  # at least 2 s without answer counts as a freeze

    def __init__(self, net: NetworkMonitor, events):
        self.net, self.events = net, events
        self.lost = 0
        self.gw_ok = 0
        self.start: float | None = None
        self.freezes: deque[dict] = deque(maxlen=50)

    async def run(self) -> None:
        up = self.net.uplink_target
        if not up:
            return
        gw = self.net.gateway
        while True:
            t0 = time.monotonic()
            try:
                a, b = await asyncio.gather(asyncio.to_thread(ping_once, up.host, 800),
                                            asyncio.to_thread(ping_once, gw.host, 800) if gw else asyncio.sleep(0))
                self._step(up, gw, a is not None, b is not None)
            except Exception:
                log.exception("FreezeWatch")
            await asyncio.sleep(max(0.1, 1.0 - (time.monotonic() - t0)))

    def _step(self, up: Target, gw: Target | None, up_ok: bool, gw_ok: bool) -> None:
        if not up_ok:
            if not self.lost:
                self.start, self.gw_ok = time.time(), 0
            self.lost += 1
            self.gw_ok += gw_ok
            return
        if self.lost >= self.MIN_LOST:
            dur = time.time() - self.start
            through = gw is not None and self.gw_ok >= self.lost * 0.8
            self.freezes.append({"ts": self.start, "s": round(dur), "gateway_ok": through})
            if through:
                why = (f"{gw.name} answered through it the whole time, so the cable is fine. "
                       f"{up.name} itself stopped responding (Wi-Fi clients on it freeze).")
            elif gw:
                why = f"{gw.name} did not answer either: the server link, {up.name} or the cable dropped."
            else:
                why = ""
            self.events.emit("disruption", "warning", f"{up.name} froze for {fmt_duration(dur)}",
                             f"No ping reply for {self.lost} s. {why}".strip(), up.host)
        self.lost = 0

    def status(self) -> dict:
        day = [f for f in self.freezes if time.time() - f["ts"] < 86400]
        return {"host": self.net.uplink_target.host if self.net.uplink_target else None,
                "last_24h": len(day), "recent": list(self.freezes)[-10:]}


class CallQuality:
    """Measures what decides how a video call feels: response time, unevenness (jitter) and lost packets.

    Pings the internet every second and sums up per minute. The network's total traffic at that time
    is stored too, so you can see whether bad minutes come from a full network (bufferbloat) or not.
    """
    HOSTS = ("1.1.1.1", "8.8.8.8")

    def __init__(self, net: NetworkMonitor, events, load=lambda: None, db=None):
        self.net, self.events, self.load, self.db = net, events, load, db
        self._cur: list[float | None] = []
        self._minute: float | None = None
        self.minutes: deque[dict] = deque(maxlen=1440)
        if db is not None:  # the minutes are stored in the database so the graph survives restarts
            for m in db.query("SELECT * FROM calls WHERE ts > ? ORDER BY ts", (time.time() - 86400,)):
                self.minutes.append(m)
        self._poor = 0
        self._alerted = 0.0

    @staticmethod
    def grade(ms, jitter, loss) -> str:
        if ms is None or loss >= 3 or jitter >= 40 or ms >= 200:
            return "poor"
        if loss >= 1 or jitter >= 20 or ms >= 100:
            return "fair"
        return "good"

    async def run(self) -> None:
        i = 0
        while True:
            t0 = time.monotonic()
            try:
                ms = await asyncio.to_thread(ping_once, self.HOSTS[i % 2], 1000)
            except Exception:
                ms = None
            i += 1
            now = time.time()
            minute = now - now % 60
            if self._minute is not None and minute != self._minute and self._cur:
                try:
                    self._finish(self._minute)
                except Exception:  # an error must never stop the measurement
                    log.exception("Call quality: could not finish minute")
                    self._cur = []
            self._minute = minute
            self._cur.append(ms)
            await asyncio.sleep(max(0.1, 1.0 - (time.monotonic() - t0)))

    def _finish(self, ts: float) -> None:
        xs, self._cur = self._cur, []
        ok = [x for x in xs if x is not None]
        loss = 100 * (len(xs) - len(ok)) / len(xs)
        ms = statistics.median(ok) if ok else None
        jitter = statistics.mean(abs(a - b) for a, b in zip(ok, ok[1:])) if len(ok) > 1 else 0.0
        try:
            load = self.load()
        except Exception:
            load = None
        g = self.grade(ms, jitter, loss)
        m = {"ts": ts, "ms": round(ms, 1) if ms is not None else None, "jitter": round(jitter, 1),
             "loss": round(loss, 1), "load": round(load, 1) if load is not None else None, "grade": g}
        self.minutes.append(m)
        if self.db is not None:
            try:
                self.db.execute("INSERT OR REPLACE INTO calls(ts, ms, jitter, loss, load, grade) VALUES(?,?,?,?,?,?)",
                                [(m["ts"], m["ms"], m["jitter"], m["loss"], m["load"], m["grade"])])
            except Exception:
                pass
        if self.net.local_down or ms is None:  # a full outage is already alerted by the network monitor
            self._poor = 0
            return
        self._poor = self._poor + 1 if g == "poor" else 0
        if self._poor == 2 and time.time() - self._alerted > 1800:
            self._alerted = time.time()
            if load is not None and load >= 20:
                why = (f"The network was busy ({load:.0f} Mbit/s) at the same time. Heavy downloads or uploads fill the "
                       "router's queue and delay everything else (bufferbloat). Turning on QoS in the router helps.")
            else:
                why = "The home network was quiet, so the problem is most likely at your internet provider or further out."
            self.events.emit("disruption", "warning", "Poor call quality on the internet connection",
                             f"Last 2 minutes: delay {m['ms']} ms, jitter {m['jitter']} ms, lost packets {m['loss']} %. {why}",
                             "internet")

    def status(self) -> dict:
        last = self.minutes[-1] if self.minutes else None
        hour = [m for m in self.minutes if time.time() - m["ts"] < 3600]
        return {"now": last, "hour": {g: sum(1 for m in hour if m["grade"] == g) for g in ("good", "fair", "poor")}}

    def history(self, hours: float) -> list[dict]:
        return [m for m in self.minutes if time.time() - m["ts"] < hours * 3600]
