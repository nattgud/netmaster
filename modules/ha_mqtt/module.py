"""Home Assistant through MQTT discovery.

What shows up in Home Assistant:
  NetMaster (one device)
    event.netmaster_security_alert   every security alert, with a fixed event_type (see KINDS)
    sensor.netmaster_unknown_devices how many devices are not marked as known, with the list as an attribute
    device triggers                  one per alert type, for the automation editor ("NetMaster: ARP spoofing")
  Every device you pick in NetMaster ("Show in Home Assistant")
    device_tracker.<name>            home / not_home, with IP, MAC, vendor, connection and top 3 sites
    switch.<name>_internet           on = has internet, off = paused (only when a router module can pause)
    sensor.<name>_ip_address         the current IP (diagnostic)
Devices are linked by MAC, so they join a device Home Assistant already knows from another integration.
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import time

from netmaster.sdk import ModuleBase

# Alert type -> name in the automation editor. Keep the ids stable: automations depend on them.
KINDS = {
    "arp_spoofing": "ARP spoofing (router MAC changed)",
    "mac_flapping": "IP address keeps changing MAC",
    "new_device": "New unknown device",
    "rogue_dhcp": "Unknown DHCP server",
    "dns_tampered": "Tampered DNS answers",
    "dns_redirects_nx": "Router DNS redirects unknown names",
    "dns_servers_changed": "Server DNS servers changed",
    "new_open_port": "New open port on a device",
    "risky_services": "Risky services in the network",
    "internet_exposed_port": "New port visible from the internet",
    "vulnerability": "Known vulnerabilities on the public IP",
    "heavy_upload": "Heavy upload from a device",
    "night_activity": "Device active at night",
    "new_server_program": "New program on the server uses the internet",
    "unknown_log_source": "Logs from an unknown source",
    "router_threat": "Security alert from the router",
    "router_dos": "Attack blocked by the router",
    "router_login_fail": "Failed login to the router",
    "router_login_ok": "Someone logged in to the router",
    "router_remote_mgmt": "Router remote management turned on",
    "router_portfwd": "Port opened on the router",
    "other": "Other security alert",
}
ONLINE_S = 600          # same limit as "online" in NetMaster
TOP_EVERY_S = 300       # top sites change slowly
MAC_RX = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)) if ts else None


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        s = settings
        self.host = (s.get("host") or "").strip()
        self.port = int(float(s.get("port") or 1883))
        self.disc = (s.get("discovery_prefix") or "homeassistant").strip().strip("/")
        self.pre = (s.get("topic_prefix") or "netmaster").strip().strip("/")
        self.interval = max(10.0, float(s.get("interval_s") or 30))
        node_file = ctx.data_dir / "node_id"
        if not node_file.exists():
            node_file.write_text("nm_" + secrets.token_hex(3), "utf-8")
        self.node = node_file.read_text("utf-8").strip()  # keeps ids unique if you run two NetMasters
        self.client = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.connected = False
        self.resend = asyncio.Event()   # (re)connected or Home Assistant restarted: send everything again
        self.sent: dict[str, str] = {}  # topic -> last payload, so unchanged states are not resent
        self.shared: set[str] = set()   # MACs with entities in Home Assistant
        self.switches: set[str] = set()
        self.top: dict[str, tuple[float, list]] = {}
        self.alerts = 0

    # ---------- MQTT ----------
    def _connect(self):
        import paho.mqtt.client as mqtt
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"netmaster-{self.node}")
        if self.settings.get("username"):
            c.username_pw_set(self.settings["username"], self.settings.get("password") or None)
        if self.settings.get("tls"):
            c.tls_set()
        c.will_set(f"{self.pre}/status", "offline", qos=1, retain=True)
        c.reconnect_delay_set(2, 60)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        c.connect_async(self.host, self.port, keepalive=60)
        c.loop_start()
        self.client = c

    def _on_connect(self, client, userdata, flags, rc, props=None):
        if rc.is_failure:
            self.connected = False
            self.last_error = f"The broker refused the connection: {rc}"
            return
        self.connected = True
        client.publish(f"{self.pre}/status", "online", qos=1, retain=True)
        client.subscribe([(f"{self.pre}/device/+/internet/set", 1), (f"{self.disc}/status", 1)])
        self.loop.call_soon_threadsafe(self.resend.set)

    def _on_disconnect(self, client, userdata, flags, rc, props=None):
        self.connected = False
        if rc.is_failure:
            self.last_error = f"Lost the connection to the broker ({rc}), reconnecting"

    def _on_message(self, client, userdata, msg):
        payload = msg.payload.decode("utf-8", "replace").strip()
        if msg.topic == f"{self.disc}/status":
            if payload == "online":  # Home Assistant restarted and forgot non-retained state
                self.loop.call_soon_threadsafe(self.resend.set)
            return
        m = re.fullmatch(re.escape(self.pre) + r"/device/([0-9a-f]{12})/internet/set", msg.topic)
        if m and payload in ("ON", "OFF"):
            asyncio.run_coroutine_threadsafe(self._set_internet(m.group(1), payload == "ON"), self.loop)

    def _pub(self, topic: str, payload, retain: bool = True, force: bool = False) -> None:
        if not isinstance(payload, str):
            payload = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if not force and self.sent.get(topic) == payload:
            return
        if self.client and self.connected:
            self.client.publish(topic, payload, qos=1, retain=retain)
            self.sent[topic] = payload

    # ---------- discovery ----------
    @staticmethod
    def _id(mac: str) -> str:
        return mac.replace(":", "")

    def _hub_device(self) -> dict:
        return {"identifiers": [f"netmaster_{self.node}"], "name": "NetMaster", "manufacturer": "NetMaster",
                "model": "Network monitor"}

    def _base(self, uid: str, name: str | None, device: dict, **extra) -> dict:
        # name None = the entity is named after its device (has_entity_name), e.g. "Anna's iPhone".
        return {"unique_id": uid, "name": name, "device": device, "availability_topic": f"{self.pre}/status", **extra}

    def _discover_hub(self) -> None:
        dev = self._hub_device()
        n = self.node
        ev = self._base(f"{n}_security_alert", "Security alert", dev, state_topic=f"{self.pre}/security/alert",
                        event_types=list(KINDS), icon="mdi:shield-alert")
        self._pub(f"{self.disc}/event/{n}/security_alert/config", ev, force=True)
        un = self._base(f"{n}_unknown_devices", "Unknown devices", dev, state_topic=f"{self.pre}/unknown_devices",
                        value_template="{{ value_json.count }}",
                        json_attributes_topic=f"{self.pre}/unknown_devices",
                        json_attributes_template="{{ {'devices': value_json.devices} | tojson }}",
                        state_class="measurement", unit_of_measurement="devices", icon="mdi:help-network")
        self._pub(f"{self.disc}/sensor/{n}/unknown_devices/config", un, force=True)
        for kind, label in KINDS.items():
            self._pub(f"{self.disc}/device_automation/{n}/{kind}/config", {
                "automation_type": "trigger", "topic": f"{self.pre}/security/{kind}",
                "type": "security_alert", "subtype": label, "device": dev}, force=True)

    def _device_info(self, mac: str, d: dict) -> dict:
        info = {"identifiers": [f"netmaster_{self.node}_{self._id(mac)}"], "connections": [["mac", mac]],
                "name": self._name(mac, d), "via_device": f"netmaster_{self.node}"}
        if d.get("vendor"):
            info["manufacturer"] = d["vendor"]
        return info

    @staticmethod
    def _name(mac: str, d: dict) -> str:
        return d.get("name") or d.get("hostname") or d.get("vendor") or mac

    def _discover_device(self, mac: str, d: dict, with_switch: bool) -> None:
        i, n, dev = self._id(mac), self.node, self._device_info(mac, d)
        base = f"{self.pre}/device/{i}"
        self._pub(f"{self.disc}/device_tracker/{n}/{i}/config",
                  self._base(f"{n}_{i}_tracker", None, dev, state_topic=f"{base}/state",
                             json_attributes_topic=f"{base}/attributes", payload_home="home",
                             payload_not_home="not_home", source_type="router", icon="mdi:lan-connect"))
        self._pub(f"{self.disc}/sensor/{n}/{i}_ip/config",
                  self._base(f"{n}_{i}_ip", "IP address", dev, state_topic=f"{base}/ip",
                             entity_category="diagnostic", icon="mdi:ip-network"))
        topic = f"{self.disc}/switch/{n}/{i}_internet/config"
        if with_switch:
            self._pub(topic, self._base(f"{n}_{i}_internet", "Internet", dev, state_topic=f"{base}/internet",
                                        command_topic=f"{base}/internet/set", icon="mdi:web",
                                        json_attributes_topic=f"{base}/internet/attributes"))
            self.switches.add(mac)
        elif mac in self.switches:
            self._pub(topic, "")
            self.switches.discard(mac)

    def _remove_device(self, mac: str) -> None:
        i, n = self._id(mac), self.node
        for t in (f"device_tracker/{n}/{i}", f"sensor/{n}/{i}_ip", f"switch/{n}/{i}_internet"):
            self._pub(f"{self.disc}/{t}/config", "")
        self.shared.discard(mac)
        self.switches.discard(mac)
        self._save_shared()

    def _save_shared(self) -> None:
        (self.ctx.data_dir / "shared.json").write_text(json.dumps(sorted(self.shared)), "utf-8")

    def _load_shared(self) -> set[str]:
        try:
            return set(json.loads((self.ctx.data_dir / "shared.json").read_text("utf-8")))
        except (OSError, ValueError):
            return set()

    # ---------- state ----------
    async def _publish_all(self, force: bool = False) -> None:
        devs = self.ctx.devices()
        now = time.time()
        unknown = [{"name": self._name(m, d), "ip": d.get("ip"), "mac": m, "vendor": d.get("vendor"),
                    "host_name": d.get("hostname"), "online": now - (d.get("last_seen") or 0) < ONLINE_S,
                    "first_seen": _iso(d.get("first_seen")), "last_seen": _iso(d.get("last_seen"))}
                   for m, d in devs.items() if not d.get("trusted")]
        unknown.sort(key=lambda x: x["first_seen"] or "", reverse=True)
        # Home Assistant limits attribute size, so the list is capped (the count is not).
        self._pub(f"{self.pre}/unknown_devices", {"count": len(unknown), "devices": unknown[:40]}, force=force)

        want = {m for m, d in devs.items() if d.get("share")}
        for mac in self.shared - want:  # unticked or forgotten
            self._remove_device(mac)
        can_pause = self.ctx.can_pause
        protected = self.ctx.protected() if can_pause else {}
        paused = self.ctx.paused() if can_pause else set()
        changed = False
        for mac in sorted(want):
            d = devs[mac]
            with_switch = can_pause and mac not in protected
            if force or mac not in self.shared or (mac in self.switches) != with_switch \
                    or self.sent.get(f"name:{mac}") != self._name(mac, d):
                self._discover_device(mac, d, with_switch)
                self.sent[f"name:{mac}"] = self._name(mac, d)
                if mac not in self.shared:
                    self.shared.add(mac)
                    changed = True
            await self._publish_device(mac, d, mac in paused, with_switch, force)
        if changed:
            self._save_shared()

    async def _publish_device(self, mac: str, d: dict, paused: bool, with_switch: bool, force: bool) -> None:
        i = self._id(mac)
        base = f"{self.pre}/device/{i}"
        online = time.time() - (d.get("last_seen") or 0) < ONLINE_S
        attrs = {"ip": d.get("ip"), "mac": mac, "host_name": d.get("hostname"), "vendor": d.get("vendor"),
                 "netmaster_name": d.get("name"), "known": bool(d.get("trusted")),
                 "randomized_mac": bool(d.get("randomized")), "first_seen": _iso(d.get("first_seen")),
                 "last_seen": _iso(d.get("last_seen")), "internet_paused": paused}
        t = self.ctx.traffic(mac) or {}
        if t:
            attrs |= {"download_mbps": round((t.get("down") or 0) * 8 / 1e6, 2),
                      "upload_mbps": round((t.get("up") or 0) * 8 / 1e6, 2),
                      "connection": t.get("conn"), "ssid": t.get("ssid"), "signal": t.get("signal")}
        top = await self._top(mac, d.get("ip"))
        if top is not None:
            attrs["top_domains"] = [x["domain"] for x in top]
            attrs["top_domains_24h"] = [{"domain": x["domain"], "lookups": x["n"], "blocked": x.get("blocked") or 0}
                                        for x in top]
        self._pub(f"{base}/state", "home" if online else "not_home", force=force)
        self._pub(f"{base}/attributes", attrs, force=force)
        self._pub(f"{base}/ip", d.get("ip") or "", force=force)
        if with_switch:
            self._pub(f"{base}/internet", "OFF" if paused else "ON", force=force)

    async def _top(self, mac: str, ip: str | None):
        cached = self.top.get(mac)
        if cached and time.time() - cached[0] < TOP_EVERY_S and cached[2] == ip:
            return cached[1]
        try:
            top = await self.ctx.to_thread(self.ctx.top_domains, ip, 24, 3)
        except Exception as e:
            self.ctx.log.info("Top sites for %s failed: %s", mac, e)
            top = cached[1] if cached else None
        self.top[mac] = (time.time(), top, ip)
        return top

    async def _set_internet(self, macid: str, internet: bool) -> None:
        mac = ":".join(macid[i:i + 2] for i in range(0, 12, 2))
        d = self.ctx.devices().get(mac)
        if not d or not d.get("share") or mac not in self.switches:
            return  # only devices that have an Internet switch (never the router or the NetMaster server)
        topic = f"{self.pre}/device/{macid}/internet"
        try:
            paused = await self.ctx.pause(mac, not internet)
            self._pub(f"{topic}/attributes", {"last_error": None}, force=True)
        except Exception as e:
            paused = mac in self.ctx.paused()
            self.ctx.log.warning("Internet switch for %s: %s", mac, e)
            self._pub(f"{topic}/attributes", {"last_error": str(e), "last_error_at": _iso(time.time())}, force=True)
        self._pub(topic, "OFF" if paused else "ON", force=True)

    # ---------- alerts ----------
    def _alert(self, ev: dict) -> None:
        kind = ev.get("kind") or "other"
        if kind not in KINDS:
            kind = "other"
        src = str(ev.get("source") or "").lower()
        devs = self.ctx.devices()
        mac = src if MAC_RX.match(src) else None
        if not mac and src:
            m, _ = self.ctx.device_by_ip(src)
            mac = m if MAC_RX.match(m) else None
        d = devs.get(mac) if mac else None
        payload = {"event_type": kind, "type_name": KINDS[kind], "severity": ev.get("severity"),
                   "title": ev.get("title"), "detail": ev.get("detail"), "source": ev.get("source"),
                   "ip": (d or {}).get("ip") or (src if src and not MAC_RX.match(src) else None),
                   "mac": mac, "device_name": self._name(mac, d) if d else None,
                   "vendor": (d or {}).get("vendor"), "known_device": bool(d.get("trusted")) if d else None,
                   "netmaster_event_id": ev.get("id"), "time": _iso(ev.get("ts"))}
        self._pub(f"{self.pre}/security/alert", payload, retain=False, force=True)
        self._pub(f"{self.pre}/security/{kind}", payload, retain=False, force=True)
        self.alerts += 1

    # ---------- main loop ----------
    async def run(self) -> None:
        if not self.host:
            self.last_error = "Set the MQTT broker address in the module settings"
            return
        if not hasattr(self.ctx, "subscribe_events"):
            self.last_error = "This module needs NetMaster 0.2.0 or later. Update NetMaster first."
            return
        self.loop = asyncio.get_running_loop()
        self.shared = self._load_shared()
        self.switches = set(self.shared)  # so stale switches are removed when they no longer apply
        events = self.ctx.subscribe_events()
        await self.ctx.to_thread(self._connect)
        next_round = 0.0
        while True:
            try:
                if self.resend.is_set() and self.connected:
                    self.resend.clear()
                    self.sent.clear()
                    self._discover_hub()
                    await self._publish_all(force=True)
                    next_round = time.time() + self.interval
                elif self.connected and time.time() >= next_round:
                    await self._publish_all()
                    next_round = time.time() + self.interval
                if self.connected:
                    self.ok()
                elif not self.last_error:
                    self.last_error = f"Connecting to {self.host}:{self.port}…"
                try:
                    ev = await asyncio.wait_for(events.get(), timeout=2)
                except asyncio.TimeoutError:
                    continue
                if ev.get("category") == "security" and self.connected:
                    self._alert(ev)
                elif ev.get("category") == "system" and ev.get("title", "").startswith("Internet "):
                    next_round = 0  # paused/resumed somewhere: update the switch now
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.error(e)
                await asyncio.sleep(5)

    def stop(self) -> None:
        if self.client:
            try:
                self.client.publish(f"{self.pre}/status", "offline", qos=1, retain=True)
                self.client.disconnect()
                self.client.loop_stop()
            except Exception:
                pass

    def status(self) -> dict:
        return {"host": self.host, "name": "Home Assistant", "connected": self.connected,
                "devices": len(self.shared), "alerts_sent": self.alerts}
