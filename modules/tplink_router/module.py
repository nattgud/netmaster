"""TP-Link router: system log, clients, traffic, settings check and pausing devices (via tplinkrouterc6u)."""
from __future__ import annotations

import hashlib
import re
import threading
import time

from netmaster.sdk import Busy, ModuleBase


def _row_text(row) -> str:
    if isinstance(row, dict):
        # e.g. {"time", "type": "NAT", "level": "NOTICE", "content": "[12508] Virtual server ..."}
        content = next((str(row[k]) for k in ("content", "msg", "message", "log") if row.get(k)), None)
        if content is None:
            return " ".join(str(v) for v in row.values())
        content = re.sub(r"^\[\d+\]\s*", "", content)
        parts = [str(row[k]) for k in ("time", "level") if row.get(k)]
        prefix = f"{row['type']}: " if row.get("type") else ""
        return f"{' '.join(parts)} {prefix}{content}".strip()
    return str(row)


def _mac(m) -> str:
    return str(m).lower().replace("-", ":")


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.seen: set[str] = set()
        self.first = True
        self.model: str | None = None
        self.public_ip: str | None = None
        self.audit: list[dict] | None = None
        self.audit_ts: float | None = None
        self.blocked: list[str] = []        # MACs paused in the router's access control
        self._fails = 0
        self._lock = threading.Lock()       # one login at a time (the router only allows one)

    @property
    def host(self) -> str | None:
        return (self.settings.get("host") or "").strip() or self.ctx.gateway

    # ---------- login ----------
    def _client(self):
        from tplinkrouterc6u import TplinkRouterProvider
        if not self.settings.get("password"):
            raise RuntimeError("No password set")
        r = TplinkRouterProvider.get_client(f"http://{self.host}", self.settings["password"],
                                            self.settings.get("username") or "admin")
        # The library logs in with confirm=true, which logs out whoever is already logged in to the
        # router's web page. Without it the router refuses us instead, and we try again later.
        r._get_login_data = lambda crypted: f"operation=login&password={crypted}"
        try:
            r.authorize()
        except Exception as e:
            if "conflict" in str(e).lower() or "logged" in str(e).lower():
                raise Busy("Paused: someone is logged in to the router's web page") from None
            raise
        return r

    @staticmethod
    def _logout(r) -> None:
        try:
            r.logout()
        except Exception:
            pass

    # ---------- settings check ----------
    def _audit(self, r) -> list[dict]:
        """Security check of the router's settings. Only what actually matters."""
        def get(path, op="read"):
            try:
                return r.request(path, f"operation={op}")
            except Exception:
                return None
        fw = get("admin/firmware?form=upgrade") or {}
        upd = get("admin/cloud_account?form=check_upgrade") or {}
        auto = get("admin/firmware?form=auto_upgrade") or {}
        remote = get("admin/administration?form=remote") or {}
        upnp = get("admin/upnp?form=enable") or {}
        dmz = get("admin/nat?form=dmz") or {}
        vs = get("admin/nat?form=vs", "load") or []
        if m := re.search(r"//([\d.]+)", str(remote.get("web_address", ""))):
            self.public_ip = m.group(1)

        def chk(id_, title, ok, detail):
            return {"id": id_, "title": title, "ok": ok, "detail": detail}
        newer = str(upd.get("update_number", "0")) not in ("0", "")
        out = [
            chk("firmware", "Firmware", not newer,
                f"{fw.get('firmware_version', '?')}. " + ("A newer version is available." if newer else "Up to date.")
                + f" Auto-update {'on' if auto.get('enable') == 'on' else 'off'}."),
            chk("remote", "Remote management", remote.get("enable") != "on",
                "On: the router admin page is reachable from the internet." if remote.get("enable") == "on" else "Off."),
            chk("upnp", "UPnP", upnp.get("enable") != "on",
                "On: any device can open ports to the internet by itself. Turn off unless a console or app needs it."
                if upnp.get("enable") == "on" else "Off."),
            chk("dmz", "DMZ", dmz.get("enable") != "on",
                f"On: every port is forwarded to {dmz.get('ipaddr')}." if dmz.get("enable") == "on" else "Off."),
        ]
        fwd = [f"{v.get('name')}: {v.get('external_port')} → {v.get('ipaddr')}:{v.get('internal_port')} ({v.get('protocol')})"
               for v in vs if isinstance(v, dict) and v.get("enable") == "on"]
        out.append(chk("forwards", "Port forwards", None, "; ".join(fwd) if fwd else "None."))
        for band, label in (("2g", "2.4 GHz"), ("5g", "5 GHz")):
            w = get(f"admin/wireless?form=wireless_{band}")
            if not w or w.get("enable") != "on":
                continue
            enc, ver = w.get("encryption"), w.get("psk_version")
            weak = enc in ("none", "wep") or ver == "wpa"
            name = {"rsn": "WPA2", "auto": "WPA/WPA2", "sae": "WPA3", "sae_transition": "WPA2/WPA3"}.get(ver, ver or enc)
            out.append(chk(f"wifi_{band}", f"Wi-Fi {label}", not weak,
                           "No password!" if enc == "none" else f"{name}." + (" Weak encryption." if weak else "")))
        return out

    def _apply_audit(self, checks: list[dict]) -> None:
        prev = {c["id"]: c["ok"] for c in (self.audit or [])}
        for c in checks:
            if c["ok"] is False and prev.get(c["id"]) is True:
                self.ctx.emit("security", "warning", f"Router setting changed: {c['title']}", c["detail"], self.host or "")
        self.audit, self.audit_ts = checks, time.time()

    # ---------- reading ----------
    def _fetch(self):
        with self._lock:
            r = self._client()
            try:
                if self.model is None:
                    try:
                        self.model = r.get_firmware().model
                    except Exception:
                        self.model = "unknown"
                rows = r.request("admin/syslog?form=log&operation=load", "operation=load")
                devs = list(getattr(r.get_status(), "devices", []) or [])
                try:
                    self.blocked = [_mac(b.macaddr) for b in r.get_blocked_devices()]
                except Exception:
                    pass
                audit = None
                if not self.audit_ts or time.time() - self.audit_ts > self.ctx.cfg.audit_interval_h * 3600:
                    audit = self._audit(r)
            finally:
                self._logout(r)
        return (rows if isinstance(rows, list) else []), devs, audit

    async def run(self) -> None:
        interval = max(5.0, float(self.settings.get("interval_s") or 10))
        while True:
            if self.host and self.settings.get("password"):
                try:
                    rows, devs, audit = await self.ctx.to_thread(self._fetch)
                    self._handle(rows, devs)
                    if audit is not None:
                        self._apply_audit(audit)
                    self.ok()
                    self._fails = 0
                except Busy as e:
                    # Someone is logged in to the router's web page: don't disturb, wait and retry.
                    self.last_error = str(e)
                    await self.ctx.sleep(max(0, 300 - interval))
                except Exception as e:
                    self._fails += 1
                    self.error(e)
                    if self._fails == 3:
                        self.ctx.emit("system", "warning", "Cannot read the main router log", self.last_error, self.host or "")
            else:
                self.last_error = "Set the password in the module settings"
            await self.ctx.sleep(interval)

    def _handle(self, rows: list, devs: list) -> None:
        # The time of the last stored row survives restarts, so nothing is stored twice.
        db = self.ctx.db
        last = db.get_meta("router_log_last")
        never = last is None
        last = last or ""
        newest = last
        for row in reversed(rows):  # the router lists newest first
            t = str(row.get("time", "")) if isinstance(row, dict) else ""
            text = _row_text(row)
            h = hashlib.sha1(text.encode()).hexdigest()
            if (t and t < last) or h in self.seen:
                continue
            if t == last and self.first:
                self.seen.add(h)
                continue  # may already have been stored before the restart
            self.seen.add(h)
            # The very first time: store the history without alerts.
            self.ctx.add_log(text, self.host, alarm=not never)
            newest = max(newest, t)
        if newest != last:
            db.set_meta("router_log_last", newest)
        if len(self.seen) > 5000:
            self.seen = set(list(self.seen)[-2000:])
        self.first = False
        clients = []
        for d in devs:
            conn = getattr(d, "type", None)
            clients.append({
                "ip": str(getattr(d, "ipaddr", "") or ""), "mac": str(getattr(d, "macaddr", "") or ""),
                "hostname": getattr(d, "hostname", None),
                "down": getattr(d, "down_speed", None), "up": getattr(d, "up_speed", None),
                "usage": getattr(d, "traffic_usage", None), "signal": getattr(d, "signal", None),
                "online_s": getattr(d, "online_time", None), "ssid": getattr(d, "ssid", None),
                "conn": getattr(conn, "value", None) or (str(conn) if conn else None),
            })
        self.ctx.report_clients(clients)

    # ---------- pausing a device ----------
    def block(self, mac: str, on: bool, name: str = "") -> list[str]:
        """Pauses (or resumes) a device's internet with the router's access control (blacklist)."""
        with self._lock:
            r = self._client()
            try:
                if on:
                    ac = r.get_access_control()
                    if ac.enable and ac.mode == "whitelist":
                        raise RuntimeError("The router's access control is in whitelist mode; change it to blacklist first.")
                    if not ac.enable:
                        r.set_access_control(enable=True, mode="blacklist")
                    r.block_device(mac, name)
                else:
                    r.unblock_device(mac)
                self.blocked = [_mac(b.macaddr) for b in r.get_blocked_devices()]
            finally:
                self._logout(r)
        return self.blocked

    def status(self) -> dict:
        return {"host": self.host, "name": self.model if self.model and self.model != "unknown" else None,
                "model": self.model, "log_lines": len(self.seen)}
