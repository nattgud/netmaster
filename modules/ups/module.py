"""UPS through NUT (Network UPS Tools): power cuts, battery level, runtime left and battery health.

NUT speaks a simple text protocol on TCP port 3493. Most NAS boxes (Synology, QNAP), pfSense/OPNsense,
Home Assistant's NUT add-on and any Linux machine with the nut package can share a USB-connected UPS
this way. We only read: no commands are ever sent to the UPS.
"""
from __future__ import annotations

import socket
import time

from netmaster.sdk import ModuleBase, ServiceWatch

# ups.status flags (several at once, e.g. "OB LB"), the most important first
FLAGS = {"FSD": "shutting down", "OB": "on battery", "LB": "battery low", "OFF": "off", "OVER": "overloaded",
         "RB": "replace battery", "BYPASS": "on bypass", "OL": "on mains power", "CHRG": "charging",
         "DISCHRG": "discharging", "HB": "battery high", "CAL": "calibrating", "TRIM": "lowering high mains voltage",
         "BOOST": "raising low mains voltage"}


class NutError(RuntimeError):
    pass


class Nut:
    """A tiny NUT client: one connection per round, read-only commands."""

    def __init__(self, host: str, port: int = 3493, user: str = "", password: str = "", timeout: float = 8):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        if user:
            self._ok(f"USERNAME {user}")
            self._ok(f"PASSWORD {password}")

    def close(self) -> None:
        try:
            self.sock.sendall(b"LOGOUT\n")
        except OSError:
            pass
        self.sock.close()

    def _line(self) -> str:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise NutError("The NUT server closed the connection")
            self.buf += chunk
            if len(self.buf) > 1_000_000:
                raise NutError("Too much data from the NUT server")
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    def _send(self, cmd: str) -> None:
        if any(c in cmd for c in "\r\n"):
            raise ValueError("Invalid characters")
        self.sock.sendall(cmd.encode() + b"\n")

    def _ok(self, cmd: str) -> None:
        self._send(cmd)
        r = self._line()
        if not r.startswith("OK"):
            raise NutError(_err(r))

    def _list(self, what: str) -> list[list[str]]:
        self._send(f"LIST {what}")
        first = self._line()
        if first.startswith("ERR"):
            raise NutError(_err(first))
        if not first.startswith("BEGIN LIST"):
            raise NutError(f"Unexpected answer: {first[:80]}")
        rows = []
        while not (line := self._line()).startswith("END LIST"):
            rows.append(_split(line))
        return rows

    def upses(self) -> dict[str, str]:
        return {r[1]: (r[2] if len(r) > 2 else "") for r in self._list("UPS") if len(r) >= 2}

    def vars(self, ups: str) -> dict[str, str]:
        return {r[2]: (r[3] if len(r) > 3 else "") for r in self._list(f"VAR {_quote(ups)}") if len(r) >= 3}


def _split(line: str) -> list[str]:
    """Words, with "quoted strings" (and \\" inside them) kept together."""
    out, cur, q, esc, started = [], "", False, False, False
    for ch in line:
        if esc:
            cur, esc = cur + ch, False
        elif ch == "\\" and q:
            esc = True
        elif ch == '"':
            q, started = not q, True
        elif ch == " " and not q:
            if cur or started:
                out.append(cur)
            cur, started = "", False
        else:
            cur += ch
    if cur or started:
        out.append(cur)
    return out


def _quote(s: str) -> str:
    return s if s and all(c.isalnum() or c in "-_." for c in s) else '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _err(r: str) -> str:
    code = r[4:].strip() if r.startswith("ERR") else r
    return {"ACCESS-DENIED": "Access denied: wrong username or password, or this computer's IP is not allowed",
            "UNKNOWN-UPS": "No UPS with that name on the NUT server",
            "DATA-STALE": "The NUT server has lost contact with the UPS (check the USB cable)",
            "DRIVER-NOT-CONNECTED": "The NUT server has no contact with the UPS (check the USB cable)",
            "INVALID-USERNAME": "Invalid username", "INVALID-PASSWORD": "Wrong password",
            "USERNAME-REQUIRED": "The NUT server wants a username",
            "PASSWORD-REQUIRED": "The NUT server wants a password"}.get(code.split()[0] if code else "", f"NUT error: {code}")


def _num(v: str | None) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def fmt_min(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    m = round(seconds / 60)
    return f"{m} min" if m < 120 else f"{m // 60} h {m % 60} min"


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.host = (settings.get("host") or "").strip()
        try:
            self.port = int(float(settings.get("port") or 3493))
        except ValueError:
            self.port = 3493
        self.upses: dict[str, dict] = {}       # name -> {"desc", "vars", "flags", "checked"}
        self.state: dict[str, dict] = {}       # name -> what we already alerted about
        self.watch = ServiceWatch(ctx, "UPS server (NUT)", f"nut://{self.host}:{self.port}")
        self._on_battery_since: dict[str, float] = {}

    def _read(self) -> dict[str, dict]:
        nut = Nut(self.host, self.port, (self.settings.get("username") or "").strip(), self.settings.get("password") or "")
        try:
            want = (self.settings.get("ups") or "").strip()
            names = {want: ""} if want else nut.upses()
            if not names:
                raise NutError("The NUT server has no UPS configured")
            out = {}
            for name, desc in names.items():
                try:
                    v = nut.vars(name)
                    out[name] = {"desc": desc, "vars": v, "flags": set((v.get("ups.status") or "").split()), "error": None}
                except NutError as e:
                    if want:
                        raise
                    out[name] = {"desc": desc, "vars": {}, "flags": set(), "error": str(e)}
            return out
        finally:
            nut.close()

    def _label(self, name: str, u: dict) -> str:
        v = u["vars"]
        model = " ".join(x for x in (v.get("device.mfr") or v.get("ups.mfr"), v.get("device.model") or v.get("ups.model")) if x).strip()
        if not model:
            return f"UPS {name}"
        return f"UPS {model}" + (f" ({name})" if len(self.upses) > 1 else "")

    def _alerts(self, name: str, u: dict) -> None:
        if u["error"] or not u["vars"]:
            return
        st = self.state.setdefault(name, {"ob": None, "lb": False, "rb": False, "over": False, "low_rt": False})
        f, v, label = u["flags"], u["vars"], self._label(name, u)
        charge, runtime = _num(v.get("battery.charge")), _num(v.get("battery.runtime"))
        info = " · ".join(x for x in (f"battery {charge:.0f}%" if charge is not None else "",
                                      f"about {fmt_min(runtime)} left" if runtime is not None else "",
                                      f"load {v['ups.load']}%" if v.get("ups.load") else "") if x)
        ob = "OB" in f
        if ob and not st["ob"]:
            st["ob"] = True
            self._on_battery_since[name] = time.time()
            self.ctx.emit("disruption", "critical", f"{label} is running on battery",
                          "The power is out (or the UPS lost mains power). " + info, f"ups:{name}", kind="ups_on_battery")
        elif not ob and st["ob"] and "OL" in f:
            st["ob"] = False
            dur = time.time() - self._on_battery_since.pop(name, time.time())
            self.ctx.emit("disruption", "info", f"Power is back on {label}",
                          f"It ran on battery for {fmt_min(dur)}. " + info, f"ups:{name}", kind="ups_power_back")
        try:
            limit = float(self.settings.get("low_runtime_min") or 10) * 60
        except ValueError:
            limit = 600.0
        low_rt = runtime is not None and ob and runtime < limit
        lb = "LB" in f
        if (lb or low_rt) and not (st["lb"] or st["low_rt"]):
            self.ctx.emit("disruption", "critical", f"{label} battery is almost empty",
                          f"{info}. Devices on the UPS will soon lose power; shut down what you can.", f"ups:{name}",
                          kind="ups_battery_low")
        st["lb"], st["low_rt"] = lb, low_rt
        for flag, key, sev, title, detail, kind in (
                ("RB", "rb", "warning", f"{label} battery needs replacing",
                 "The UPS reports that its battery is worn out. It may not last through a power cut.", "ups_replace_battery"),
                ("OVER", "over", "warning", f"{label} is overloaded",
                 "More equipment is connected than the UPS can carry. Move something to a normal outlet.", "ups_overload")):
            if flag in f and not st[key]:
                self.ctx.emit("disruption", sev, title, detail + (f" ({info})" if info else ""), f"ups:{name}", kind=kind)
            st[key] = flag in f

    def _record(self, name: str, u: dict) -> None:
        """History for the graphs in the module's card."""
        v, many = u["vars"], len(self.upses) > 1
        for var, key, label, unit, scale in (("battery.charge", "charge", "Battery charge", "%", 1),
                                             ("battery.runtime", "runtime", "Runtime on battery", "min", 1 / 60),
                                             ("ups.load", "load", "Load", "%", 1),
                                             ("input.voltage", "voltage", "Mains voltage", "V", 1)):
            if (x := _num(v.get(var))) is not None:
                self.ctx.record(f"{name}.{key}" if many else key, x * scale, f"{label} ({name})" if many else label, unit)

    def device_info(self, mac: str, ip: str | None) -> list[dict] | None:
        """Shown on the device the UPS is connected to (the NUT server, often a NAS)."""
        if not ip or ip != self._host_ip():
            return None
        return [{"label": self._label(n, u), "value": self._summary(u), "state": self._state(u)} for n, u in self.upses.items()]

    def _host_ip(self) -> str | None:
        if not hasattr(self, "_ip"):
            try:
                self._ip = socket.gethostbyname(self.host) if self.host else None
            except OSError:
                return None
        return self._ip

    async def run(self) -> None:
        while True:
            if not self.host:
                self.last_error = "Set the NUT server address in the module settings"
            else:
                data: dict = {}
                ok = await self.watch.check(lambda: data.update(self._read_into()))
                if ok:
                    self.upses = data
                    for name, u in list(self.upses.items()):
                        try:
                            self._alerts(name, u)
                            self._record(name, u)
                        except Exception:
                            self.ctx.log.exception("UPS alert check failed")
                    errs = [u["error"] for u in self.upses.values() if u["error"]]
                    if errs and len(errs) == len(self.upses):
                        self.error(errs[0])
                    else:
                        self.ok()
                else:
                    self.error(self.watch.error or "No answer from the NUT server")
            try:
                s = max(5.0, float(self.settings.get("interval_s") or 15))
            except ValueError:
                s = 15.0
            await self.ctx.sleep(s)

    def _read_into(self) -> dict[str, dict]:
        data = self._read()
        now = time.time()
        for u in data.values():
            u["checked"] = now
        return data

    async def action(self, action_id: str, value: str | None = None) -> str:
        if action_id != "check":
            raise ValueError("This module has no such action")
        if not self.host:
            raise ValueError("Set the NUT server address first")
        self.upses = await self.ctx.to_thread(self._read_into)
        self.ok()
        return " | ".join(f"{self._label(n, u)}: {self._summary(u)}" for n, u in self.upses.items())

    # ---------- UI ----------
    def _summary(self, u: dict) -> str:
        if u["error"]:
            return u["error"]
        v, f = u["vars"], u["flags"]
        parts = [FLAGS.get(x, x) for x in sorted(f, key=lambda x: list(FLAGS).index(x) if x in FLAGS else 99)] or ["unknown state"]
        if (c := _num(v.get("battery.charge"))) is not None:
            parts.append(f"battery {c:.0f}%")
        if (r := _num(v.get("battery.runtime"))) is not None:
            parts.append(f"runtime {fmt_min(r)}")
        if v.get("ups.load"):
            parts.append(f"load {v['ups.load']}%")
        if v.get("input.voltage"):
            parts.append(f"{v['input.voltage']} V in")
        return " · ".join(parts)

    @staticmethod
    def _state(u: dict) -> str:
        f = u["flags"]
        if u["error"] or not f:
            return "degraded"
        if "OB" in f or "LB" in f or "FSD" in f or "OFF" in f:
            return "down"
        if "RB" in f or "OVER" in f or "BYPASS" in f:
            return "degraded"
        return "up"

    def status(self) -> dict:
        rows = [{"label": "🔋 " + self._label(n, u), "value": self._summary(u), "state": self._state(u)}
                for n, u in self.upses.items()]
        services = [self.watch.status()] if self.watch.state == "down" else []
        for n, u in self.upses.items():
            st = self._state(u)
            if st != "up":
                summ = self._summary(u).split(" · ")
                services.append({"name": self._label(n, u), "url": f"nut://{self.host}/{n}", "state": st,
                                 "value": summ[0], "detail": " · ".join(summ[1:]), "since": self._on_battery_since.get(n),
                                 "ms": None, "error": u["error"]})
        return {"rows": rows, "services": services, "host": self.host}
