"""The module marketplace: installs, configures and runs modules (see sdk.py for how to write one).

Modules come from the module source: a folder with index.json and one sub-folder per module,
normally the modules/ folder of the NetMaster repository on GitHub. Nothing is installed by
default; the user picks modules in the app. Installed modules live in data/modules/<id>. Settings are in data/modules.json, passwords in
data/secrets.json (never sent back to the browser).
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import logging
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .config import DATA_DIR, load_settings
from .sdk import Busy, Context, ModuleBase

log = logging.getLogger("netmaster.modules")

INSTALLED = DATA_DIR / "modules"
STATE_FILE = DATA_DIR / "modules.json"
SECRETS_FILE = DATA_DIR / "secrets.json"
ID_RX = re.compile(r"^[a-z0-9_]{1,40}$")
FILE_RX = re.compile(r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9]+)?$")
TYPES = ("text", "password", "number", "bool")


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
    tmp.replace(path)


def _fetch(url: str, limit: int = 2_000_000) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "NetMaster"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File too large")
    return data


def _ver(v) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in str(v).split("."))


def validate_meta(meta: dict) -> dict:
    """Checks a module.json and fills in defaults."""
    if not isinstance(meta, dict) or not ID_RX.match(str(meta.get("id", ""))):
        raise ValueError("module.json needs an id (lowercase letters, digits, _)")
    meta.setdefault("name", meta["id"])
    meta.setdefault("version", "0")
    meta.setdefault("description", "")
    meta.setdefault("provides", [])
    meta.setdefault("requires", [])
    meta.setdefault("files", ["module.py"])
    meta.setdefault("settings", [])
    meta.setdefault("actions", [])
    for f in meta["files"]:
        if not FILE_RX.match(str(f)):
            raise ValueError(f"Invalid file name in module.json: {f}")
    for s in meta["settings"]:
        if not s.get("key") or s.get("type", "text") not in TYPES:
            raise ValueError(f"Invalid setting in module.json: {s}")
    for a in meta["actions"]:
        if not isinstance(a, dict) or not ID_RX.match(str(a.get("id", ""))) or not a.get("label"):
            raise ValueError(f"Invalid action in module.json: {a}")
    return meta


class ModuleManager:
    def __init__(self, cfg, db, events, syslog, inventory, net, local_ip=lambda: None):
        self.cfg, self.db, self.events, self.syslog, self.inventory, self.net = cfg, db, events, syslog, inventory, net
        self.local_ip = local_ip
        self.usage = self.wifi = None       # insights.Usage / WifiWatch, set by app
        self.pause_fn = None                # async (mac, paused, via) -> bool, set by app
        self.protected_fn = lambda: {}      # {mac: reason} for devices that must never be paused, set by app
        self.instances: dict[str, ModuleBase] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.load_errors: dict[str, str] = {}
        self.traffic: dict[str, dict] = {}
        self.traffic_ts: float | None = None
        self._remote: tuple[float, list] | None = None
        self.source_error: str | None = None
        self.jobs: dict[str, dict] = {}
        self._migrate_legacy()

    # ---------- stored state ----------
    def _state(self) -> dict:
        return _read_json(STATE_FILE, {})

    def _secrets(self) -> dict:
        return _read_json(SECRETS_FILE, {})

    def installed(self) -> dict[str, dict]:
        out = {}
        if INSTALLED.is_dir():
            for d in sorted(INSTALLED.iterdir()):
                try:
                    out[d.name] = validate_meta(json.loads((d / "module.json").read_text("utf-8")))
                except (OSError, ValueError) as e:
                    self.load_errors[d.name] = f"Broken module.json: {e}"
        return out

    def settings_for(self, mid: str, meta: dict) -> dict:
        stored = self._state().get(mid, {}).get("settings", {})
        secrets = self._secrets().get(mid, {})
        out = {}
        for s in meta["settings"]:
            v = secrets.get(s["key"]) if s.get("type") == "password" else stored.get(s["key"])
            out[s["key"]] = s.get("default", "" if s.get("type") != "bool" else False) if v is None else v
        return out

    # ---------- running ----------
    def _load_class(self, mid: str):
        path = INSTALLED / mid / "module.py"
        spec = importlib.util.spec_from_file_location(f"netmaster_module_{mid}", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        cls = getattr(mod, "Module", None)
        if not (isinstance(cls, type) and issubclass(cls, ModuleBase)):
            raise TypeError("module.py has no class Module(ModuleBase)")
        return cls

    def start(self, mid: str) -> None:
        self.stop(mid)
        meta = self.installed().get(mid)
        if not meta or not self._state().get(mid, {}).get("enabled"):
            return
        try:
            cls = self._load_class(mid)
            data_dir = DATA_DIR / "module-data" / mid
            data_dir.mkdir(parents=True, exist_ok=True)
            inst = cls(Context(self, mid, data_dir), self.settings_for(mid, meta), meta)
        except Exception as e:
            log.exception("Module %s could not be loaded", mid)
            self.load_errors[mid] = f"{type(e).__name__}: {e}"[:300]
            return
        self.load_errors.pop(mid, None)
        self.instances[mid] = inst
        self.tasks[mid] = asyncio.create_task(self._guard(mid, inst))

    async def _guard(self, mid: str, inst: ModuleBase) -> None:
        """Runs a module and restarts it after a crash, so one bad module never takes NetMaster down."""
        while True:
            try:
                await inst.run()
                return
            except asyncio.CancelledError:
                raise
            except Busy as e:
                inst.last_error = str(e) or "Busy: someone is logged in to the device's web page"
                await asyncio.sleep(300)
            except Exception as e:
                log.exception("Module %s crashed", mid)
                inst.error(e)
                await asyncio.sleep(60)

    def stop(self, mid: str) -> None:
        if t := self.tasks.pop(mid, None):
            t.cancel()
        if inst := self.instances.pop(mid, None):
            try:
                inst.ctx._close()
                inst.stop()
            except Exception:
                log.exception("Module %s failed to stop", mid)
            if "router" in inst.meta.get("provides", []):
                self.traffic = {}

    def start_all(self) -> None:
        for mid in self.installed():
            self.start(mid)

    def stop_all(self) -> None:
        for mid in list(self.instances):
            self.stop(mid)

    # ---------- capabilities ----------
    def provider(self, what: str) -> ModuleBase | None:
        return next((m for m in self.instances.values() if what in m.meta.get("provides", [])), None)

    @property
    def public_ip(self) -> str | None:
        r = self.provider("router")
        return getattr(r, "public_ip", None) if r else None

    def report_clients(self, mid: str, clients: list[dict]) -> None:
        traffic = {}
        for c in clients:
            ip, mac = c.get("ip"), str(c.get("mac") or "").lower().replace("-", ":")
            if not ip or not mac:
                continue
            self.inventory.observe_dhcp(str(ip), mac, c.get("hostname"))
            traffic[mac] = {k: c.get(k) for k in ("down", "up", "usage", "signal", "online_s", "ssid", "conn")}
        self.traffic, self.traffic_ts = traffic, time.time()
        for sink in (self.usage, self.wifi):
            if sink:
                sink.record(traffic)

    def load_mbps(self) -> float:
        return sum((t.get("down") or 0) + (t.get("up") or 0) for t in self.traffic.values()) * 8 / 1e6

    def router_status(self) -> dict:
        r = self.provider("router")
        if not r:
            return {"enabled": False, "traffic": {}, "blocked": [], "audit": None}
        st = r.status()
        return {**st, "enabled": True, "module": r.meta["id"], "name": st.get("name") or r.meta["name"],
                "last_ok": r.last_ok, "last_error": r.last_error, "clients": len(self.traffic),
                "traffic": self.traffic, "blocked": list(getattr(r, "blocked", []) or []),
                "audit": getattr(r, "audit", None), "audit_ts": getattr(r, "audit_ts", None),
                "public_ip": getattr(r, "public_ip", None), "can_block": hasattr(r, "block")}

    def dns_status(self) -> dict:
        d = self.provider("dns")
        if not d:
            return {"enabled": False}
        return {**d.status(), "enabled": True, "module": d.meta["id"], "name": d.meta["name"],
                "last_ok": d.last_ok, "last_error": d.last_error, "can_edit_rules": hasattr(d, "add_rule")}

    def protected(self) -> dict[str, str]:
        """IP = reason, for devices modules say must never be paused (e.g. the DNS filter's server)."""
        out = {}
        for m in self.instances.values():
            if hasattr(m, "protect"):
                try:
                    out.update(m.protect())
                except Exception:
                    pass
        return out

    def services(self) -> list[dict]:
        """Service checks done by modules, shown together with the built-in ones."""
        out = []
        for m in self.instances.values():
            try:
                if svc := m.status().get("service"):
                    out.append(svc)
            except Exception:
                pass
        return out

    def status(self) -> list[dict]:
        state, out = self._state(), []
        for mid, meta in self.installed().items():
            inst = self.instances.get(mid)
            extra = {}
            if inst:
                try:
                    extra = inst.status()
                except Exception as e:
                    extra = {"error": str(e)}
            out.append({"id": mid, "name": meta["name"], "version": meta["version"], "provides": meta["provides"],
                        "enabled": bool(state.get(mid, {}).get("enabled")), "running": mid in self.tasks,
                        "last_ok": inst.last_ok if inst else None,
                        "last_error": (inst.last_error if inst else None) or self.load_errors.get(mid),
                        "host": extra.get("host"), "label": extra.get("name")})
        return out

    # ---------- marketplace / install ----------
    def _source_get(self, rel: str, limit: int = 2_000_000) -> bytes:
        """A file from the module source: an https:// URL or a local folder (handy when writing modules)."""
        src = (self.cfg.module_source or "").strip().rstrip("/")
        if src.startswith("https://") or src.startswith("http://localhost") or src.startswith("http://127.0.0.1"):
            return _fetch(f"{src}/{rel}", limit)
        if src.startswith("http://"):
            raise ValueError("The module source must use https://")
        path = Path(src).expanduser().resolve() / rel
        if not path.is_file():
            raise FileNotFoundError(rel)
        data = path.read_bytes()
        if len(data) > limit:
            raise ValueError("File too large")
        return data

    def _index(self, force: bool = False) -> list[dict]:
        if self._remote and not force and time.time() - self._remote[0] < 600:
            return self._remote[1]
        items, self.source_error = [], None
        try:
            idx = json.loads(self._source_get("index.json"))
            for m in idx.get("modules", []):
                try:
                    items.append(validate_meta(dict(m)))
                except ValueError:
                    pass
        except Exception as e:
            self.source_error = f"The marketplace is not reachable: {e}"[:200]
            log.info("%s", self.source_error)
        self._remote = (time.time(), items)
        return items

    def catalog(self, refresh: bool = False) -> list[dict]:
        """Every module in the marketplace, plus the ones that are installed."""
        found = {m["id"]: m for m in self._index(refresh)}
        state, inst = self._state(), self.installed()
        for mid, meta in inst.items():
            found.setdefault(mid, meta)
        out = []
        for mid, m in sorted(found.items(), key=lambda kv: kv[1]["name"].lower()):
            meta = inst.get(mid, m)
            values = self.settings_for(mid, meta) if mid in inst else {}
            secrets = self._secrets().get(mid, {})
            out.append({
                "id": mid, "name": m["name"], "description": m["description"], "author": m.get("author", ""),
                "available_version": m["version"] if mid in {x["id"] for x in self._index()} else None,
                "installed_version": inst[mid]["version"] if mid in inst else None,
                "update": mid in inst and _ver(m["version"]) > _ver(inst[mid]["version"]),
                "provides": m["provides"], "requires": m["requires"],
                "enabled": bool(state.get(mid, {}).get("enabled")),
                "settings": [s | {"value": "" if s.get("type") == "password" else values.get(s["key"], s.get("default")),
                                  "is_set": bool(secrets.get(s["key"])) if s.get("type") == "password" else None}
                             for s in meta["settings"]],
                "actions": [a | {"options": self._options(mid, a["id"])} for a in meta.get("actions", [])]
                if mid in inst else [],
            })
        return out

    def _options(self, mid: str, aid: str) -> list[dict] | None:
        inst = self.instances.get(mid)
        try:
            return inst.action_options(aid) if inst else None
        except Exception as e:
            log.warning("Module %s action options: %s", mid, e)
            return None

    async def run_action(self, mid: str, aid: str, value: str | None) -> str:
        """Runs a module's button. The module must be running."""
        inst = self.instances.get(mid)
        if not inst:
            raise ValueError("Turn the module on first")
        if aid not in {a["id"] for a in inst.meta.get("actions", [])}:
            raise ValueError("Unknown action")
        return str(await inst.action(aid, value) or "Done")

    def install(self, mid: str, progress=lambda pct, step: None) -> dict:
        """Downloads a module from the marketplace and installs its requirements. Blocking: run in a thread.
        progress(percent, text) is called along the way."""
        if not ID_RX.match(mid):
            raise ValueError("Invalid module id")
        progress(2, "Looking up the module")
        entry = next((m for m in self._index(force=True) if m["id"] == mid), None)
        if not entry:
            raise ValueError("The module is not in the marketplace" + (f" ({self.source_error})" if self.source_error else ""))
        tmp = INSTALLED / f".{mid}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        try:
            progress(5, "Downloading")
            meta = validate_meta(json.loads(self._source_get(f"{mid}/module.json")))
            if meta["id"] != mid:
                raise ValueError("module.json id does not match")
            (tmp / "module.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), "utf-8")
            hashes = entry.get("sha256") or {}
            for i, f in enumerate(meta["files"]):
                data = self._source_get(f"{mid}/{f}")
                if f in hashes and hashlib.sha256(data).hexdigest() != hashes[f]:
                    raise ValueError(f"Checksum mismatch for {f}")
                (tmp / f).write_bytes(data)
                progress(5 + 25 * (i + 1) / len(meta["files"]), f"Downloaded {f}")
            if meta["requires"]:
                self._pip(meta["requires"], progress)
            progress(97, "Finishing")
            dest = INSTALLED / mid
            shutil.rmtree(dest, ignore_errors=True)
            tmp.replace(dest)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        progress(100, "Installed")
        log.info("Installed module %s %s", mid, meta["version"])
        return meta

    @staticmethod
    def _pip(requires: list[str], progress) -> None:
        """pip install, with a rough progress estimate from its output (30% -> 95%)."""
        progress(30, "Installing requirements: " + ", ".join(requires))
        p = subprocess.Popen([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--progress-bar", "off",
                              *requires], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        pct, tail = 30.0, []
        for line in p.stdout:
            line = line.strip()
            tail = (tail + [line])[-8:]
            if line.startswith(("Collecting", "Downloading", "Requirement already satisfied", "Installing", "Building", "Successfully")):
                pct += (95 - pct) * 0.2
                progress(pct, line[:120])
        if p.wait(timeout=900) != 0:
            raise RuntimeError("Could not install requirements: " + " | ".join(tail)[-400:])

    def start_install(self, mid: str) -> None:
        """Runs install() in the background; follow it in self.jobs[mid]."""
        if self.jobs.get(mid, {}).get("running"):
            return
        job = self.jobs[mid] = {"running": True, "pct": 0, "step": "Starting", "error": None}

        def progress(pct, step):
            job["pct"], job["step"] = round(pct), step

        async def go():
            try:
                await asyncio.to_thread(self.install, mid, progress)
                if mid in self.instances or self._state().get(mid, {}).get("enabled"):
                    self.start(mid)  # an update: restart with the new code
            except Exception as e:
                job["error"] = str(e)[:400]
            finally:
                job["running"] = False
        asyncio.create_task(go())

    def uninstall(self, mid: str) -> None:
        self.stop(mid)
        if ID_RX.match(mid):
            shutil.rmtree(INSTALLED / mid, ignore_errors=True)
        state, secrets = self._state(), self._secrets()
        state.pop(mid, None)
        secrets.pop(mid, None)
        _write_json(STATE_FILE, state)
        _write_json(SECRETS_FILE, secrets)

    def configure(self, mid: str, settings: dict | None = None, enabled: bool | None = None) -> None:
        meta = self.installed().get(mid)
        if not meta:
            raise ValueError("Module is not installed")
        state, secrets = self._state(), self._secrets()
        entry = state.setdefault(mid, {"enabled": False, "settings": {}})
        for s in meta["settings"]:
            if settings is None or s["key"] not in settings:
                continue
            v, t = settings[s["key"]], s.get("type", "text")
            if t == "password":
                if v:  # empty = keep the stored password
                    secrets.setdefault(mid, {})[s["key"]] = str(v)
                continue
            try:
                v = bool(v) if t == "bool" else float(v) if t == "number" else str(v).strip()
            except (TypeError, ValueError):
                raise ValueError(f"Invalid value for {s.get('label', s['key'])}") from None
            entry["settings"][s["key"]] = v
        if enabled is not None:
            entry["enabled"] = bool(enabled)
        _write_json(STATE_FILE, state)
        _write_json(SECRETS_FILE, secrets)
        self.start(mid)

    # ---------- older versions ----------
    def _migrate_legacy(self) -> None:
        """Older versions had the TP-Link, NETGEAR and AdGuard support built in, with passwords in
        data/*_password.txt. Turn those into installed, configured modules (once)."""
        if STATE_FILE.exists():
            return
        legacy = load_settings().get("_legacy", {})

        def secret(name: str) -> str:
            p = DATA_DIR / name
            return p.read_text("utf-8-sig").strip() if p.is_file() else ""
        plan = []
        if pw := secret("router_password.txt"):
            ra = legacy.get("router_api", {})
            plan.append(("tplink_router", {"host": ra.get("host") or "", "username": ra.get("username") or "admin",
                                           "interval_s": ra.get("interval_s") or 10}, {"password": pw}))
        if pw := secret("netgear_password.txt"):
            plan.append(("netgear_log", {"host": self.cfg.uplink or "", "username": "admin"}, {"password": pw}))
        url = legacy.get("adguard", {}).get("url")
        if not url and (ha := self.cfg.services.get("Home Assistant")):  # older versions guessed the add-on's address
            from urllib.parse import urlparse
            url = f"https://{urlparse(ha).hostname}:3000"
        if (pw := secret("adguard_password.txt")) and url:
            plan.append(("adguard", {"url": url, "username": secret("adguard_user.txt"), "verify_tls": False},
                         {"password": pw}))
        # Services that now have their own module
        from urllib.parse import urlparse
        moved = []
        for name, mid, key in (("Home Assistant", "home_assistant", "token"), ("Jellyfin", "jellyfin", "api_key")):
            if url := self.cfg.services.get(name):
                u = urlparse(url)
                plan.append((mid, {"url": f"{u.scheme}://{u.netloc}"}, {}))
                moved.append(name)
        state, secrets = {}, {}
        for mid, settings, secs in plan:
            try:
                self.install(mid)
            except Exception as e:
                # Try again at the next start (e.g. the marketplace was not reachable).
                log.warning("Could not migrate %s, will retry at next start: %s", mid, e)
                return
            state[mid] = {"enabled": True, "settings": settings}
            secrets[mid] = secs
        if moved:  # the modules check these now; don't alert twice
            from .config import save_settings
            save_settings({"services": {k: v for k, v in self.cfg.services.items() if k not in moved}})
            self.cfg.services = {k: v for k, v in self.cfg.services.items() if k not in moved}
        _write_json(SECRETS_FILE, secrets)
        _write_json(STATE_FILE, state)
        if plan:
            log.info("Migrated built-in integrations to modules: %s", ", ".join(state))
