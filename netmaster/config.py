"""Settings.

All settings live in data/settings.json and are edited from the web UI (Settings tab).
Every setting has a sensible default, so a fresh install works without any file at all.
Older installs used config.toml; it is imported automatically on first start.
"""
from __future__ import annotations

import json
import logging
import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

log = logging.getLogger("netmaster.config")

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
DATA_DIR = Path(os.environ.get("NETMASTER_DATA", ROOT / "data"))
SETTINGS_FILE = DATA_DIR / "settings.json"


@dataclass
class Config:
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    https_cert: str = ""   # optional: certificate and key files for HTTPS without a proxy
    https_key: str = ""

    ping_interval: float = 5.0
    ping_timeout_ms: int = 1000
    latency_warn_ms: float = 100.0
    loss_warn_pct: float = 10.0
    window: int = 60
    gateway: str | None = None
    uplink: str | None = None  # the access point/switch the server is connected through
    internet_targets: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])

    dns_servers: list[str] = field(default_factory=lambda: ["auto", "1.1.1.1"])
    dns_names: list[str] = field(default_factory=lambda: ["google.com", "microsoft.com", "wikipedia.org"])
    dns_interval: float = 30.0
    dns_latency_warn_ms: float = 500.0

    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5140

    db_path: Path = DATA_DIR / "netmaster.db"
    sample_retention_days: int = 7
    syslog_retention_days: int = 30

    # Routers and access points: IP = name. Used to name log sources and to check that each one answers.
    routers: dict[str, str] = field(default_factory=dict)

    lan_cidr: str = "auto"
    arp_poll_s: float = 10.0
    sweep_interval_s: float = 300.0
    baseline_minutes: int = 30
    dhcp_check_interval_s: float = 600.0
    dhcp_servers: list[str] = field(default_factory=list)  # empty = the gateway
    dns_check_interval_s: float = 600.0

    push_contact: str = "mailto:netmaster@example.org"

    speedtest_interval_min: float = 10.0
    portscan_interval_h: float = 6.0
    audit_interval_h: float = 6.0
    expected_public_ports: list[int] = field(default_factory=list)  # open to the internet on purpose
    # Important services to monitor: name = URL
    services: dict[str, str] = field(default_factory=dict)
    # Devices whose internet can never be paused: IP = reason
    protect: dict[str, str] = field(default_factory=dict)

    # Where modules are downloaded from (a folder with index.json)
    module_source: str = "https://raw.githubusercontent.com/nattgud/netmaster/main/modules"


# What the Settings tab shows. type: str, int, float, list (of str), ports (list of int), map (key = value)
SETTINGS: list[dict] = [
    {"key": "gateway", "section": "Network", "label": "Main router IP", "type": "str",
     "help": "Leave empty to detect it automatically."},
    {"key": "uplink", "section": "Network", "label": "Device the server is connected through", "type": "str",
     "help": "Optional. The access point or switch between this computer and the main router. "
             "Lets NetMaster tell a broken cable apart from a router that is down."},
    {"key": "lan_cidr", "section": "Network", "label": "Network range", "type": "str",
     "help": "\"auto\" or for example 192.168.0.0/24."},
    {"key": "internet_targets", "section": "Network", "label": "Internet test addresses", "type": "list",
     "help": "Pinged to see whether the internet works."},
    {"key": "dns_servers", "section": "Network", "label": "DNS servers to test", "type": "list",
     "help": "\"auto\" = the router's DNS."},
    {"key": "dns_names", "section": "Network", "label": "Names to look up in DNS tests", "type": "list"},
    {"key": "routers", "section": "Network", "label": "Routers and access points", "type": "map",
     "key_label": "IP address", "value_label": "Name",
     "help": "Each one is pinged and alerts when it stops answering. The name is also used for its logs."},
    {"key": "services", "section": "Monitoring", "label": "Services to monitor", "type": "map",
     "key_label": "Name", "value_label": "URL",
     "help": "Checked every 30 s. You get an alert when one stops answering."},
    {"key": "protect", "section": "Monitoring", "label": "Devices that can never be paused", "type": "map",
     "key_label": "IP address", "value_label": "Reason",
     "help": "This computer and the main router are always protected."},
    {"key": "expected_public_ports", "section": "Monitoring", "label": "Ports open to the internet on purpose", "type": "ports",
     "help": "No alert for these ports in the internet exposure check."},
    {"key": "dhcp_servers", "section": "Monitoring", "label": "Allowed DHCP servers", "type": "list",
     "help": "Empty = only the main router."},
    {"key": "latency_warn_ms", "section": "Thresholds", "label": "Slow response above (ms)", "type": "float"},
    {"key": "loss_warn_pct", "section": "Thresholds", "label": "Packet loss alert above (%)", "type": "float"},
    {"key": "dns_latency_warn_ms", "section": "Thresholds", "label": "Slow DNS above (ms)", "type": "float"},
    {"key": "ping_interval", "section": "Thresholds", "label": "Ping every (seconds)", "type": "float"},
    {"key": "speedtest_interval_min", "section": "Thresholds", "label": "Speed test every (minutes)", "type": "float"},
    {"key": "portscan_interval_h", "section": "Thresholds", "label": "Port scan every (hours)", "type": "float"},
    {"key": "audit_interval_h", "section": "Thresholds", "label": "Router security check every (hours)", "type": "float"},
    {"key": "baseline_minutes", "section": "Thresholds", "label": "Learning period at first start (minutes)", "type": "int",
     "help": "Devices seen during this time count as known."},
    {"key": "sample_retention_days", "section": "Storage", "label": "Keep measurements (days)", "type": "int"},
    {"key": "syslog_retention_days", "section": "Storage", "label": "Keep router logs (days)", "type": "int"},
    {"key": "http_host", "section": "Server", "label": "Listen on address", "type": "str", "restart": True,
     "help": "127.0.0.1 = only this computer (reach it from other devices with Tailscale or a reverse proxy). "
             "0.0.0.0 = every device on your home network."},
    {"key": "http_port", "section": "Server", "label": "Web port", "type": "int", "restart": True},
    {"key": "https_cert", "section": "Server", "label": "HTTPS certificate file", "type": "str", "restart": True,
     "help": "Optional. Path to a certificate (PEM). Not needed with Tailscale or a reverse proxy."},
    {"key": "https_key", "section": "Server", "label": "HTTPS key file", "type": "str", "restart": True},
    {"key": "syslog_port", "section": "Server", "label": "Syslog port (UDP)", "type": "int", "restart": True,
     "help": "Routers can send their logs here."},
    {"key": "push_contact", "section": "Server", "label": "Contact for push services", "type": "str",
     "help": "A mailto: or https: address. Push services use it if something goes wrong."},
    {"key": "module_source", "section": "Server", "label": "Module source", "type": "str",
     "help": "Folder (URL) with index.json that modules are downloaded from."},
]
_TYPES = {f.name: f for f in fields(Config)}


def _coerce(spec_type: str, value):
    if spec_type == "int":
        return int(value)
    if spec_type == "float":
        return float(value)
    if spec_type == "list":
        return [str(v).strip() for v in value if str(v).strip()]
    if spec_type == "ports":
        return sorted({int(v) for v in value if str(v).strip()})
    if spec_type == "map":
        return {str(k).strip(): str(v).strip() for k, v in dict(value).items() if str(k).strip()}
    value = "" if value is None else str(value).strip()
    return value


def load_settings() -> dict:
    """Stored settings (only the ones that differ from the defaults)."""
    if not SETTINGS_FILE.exists():
        _import_legacy_toml()
    try:
        return json.loads(SETTINGS_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(changes: dict) -> dict:
    """Validates and stores changes from the Settings tab. Returns the stored settings."""
    specs = {s["key"]: s for s in SETTINGS}
    data = load_settings()
    for key, value in changes.items():
        if key not in specs:
            raise ValueError(f"Unknown setting: {key}")
        try:
            data[key] = _coerce(specs[key]["type"], value)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid value for {specs[key]['label']}") from None
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
    tmp.replace(SETTINGS_FILE)
    return data


def settings_view(cfg: Config) -> dict:
    """Settings with current values, for the Settings tab."""
    return {"fields": [s | {"value": getattr(cfg, s["key"])} for s in SETTINGS]}


def load_config() -> Config:
    cfg = Config()
    for key, value in load_settings().items():
        if key in _TYPES and key != "db_path":
            setattr(cfg, key, value if value != "" else _TYPES[key].default)
    cfg.gateway = cfg.gateway or None
    cfg.uplink = cfg.uplink or None
    return cfg


# ---------- import from config.toml (older versions) ----------
def _import_legacy_toml() -> None:
    path = next((p for p in (Path(os.environ.get("NETMASTER_CONFIG", "")), DATA_DIR / "config.toml", ROOT / "config.toml")
                 if str(p) and p.is_file()), None)
    if path is None:
        return
    try:
        d = tomllib.loads(path.read_text("utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        log.warning("Could not read %s: %s", path, e)
        return
    srv, mon, dns, sl = d.get("server", {}), d.get("monitor", {}), d.get("dns", {}), d.get("syslog", {})
    st, sec, push, ins = d.get("storage", {}), d.get("security", {}), d.get("push", {}), d.get("insights", {})
    pick = {
        "http_host": srv.get("host"), "http_port": srv.get("port"),
        "ping_interval": mon.get("interval_s"), "ping_timeout_ms": mon.get("timeout_ms"),
        "latency_warn_ms": mon.get("latency_warn_ms"), "loss_warn_pct": mon.get("loss_warn_pct"),
        "gateway": mon.get("gateway"), "uplink": mon.get("uplink"), "internet_targets": mon.get("internet_targets"),
        "dns_servers": dns.get("servers"), "dns_names": dns.get("names"), "dns_interval": dns.get("interval_s"),
        "dns_latency_warn_ms": dns.get("latency_warn_ms"),
        "syslog_host": sl.get("host"), "syslog_port": sl.get("port"),
        "sample_retention_days": st.get("sample_retention_days"), "syslog_retention_days": st.get("syslog_retention_days"),
        "routers": d.get("routers"), "lan_cidr": sec.get("lan_cidr"), "arp_poll_s": sec.get("arp_poll_s"),
        "sweep_interval_s": sec.get("sweep_interval_s"), "baseline_minutes": sec.get("baseline_minutes"),
        "dhcp_check_interval_s": sec.get("dhcp_check_interval_s"), "dhcp_servers": sec.get("dhcp_servers"),
        "dns_check_interval_s": sec.get("dns_check_interval_s"), "push_contact": push.get("contact"),
        "speedtest_interval_min": ins.get("speedtest_interval_min"), "portscan_interval_h": ins.get("portscan_interval_h"),
        "audit_interval_h": ins.get("audit_interval_h"), "expected_public_ports": ins.get("expected_public_ports"),
        "services": d.get("services"), "protect": d.get("protect"),
        "module_source": d.get("modules", {}).get("source"),
    }
    data = {k: v for k, v in pick.items() if v is not None}
    # Settings that now belong to modules are kept aside so the modules can pick them up
    legacy = {k: d[k] for k in ("router_api", "adguard") if k in d}
    if legacy:
        data["_legacy"] = legacy
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
    log.info("Imported settings from %s", path)
