"""Rules that turn router log lines into events.

The patterns are deliberately broad to catch both ASUS (Asuswrt/Merlin) and TP-Link (Archer).
The first matching rule wins, so the order matters. Tune them against real logs
on the "Logs" tab in the app.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: re.Pattern
    category: str
    severity: str
    title: str


def _r(id_, pattern, category, severity, title) -> Rule:
    return Rule(id_, re.compile(pattern, re.I), category, severity, title)


RULES: list[Rule] = [
    # --- TP-Link (lines look like "2026-11-24 07:00:00 INFO NAT: Virtual server ...") ---
    _r("ax_led", r"\bLED_CONTROLLER: ", "system", "ignore", ""),  # night mode for the LEDs etc.
    _r("ax_remote_mgmt", r"\bREMOTE_MANAGEMENT: .*service start",
       "security", "warning", "Router remote management is on (router reachable from the internet)"),
    _r("ax_portfwd", r"\bNAT: .*virtual server created",
       "security", "notice", "Port opened to the internet on the router"),
    _r("ax_wan_switch", r"\bMODEM: .*switch network to",
       "disruption", "notice", "Router switched internet connection"),
    # --- Security ---
    _r("threat", r"aiprotection|bwdpi|malicious|infected|intrusion|botnet|vulnerab|trend ?micro|\bips\b.*(block|detect)",
       "security", "critical", "Security alert from the router"),
    _r("dos", r"\bd?dos\b|syn[ _-]?flood|udp[ _-]?flood|icmp[ _-]?flood|ping[ _-]of[ _-]death|land attack|"
              r"smurf|teardrop|port ?scan|scan(ning)? attack|attack detected",
       "security", "critical", "Attack on the network blocked"),
    _r("login_fail", r"(fail(ed|ure)?|invalid|incorrect|wrong|bad)\W+(\w+\W+){0,4}(login|password|auth\w*|user)|"
                     r"(login|auth\w*|password)\W+(\w+\W+){0,4}(fail(ed|ure)?|invalid|denied|incorrect)",
       "security", "warning", "Failed login to the router"),
    _r("login_ok", r"accepted (password|publickey)|(login|logged in|log in)\W+(\w+\W+){0,3}(success\w*|ok)\b|"
                   r"\buser \S+ login\b|\blogin from\b|web(ui)? login|dropbear.*auth succeeded",
       "security", "notice", "Someone logged in to the router"),
    # --- Disruptions ---
    _r("wan_down", r"wan\W+(\w+\W+){0,5}(down|disconnect\w*|lost|fail\w*|timeout)|"
                   r"(pppoe|dhcp ?client|link)\W+(\w+\W+){0,3}(down|lost|timeout)|no internet",
       "disruption", "critical", "Router reports WAN outage"),
    _r("wan_up", r"wan\W+(\w+\W+){0,5}(\bup\b|connected|restored|established)|wan_up",
       "disruption", "info", "Router reports WAN is up"),
    _r("dfs", r"radar detected|\bdfs\b.*(radar|channel)",
       "disruption", "notice", "Wi-Fi changed channel (radar/DFS)"),
    # --- System ---
    _r("reboot", r"\b(reboot(ing|ed)?|system (re)?start\w*|booting|kernel: linux version)\b",
       "system", "warning", "The router restarted"),
    _r("config", r"(config(uration)?|settings?)\W+(\w+\W+){0,3}(changed|saved|restored|reset|modified)|"
                 r"firmware\W+(\w+\W+){0,3}(upgrad\w*|updat\w*)",
       "system", "notice", "Router settings changed"),
]

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


_MAC = r"([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})"
_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_DNSMASQ_ACK = re.compile(rf"DHCPACK\([^)]*\)\s+{_IPV4}\s+{_MAC}(?:\s+(\S+))?", re.I)
_GENERIC_ACK = re.compile(r"dhcp\w*.*\back\b", re.I)


def dhcp_lease(message: str) -> tuple[str, str, str | None] | None:
    """(ip, mac, hostname) from a DHCP lease in the router log, otherwise None."""
    m = _DNSMASQ_ACK.search(message)
    if m:
        return m.group(1), m.group(2), m.group(3)
    if _GENERIC_ACK.search(message):
        ip, mac = re.search(_IPV4, message), re.search(_MAC, message, re.I)
        if ip and mac:
            return ip.group(1), mac.group(1), None
    return None


def match(message: str) -> Rule | None:
    for rule in RULES:
        if rule.pattern.search(message):
            return rule
    return None


def extract_ips(message: str) -> list[str]:
    return list(dict.fromkeys(_IP.findall(message)))
