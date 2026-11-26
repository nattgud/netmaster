"""AdGuard Home: which sites each device looks up, what was blocked, alerts for suspicious
lookups, and your own block/allow rules.

Works with a stand-alone AdGuard Home and with the Home Assistant add-on (use the add-on's
address and your Home Assistant login).
"""
from __future__ import annotations

import base64
import json
import math
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from netmaster.sdk import ModuleBase

SCHEMA = """
CREATE TABLE IF NOT EXISTS dnsq(
    hour REAL NOT NULL,
    ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    n INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    PRIMARY KEY(hour, ip, domain)
);
"""


# ---------- suspicious domains ----------
SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}


def base_domain(name: str) -> str:
    """The registered domain: www.google.co.uk -> google.co.uk, a.b.example.com -> example.com."""
    p = name.split(".")
    if len(p) >= 3 and p[-2] in SLD and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


# Top-level domains often used for spam and malware (cheap or free to register).
SHADY_TLD = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "country", "kim", "work", "rest",
             "cam", "loan", "bid", "win", "icu", "cyou", "buzz", "monster", "sbs", "cfd"}
PATTERNS = [
    (re.compile(r"((^|\.)(xmr|monero)[.-]|nanopool\.|minexmr\.|2miners\.|nicehash\.|f2pool\.|ethermine\.|hashvault\.|moneroocean\.|supportxmr\.|c3pool\.|herominers\.)"),
     "warning", "a cryptocurrency mining pool", "Mining on a home device is almost always malware using your electricity."),
    (re.compile(r"(duckdns\.org|no-ip\.|noip\.|ddns\.net|dyndns|hopto\.org|zapto\.org|serveo\.net|ngrok)"),
     "notice", "a dynamic-DNS or tunnel service", "Used by home servers, but also by malware to reach its owner. Fine if you set it up yourself."),
    (re.compile(r"(\.onion$|tor2web|torproject\.org)"),
     "notice", "the Tor network", "Fine if someone uses Tor Browser on purpose; strange for a smart-home device."),
]


def _entropy(s: str) -> float:
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s)))


def looks_random(base: str) -> bool:
    """A random name (as malware generates to find its server), e.g. xkq7zj3pq9w.com."""
    label = base.split(".")[0]
    vowels = sum(ch in "aeiou" for ch in label)
    return len(label) >= 12 and _entropy(label) >= 3.4 and vowels / len(label) < 0.25 and not label.startswith("xn--")


class Module(ModuleBase):
    PAGE = 1000
    MAX_PAGES = 20

    QUIET_MAX = 25        # at most this many sites a week = a "quiet" device (smart-home gadgets)
    LEARN_S = 3 * 86400   # how long we learn what a device usually contacts

    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.db = ctx.db
        self._alerted: dict[tuple, float] = {}
        self._known: dict[str, set[str]] | None = None
        self.url = (settings.get("url") or "").strip().rstrip("/")
        self._last_ts = float(self.db.get_meta("adguard_last_ts") or 0)
        self._ctx = ssl.create_default_context()
        if not settings.get("verify_tls", True):   # e.g. the Home Assistant add-on's own certificate
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        with self.db._lock, self.db._conn:
            self.db._conn.executescript(SCHEMA)

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def _get(self, path: str, body: dict | None = None) -> dict:
        user, pw = self.settings.get("username") or "", self.settings.get("password") or ""
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "User-Agent": "NetMaster"}
        data = None
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        req = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20, context=self._ctx) as r:
                raw = r.read()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError("Login refused: check the username and password") from None
            raise

    @staticmethod
    def _ts(s: str) -> float:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

    def _fetch(self) -> list[tuple[float, str, str, bool]]:
        """New lookups since last time. AdGuard lists newest first, so page backwards until we reach the last one."""
        rows, older = [], None
        for _ in range(self.MAX_PAGES):
            q = {"limit": self.PAGE}
            if older:
                q["older_than"] = older
            d = self._get("/control/querylog?" + urllib.parse.urlencode(q))
            items = d.get("data") or []
            done = False
            for it in items:
                ts = self._ts(it["time"])
                if ts <= self._last_ts:
                    done = True
                    break
                name = (it.get("question") or {}).get("name", "").rstrip(".").lower()
                if name:
                    rows.append((ts, it.get("client", ""), name, str(it.get("reason", "")).startswith("Filtered"),
                                 str(it.get("reason", ""))))
            older = d.get("oldest")
            if done or not items or not older or not self._last_ts:
                break  # the first time: only the latest page
        return rows

    def _store(self, rows) -> None:
        agg: dict[tuple, list[int]] = {}
        for ts, ip, name, blocked, _ in rows:
            a = agg.setdefault((ts - ts % 3600, ip, name), [0, 0])
            a[0] += 1
            a[1] += blocked
        self.db.execute("INSERT INTO dnsq(hour, ip, domain, n, blocked) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(hour, ip, domain) DO UPDATE SET n = n + excluded.n, blocked = blocked + excluded.blocked",
                        [(h, ip, dom, n, b) for (h, ip, dom), (n, b) in agg.items()])
        self._last_ts = max(r[0] for r in rows)
        self.db.set_meta("adguard_last_ts", str(self._last_ts))

    async def run(self) -> None:
        while True:
            if not self.url:
                self.last_error = "Set the AdGuard Home address in the module settings"
            else:
                try:
                    rows = await self.ctx.to_thread(self._fetch)
                    if rows:
                        try:
                            self._check(rows)
                        except Exception:
                            self.ctx.log.exception("AdGuard check failed")
                        self._store(rows)
                    self.ok()
                except Exception as e:
                    self.error(e)
                try:
                    with self.db._lock, self.db._conn:
                        self.db._conn.execute("DELETE FROM dnsq WHERE hour < ?", (time.time() - 30 * 86400,))
                except Exception:
                    pass
            await self.ctx.sleep(max(15.0, float(self.settings.get("interval_s") or 60)))

    # ---------- alerts ----------
    def _once(self, key: tuple, every_s: float) -> bool:
        if time.time() - self._alerted.get(key, 0) < every_s:
            return False
        self._alerted[key] = time.time()
        return True

    def _dev(self, ip: str) -> tuple[str, str]:
        return self.ctx.device_by_ip(ip)

    def _load_known(self) -> None:
        """Which sites each device contacted in the last 30 days, and since when we have data for it."""
        self._known, self._since = {}, {}
        for r in self.db.query("SELECT ip, domain, MIN(hour) AS first FROM dnsq GROUP BY ip, domain"):
            self._known.setdefault(r["ip"], set()).add(base_domain(r["domain"]))
            self._since[r["ip"]] = min(self._since.get(r["ip"], r["first"]), r["first"])

    def _quiet(self, ip: str) -> bool:
        if time.time() - self._since.get(ip, time.time()) < self.LEARN_S:
            return False
        week = self.db.query("SELECT domain FROM dnsq WHERE ip = ? AND hour >= ?", (ip, time.time() - 7 * 86400))
        return len({base_domain(r["domain"]) for r in week}) <= self.QUIET_MAX

    def _alert(self, ip: str, sev: str, title: str, detail: str) -> None:
        mac, _ = self._dev(ip)
        self.ctx.emit("security", sev, title, detail, mac)

    def _check(self, rows) -> None:
        if self._known is None:
            self._load_known()
        for ts, ip, name, blocked, reason in sorted(rows):
            base = base_domain(name)
            _, dev = self._dev(ip)
            if reason in ("FilteredSafeBrowsing", "FilteredParental") and self._once((ip, base, "sb"), 86400):
                self._alert(ip, "warning", f"{dev} tried to reach a dangerous site",
                            f"{name} is on AdGuard's list of malware/phishing sites and was blocked. "
                            "If nobody clicked a strange link, the device may be infected.")
            for rx, sev, what, why in PATTERNS:
                if rx.search(name) and self._once((ip, base, what), 7 * 86400):
                    self._alert(ip, sev, f"{dev} contacted {what}", f"{name}. {why}")
            tld = base.rsplit(".", 1)[-1]
            if not blocked and tld in SHADY_TLD and self._once((ip, base, "tld"), 7 * 86400):
                self._alert(ip, "notice", f"{dev} contacted a site on a suspicious domain ending",
                            f"{name} (.{tld} is cheap and often used for spam and malware). Usually harmless, worth a look "
                            "if the device shouldn't browse.")
            if not blocked and looks_random(base) and self._once((ip, base, "dga"), 7 * 86400):
                self._alert(ip, "warning", f"{dev} looked up a random-looking site",
                            f"{name}. Malware generates names like this to find its control server. Worth checking "
                            "the device with Investigate and an antivirus scan.")
            known = self._known.setdefault(ip, set())
            if base not in known:
                known.add(base)
                if not blocked and self._quiet(ip) and self._once((ip, base, "new"), 30 * 86400):
                    self._alert(ip, "notice", f"{dev} contacted a new site: {base}",
                                f"{name}. This device normally only talks to a few sites, and has never contacted this one "
                                "before. Often a firmware update or new feature; suspicious if the site looks unrelated.")
            self._since.setdefault(ip, ts)

    def top(self, hours: float = 24, n: int = 3) -> dict:
        """Most contacted sites (registered domain) per IP, for the column in the device list."""
        since = time.time() - hours * 3600
        out: dict[str, dict] = {}
        for r in self.db.query("SELECT ip, domain, SUM(n) AS n, SUM(blocked) AS b FROM dnsq WHERE hour >= ? GROUP BY ip, domain",
                               (since - since % 3600,)):
            o = out.setdefault(r["ip"], {"sites": {}, "blocked": 0, "total": 0})
            b = base_domain(r["domain"])
            o["sites"][b] = o["sites"].get(b, 0) + r["n"]
            o["blocked"] += r["b"]
            o["total"] += r["n"]
        return {ip: {"top": sorted(o["sites"], key=o["sites"].get, reverse=True)[:n], "blocked": o["blocked"],
                     "total": o["total"], "sites": len(o["sites"])} for ip, o in out.items()}

    def device(self, ip: str | None, hours: float = 24, limit: int = 40) -> dict:
        if not ip:
            return {"enabled": self.enabled, "domains": [], "total": 0, "blocked": 0}
        since = time.time() - hours * 3600
        doms = self.db.query("SELECT domain, SUM(n) AS n, SUM(blocked) AS blocked, MIN(hour) AS first FROM dnsq "
                             "WHERE ip = ? AND hour >= ? GROUP BY domain ORDER BY SUM(n) DESC LIMIT ?",
                             (ip, since - since % 3600, limit))
        tot = self.db.query("SELECT COALESCE(SUM(n),0) AS n, COALESCE(SUM(blocked),0) AS b, COUNT(DISTINCT domain) AS d "
                            "FROM dnsq WHERE ip = ? AND hour >= ?", (ip, since - since % 3600))[0]
        return {"enabled": self.enabled, "domains": doms, "total": tot["n"], "blocked": tot["b"], "distinct": tot["d"]}

    # ---------- your own filter rules ----------
    DOMAIN_RX = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

    @staticmethod
    def make_rule(domain: str, action: str, client: str | None = None) -> str:
        """||x^ blocks x and everything under it. @@ = allow. $client = only for one device."""
        rule = ("@@" if action == "allow" else "") + f"||{domain}^"
        return rule + (f"$client='{client}'" if client else "")

    def rules(self) -> list[str]:
        return [r for r in (self._get("/control/filtering/status").get("user_rules") or []) if r.strip()]

    def add_rule(self, domain: str, action: str, client: str | None = None) -> list[str]:
        domain = domain.strip().lower().rstrip(".")
        if not self.DOMAIN_RX.match(domain) or action not in ("block", "allow"):
            raise ValueError("Invalid domain or action")
        rule = self.make_rule(domain, action, client)
        opposite = self.make_rule(domain, "allow" if action == "block" else "block", client)
        rules = [r for r in self.rules() if r not in (rule, opposite)] + [rule]
        self._get("/control/filtering/set_rules", {"rules": rules})
        return rules

    def remove_rule(self, rule: str) -> list[str]:
        rules = [r for r in self.rules() if r != rule]
        self._get("/control/filtering/set_rules", {"rules": rules})
        return rules

    def protect(self) -> dict[str, str]:
        """The DNS filter's own server: pausing it would break DNS for the whole network."""
        host = urllib.parse.urlparse(self.url).hostname
        return {host: "the DNS filter (AdGuard Home)"} if host else {}

    def status(self) -> dict:
        return {"url": self.url, "host": urllib.parse.urlparse(self.url).hostname}
