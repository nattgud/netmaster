"""Certificates and domains: warns before TLS certificates and domain names expire.

Certificates are read straight from the server (also self-signed ones in the home network).
Domain expiry dates come from RDAP, the registries' open lookup service (no account needed).
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone

from netmaster.sdk import ModuleBase, http_get

DOMAIN_RX = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def _split(text: str) -> list[str]:
    return [p for p in re.split(r"[\s,;]+", text or "") if p]


def parse_target(s: str) -> tuple[str, int] | None:
    """'nas.local:5001', 'https://x.se/path', '[::1]:443' or '192.168.1.1' -> (host, port)."""
    s = s.strip()
    if not s:
        return None
    if "://" not in s:
        s = "https://" + s
    try:
        u = urllib.parse.urlparse(s)
        if u.scheme != "https" or not u.hostname:
            return None
        return u.hostname, u.port or 443
    except ValueError:
        return None


def _when(dt: datetime) -> float:
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def read_cert(host: str, port: int, timeout: float = 8) -> dict:
    """The certificate a server presents, whether or not we trust it."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID

    raw = ssl.create_default_context()
    raw.check_hostname, raw.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with raw.wrap_socket(sock, server_hostname=host if not _is_ip(host) else None) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError("The server sent no certificate")
    cert = x509.load_der_x509_certificate(der)

    def cn(name) -> str:
        a = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(a[0].value) if a else ""

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_after = cert.not_valid_after
    try:
        names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        alt = [str(n) for n in names.get_values_for_type(x509.DNSName)][:5]
    except Exception:
        alt = []
    self_signed = cert.issuer == cert.subject
    trusted, problem = True, ""
    try:
        ok = ssl.create_default_context()
        if _is_ip(host):
            ok.check_hostname = False
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ok.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as e:
        trusted, problem = False, ("self-signed" if self_signed else
                                   "wrong name" if "match" in str(e.verify_message or e).lower() else
                                   "expired" if "expired" in str(e.verify_message or e).lower() else "not trusted")
    except Exception:
        pass  # only the first connection decides whether it is reachable
    return {"expires": _when(not_after), "issuer": cn(cert.issuer) or "unknown issuer", "subject": cn(cert.subject),
            "names": alt, "trusted": trusted, "problem": problem, "self_signed": self_signed}


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


def _whois(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=15) as c:
        c.sendall((query + "\r\n").encode())
        out = b""
        while len(out) < 200_000 and (chunk := c.recv(4096)):
            out += chunk
    return out.decode("utf-8", "replace")


WHOIS_EXP = re.compile(r"^\s*(?:registry expiry date|registrar registration expiration date|expir\w*(?: date| on)?|"
                       r"paid-till|renewal date|valid until)\s*:\s*(.+?)\s*$", re.I | re.M)
WHOIS_REG = re.compile(r"^\s*registrar(?: name)?\s*:\s*(.+?)\s*$", re.I | re.M)


def _parse_date(s: str) -> float:
    s = s.strip().replace("Z", "+00:00")
    for f in (None, "%Y-%m-%d", "%d.%m.%Y", "%d-%b-%Y", "%Y.%m.%d", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            dt = datetime.fromisoformat(s) if f is None else datetime.strptime(s.split()[0], f)
            return _when(dt)
        except ValueError:
            continue
    raise ValueError(s)


def whois_expiry(domain: str) -> dict:
    """For registries without RDAP (for example .se and .nu): ask IANA which WHOIS server, then ask it."""
    tld = domain.rsplit(".", 1)[-1]
    server = next((ln.split(":", 1)[1].strip() for ln in _whois("whois.iana.org", tld).splitlines()
                   if ln.lower().startswith("whois:")), "")
    if not server:
        raise RuntimeError("The registry has no public lookup for this domain ending")
    text = _whois(server, domain)
    for m in WHOIS_EXP.finditer(text):
        try:
            exp = _parse_date(m.group(1))
        except ValueError:
            continue
        reg = WHOIS_REG.search(text)
        return {"expires": exp, "registrar": reg.group(1) if reg else ""}
    raise RuntimeError("The registry does not publish an expiry date for this domain")


def domain_expiry(domain: str) -> dict:
    """{"expires": ts, "registrar": str} from RDAP (rdap.org forwards to the right registry), else WHOIS."""
    try:
        return rdap_expiry(domain)
    except Exception as e:
        try:
            return whois_expiry(domain)
        except RuntimeError as w:   # WHOIS answered but had no date: that says more
            raise w from None
        except Exception:
            raise e from None


def rdap_expiry(domain: str) -> dict:
    code, body = http_get(f"https://rdap.org/domain/{urllib.parse.quote(domain)}",
                          headers={"Accept": "application/rdap+json"}, timeout=15)
    if code == 404:
        raise RuntimeError("Not found in the registry (or the registry has no RDAP)")
    if code != 200 or not body:
        raise RuntimeError(f"The registry answered HTTP {code}")
    d = json.loads(body)
    exp = next((e.get("eventDate") for e in d.get("events") or [] if e.get("eventAction") == "expiration"), None)
    if not exp:
        raise RuntimeError("The registry does not publish an expiry date for this domain")
    registrar = ""
    for ent in d.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = str(item[3])
    return {"expires": datetime.fromisoformat(exp.replace("Z", "+00:00")).timestamp(), "registrar": registrar}


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.results: dict[str, dict] = {}   # "cert:host:port" / "domain:x" -> result
        self._state_file = ctx.data_dir / "alerted.json"
        try:
            self._alerted: dict[str, str] = json.loads(self._state_file.read_text("utf-8"))
        except Exception:
            self._alerted = {}
        self._wake = None

    # ---------- what to check ----------
    def targets(self) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        items = _split(self.settings.get("hosts") or "")
        if self.settings.get("include_services", True):
            items += [u for u in (self.ctx.cfg.services or {}).values() if str(u).lower().startswith("https://")]
        for s in items:
            t = parse_target(s)
            if t and t not in out:
                out.append(t)
        return out[:100]

    def domains(self) -> list[str]:
        out = []
        for s in _split(self.settings.get("domains") or ""):
            d = s.lower().strip(".")
            d = urllib.parse.urlparse(d if "://" in d else "x://" + d).hostname or d
            if DOMAIN_RX.match(d) and d not in out:
                out.append(d)
        return out[:50]

    def _days(self, key: str) -> int:
        try:
            return max(0, int(float(self.settings.get(key) or 0)))
        except ValueError:
            return 0

    # ---------- checking ----------
    def check_all(self) -> None:
        seen = set()
        for host, port in self.targets():
            key = f"cert:{host}:{port}"
            seen.add(key)
            label = host if port == 443 else f"{host}:{port}"
            try:
                r = read_cert(host, port)
                r.update(kind="cert", label=label, error=None)
            except Exception as e:
                r = {"kind": "cert", "label": label, "error": _short(e), **_keep(self.results.get(key))}
            r["checked"] = time.time()
            self.results[key] = r
        for d in self.domains():
            key = f"domain:{d}"
            seen.add(key)
            try:
                r = domain_expiry(d)
                r.update(kind="domain", label=d, error=None)
            except Exception as e:
                r = {"kind": "domain", "label": d, "error": _short(e), **_keep(self.results.get(key))}
            r["checked"] = time.time()
            self.results[key] = r
        for k in list(self.results):
            if k not in seen:
                del self.results[k]
        self._alerts()

    def level(self, r: dict) -> str:
        """ok | warn | critical | expired | unknown"""
        if not r.get("expires"):
            return "unknown"
        days = (r["expires"] - time.time()) / 86400
        if days < 0:
            return "expired"
        if days <= self._days("critical_days"):
            return "critical"
        if days <= self._days("warn_days"):
            return "warn"
        return "ok"

    def _alerts(self) -> None:
        sev = {"warn": "warning", "critical": "critical", "expired": "critical"}
        changed = False
        for key, r in self.results.items():
            lvl = self.level(r)
            if lvl == "unknown":
                continue
            exp = int(r["expires"])
            mark = f"{exp}:{lvl}"
            if lvl == "ok":
                if key in self._alerted:      # renewed: start over
                    del self._alerted[key]
                    changed = True
                    self.ctx.emit("system", "info", f"{_what(r)} was renewed",
                                  f"Now valid until {_date(exp)}.", key, kind=f"{r['kind']}_renewed")
                continue
            if self._alerted.get(key, "").startswith(f"{exp}:") and _rank(self._alerted[key]) >= _rank(mark):
                continue                      # already told about this level for this certificate
            self._alerted[key] = mark
            changed = True
            days = int((exp - time.time()) // 86400)
            if lvl == "expired":
                title = f"{_what(r)} has expired"
                detail = f"It expired on {_date(exp)}."
            else:
                title = f"{_what(r)} expires in {days} day{'s' if days != 1 else ''}"
                detail = f"Valid until {_date(exp)}."
            if r["kind"] == "cert":
                detail += f" Issued by {r.get('issuer')}." + (
                    " Let's Encrypt and similar renew on their own: if it has not renewed by now, the automatic "
                    "renewal may be broken." if lvl != "warn" else "")
            else:
                detail += (f" Registrar: {r['registrar']}." if r.get("registrar") else "") + \
                          " Renew it before it expires, or the website and email on it stop working."
            self.ctx.emit("system", sev[lvl], title, detail, key, kind=f"{r['kind']}_expiring")
        if changed:
            try:
                self._state_file.write_text(json.dumps(self._alerted), "utf-8")
            except OSError:
                pass

    async def run(self) -> None:
        import asyncio
        self._wake = asyncio.Event()
        while True:
            if not self.targets() and not self.domains():
                self.results = {}
                self.last_error = "Add addresses or domains to check in the module settings"
            else:
                try:
                    await self.ctx.to_thread(self.check_all)
                    errs = [r for r in self.results.values() if r.get("error")]
                    if errs and len(errs) == len(self.results):
                        self.error(f"Nothing could be checked: {errs[0]['label']}: {errs[0]['error']}")
                    else:
                        self.ok()
                except Exception as e:
                    self.error(e)
            try:
                hours = max(1.0, float(self.settings.get("interval_h") or 6))
            except ValueError:
                hours = 6.0
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), hours * 3600)
            except asyncio.TimeoutError:
                pass

    async def action(self, action_id: str, value: str | None = None) -> str:
        if action_id != "check":
            raise ValueError("This module has no such action")
        await self.ctx.to_thread(self.check_all)
        self.ok()
        bad = sum(self.level(r) in ("warn", "critical", "expired") for r in self.results.values())
        failed = sum(bool(r.get("error")) for r in self.results.values())
        msg = f"Checked {len(self.results)}"
        if bad:
            msg += f", {bad} expiring soon"
        if failed:
            msg += f", {failed} could not be checked"
        return msg + "."

    # ---------- UI ----------
    def _row(self, r: dict) -> dict:
        lvl = self.level(r)
        parts = []
        if r.get("expires"):
            days = int((r["expires"] - time.time()) // 86400)
            parts.append(f"expired {_date(r['expires'])}" if days < 0 else f"{days} d left ({_date(r['expires'])})")
        if r["kind"] == "cert" and r.get("issuer"):
            parts.append(r["issuer"])
        if r["kind"] == "cert" and r.get("expires") and not r.get("trusted", True) and r.get("problem") != "expired":
            parts.append(r.get("problem") or "not trusted")
        if r["kind"] == "domain" and r.get("registrar"):
            parts.append(r["registrar"])
        if r.get("error"):
            parts.append(r["error"])
        state = {"ok": "up", "warn": "degraded", "critical": "down", "expired": "down"}.get(lvl, "degraded")
        if lvl == "ok" and r.get("error"):
            state = "degraded"
        return {"label": ("🔒 " if r["kind"] == "cert" else "🌐 ") + r["label"], "value": " · ".join(parts), "state": state}

    def status(self) -> dict:
        order = {"expired": 0, "critical": 1, "warn": 2, "unknown": 3, "ok": 4}
        items = sorted(self.results.values(), key=lambda r: (order[self.level(r)], r.get("expires") or 0))
        services = []
        for r in items:
            lvl = self.level(r)
            if lvl not in ("warn", "critical", "expired"):
                continue   # errors (a server that is off, a registry without dates) stay in the module's card
            row = self._row(r)
            services.append({"name": _what(r), "url": r["label"], "state": row["state"],
                             "value": row["value"].split(" · ")[0], "detail": " · ".join(row["value"].split(" · ")[1:]), "since": r.get("checked"),
                             "ms": None, "error": r.get("error")})
        return {"rows": [self._row(r) for r in items], "services": services[:10]}


def _what(r: dict) -> str:
    return f"Certificate for {r['label']}" if r["kind"] == "cert" else f"Domain {r['label']}"


def _date(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def _rank(mark: str) -> int:
    return {"warn": 1, "critical": 2, "expired": 3}.get(mark.rsplit(":", 1)[-1], 0)


def _keep(prev: dict | None) -> dict:
    """Keep the last known date when one check fails (a server that is off for the night)."""
    return {k: v for k, v in (prev or {}).items() if k in ("expires", "issuer", "registrar", "trusted", "problem")}


def _short(e: Exception) -> str:
    if isinstance(e, socket.timeout):
        return "No answer (timeout)"
    if isinstance(e, ConnectionRefusedError):
        return "Connection refused (nothing on that port)"
    if isinstance(e, ConnectionResetError):
        return "The server closed the connection"
    if isinstance(e, socket.gaierror):
        return "Name not found"
    if isinstance(e, ssl.SSLError):
        return f"TLS failed: {e.reason or e}"[:120]
    return f"{e}"[:120] or type(e).__name__
