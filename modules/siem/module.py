"""SIEM / syslog: sends every NetMaster alert to a log server or SIEM as it happens.

Formats:
- syslog (RFC 5424) with structured data: rsyslog, syslog-ng, Graylog, Splunk, Wazuh, Elastic, Sentinel (AMA).
- CEF (ArcSight Common Event Format) in syslog: Microsoft Sentinel, ArcSight, QRadar, Splunk, LogRhythm.
- JSON in syslog: Elastic/Logstash, Graylog, Wazuh and others that parse JSON.
Transport: UDP, TCP or TCP with TLS. Over TCP each message ends with a newline (RFC 6587).
"""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
import threading
import time
from collections import deque
from datetime import datetime

from netmaster import __version__
from netmaster.sdk import ModuleBase

SEVERITIES = ["info", "notice", "warning", "critical"]
SYSLOG_SEV = {"info": 6, "notice": 5, "warning": 4, "critical": 2}
CEF_SEV = {"info": 2, "notice": 3, "warning": 6, "critical": 9}
FACILITY = 16          # local0
PEN = "32473"          # the example enterprise number from RFC 5612, for the structured data id
MAX_QUEUE = 2000
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _cef_head(v) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r\n", "\\n").replace("\n", "\\n")


def _sd(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


class Module(ModuleBase):
    def __init__(self, ctx, settings, meta):
        super().__init__(ctx, settings, meta)
        self.sock: socket.socket | None = None
        self.pending: deque[bytes] = deque(maxlen=MAX_QUEUE)
        self.sent = self.dropped = 0
        self.hostname = socket.gethostname()
        self.lock = threading.Lock()   # run() and the test button may send at the same time

    @property
    def host(self) -> str:
        return str(self.settings.get("host") or "").strip()

    @property
    def port(self) -> int:
        return int(float(self.settings.get("port") or 514))

    def wanted(self, ev: dict) -> bool:
        sev = ev.get("severity", "info")
        lowest = str(self.settings.get("min_severity") or "info")
        return SEVERITIES.index(sev if sev in SEVERITIES else "info") >= SEVERITIES.index(lowest if lowest in SEVERITIES else "info")

    # ---------- formats ----------
    def message(self, ev: dict) -> bytes:
        ts = float(ev.get("ts") or time.time())
        sev = ev.get("severity") if ev.get("severity") in SEVERITIES else "info"
        cat, kind = ev.get("category") or "system", ev.get("kind") or ev.get("category") or "event"
        title, detail = str(ev.get("title", "")), str(ev.get("detail", ""))
        pri = FACILITY * 8 + SYSLOG_SEV[sev]
        fmt = self.settings.get("format") or "rfc5424"
        if fmt == "cef":
            ext = {"rt": int(ts * 1000), "cat": cat, "msg": detail, "dvchost": self.hostname,
                   "dvc": self.ctx.local_ip or "", "externalId": ev.get("id") or "",
                   "cs1Label": "source", "cs1": ev.get("source") or ""}
            line = (f"CEF:0|NetMaster|NetMaster|{_cef_head(__version__)}|{_cef_head(kind)}|{_cef_head(title)}|"
                    f"{CEF_SEV[sev]}|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != ""))
            # the classic BSD syslog header that CEF collectors expect
            d = datetime.fromtimestamp(ts)
            return f"<{pri}>{MONTHS[d.month - 1]} {d.day:>2} {d:%H:%M:%S} {self.hostname} {line}".encode()
        stamp = datetime.fromtimestamp(ts).astimezone().isoformat(timespec="milliseconds")
        if fmt == "json":
            body = json.dumps({"id": ev.get("id"), "time": stamp, "category": cat, "severity": sev, "title": title,
                               "detail": detail, "kind": ev.get("kind") or None, "source": ev.get("source") or None,
                               "netmaster": self.ctx.local_ip}, ensure_ascii=False)
            sd = "-"
        else:
            body = f"{title}" + (f" - {detail}" if detail else "")
            fields = {"id": ev.get("id") or "", "category": cat, "severity": sev, "kind": ev.get("kind") or "",
                      "source": ev.get("source") or ""}
            sd = f"[netmaster@{PEN} " + " ".join(f'{k}="{_sd(v)}"' for k, v in fields.items() if v != "") + "]"
        msgid = "".join(c for c in str(kind) if 33 <= ord(c) <= 126)[:32] or "-"
        return f"<{pri}>1 {stamp} {self.hostname} NetMaster - {msgid} {sd} {body}".encode()

    # ---------- sending ----------
    def _connect(self) -> socket.socket:
        proto = self.settings.get("protocol") or "udp"
        if proto == "udp":
            s = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.host, self.port))
            return s
        s = socket.create_connection((self.host, self.port), timeout=10)
        if proto == "tls":
            ctx = ssl.create_default_context()
            if not self.settings.get("verify_tls", True):
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        return s

    def flush(self) -> None:
        """Sends everything waiting. Raises when the server cannot be reached; the rest stays queued."""
        if not self.host:
            raise ValueError("Set the log server address in the module settings")
        udp = (self.settings.get("protocol") or "udp") == "udp"
        with self.lock:
            self._flush(udp)

    def _flush(self, udp: bool) -> None:
        while self.pending:
            msg = self.pending[0]
            if self.sock is None:
                self.sock = self._connect()
            try:
                self.sock.sendall(msg[:8000] if udp else msg + b"\n")
            except OSError:
                self.close()
                raise
            self.pending.popleft()
            self.sent += 1

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def queue(self, msg: bytes) -> None:
        if len(self.pending) == self.pending.maxlen:
            self.dropped += 1
        self.pending.append(msg)

    # ---------- running ----------
    async def run(self) -> None:
        q = self.ctx.subscribe_events()
        if not self.host:
            self.last_error = "Set the log server address in the module settings"
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), 10)   # wake now and then to retry a waiting queue
                    if self.wanted(ev):
                        self.queue(self.message(ev))
                except asyncio.TimeoutError:
                    pass
                if self.pending and self.host:
                    try:
                        await self.ctx.to_thread(self.flush)
                        self.ok()
                    except OSError as e:
                        self.error(f"Could not reach {self.host}:{self.port}: {e.strerror or e}. "
                                   f"{len(self.pending)} messages wait and are sent when it answers.")
        finally:
            self.close()

    def stop(self) -> None:
        self.close()

    async def action(self, action_id: str, value: str | None = None) -> str:
        if action_id != "test":
            raise ValueError("This module has no such action")
        self.queue(self.message({"id": 0, "ts": time.time(), "category": "system", "severity": "info",
                                 "title": "NetMaster test message", "detail": "Sending to the log server works.",
                                 "kind": "test", "source": "siem"}))
        try:
            await self.ctx.to_thread(self.flush)
        except OSError as e:
            raise RuntimeError(f"Could not reach {self.host}:{self.port}: {e.strerror or e}") from None
        self.ok()
        proto = (self.settings.get("protocol") or "udp").upper()
        return "Sent. Check that it arrived." + (" UDP gives no receipt: check the log server." if proto == "UDP" else "")

    def status(self) -> dict:
        if not self.host:
            return {}
        parts = [f"{self.sent} sent"]
        if self.pending:
            parts.append(f"{len(self.pending)} waiting")
        if self.dropped:
            parts.append(f"{self.dropped} dropped")
        proto = (self.settings.get("protocol") or "udp").upper()
        return {"rows": [{"label": f"{self.host}:{self.port} ({proto})", "value": " · ".join(parts),
                          "state": "down" if self.last_error else "up"}]}
