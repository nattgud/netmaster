"""Login: one admin password, hashed with scrypt, and random session tokens in a cookie.

- The password hash is stored in the database (meta "auth_password").
- Sessions are random 256-bit tokens. Only their SHA-256 is stored, so a stolen database
  cannot be used to log in. They expire after 30 days without use.
- Failed logins are rate limited per IP address.
- The first password can be set from the computer NetMaster runs on, or from anywhere with the
  one-time code in data/setup-code.txt. It can also be set with: python -m netmaster set-password
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from pathlib import Path

SESSION_DAYS = 30
COOKIE = "nm_session"
MIN_LENGTH = 8
SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
    token_hash TEXT PRIMARY KEY,
    created REAL NOT NULL,
    last_seen REAL NOT NULL,
    agent TEXT
);
"""


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024)
    return f"scrypt$32768$8$1${salt.hex()}${h.hex()}"


def check_password(pw: str, stored: str | None) -> bool:
    try:
        algo, n, r, p, salt, h = (stored or "").split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got.hex(), h)
    except (ValueError, TypeError):
        return False


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, db, data_dir: Path):
        self.db = db
        self.code_file = data_dir / "setup-code.txt"
        self._fails: dict[str, list[float]] = {}
        self._touched: dict[str, float] = {}
        with db._lock, db._conn:
            db._conn.executescript(SCHEMA)
        if self.needs_setup and not self.code_file.exists():
            data_dir.mkdir(parents=True, exist_ok=True)
            self.code_file.write_text(secrets.token_hex(4) + "\n", "utf-8")

    # ---------- password ----------
    @property
    def needs_setup(self) -> bool:
        return not self.db.get_meta("auth_password")

    def setup_code(self) -> str:
        try:
            return self.code_file.read_text("utf-8").strip()
        except OSError:
            return ""

    def set_password(self, pw: str) -> None:
        if len(pw) < MIN_LENGTH:
            raise ValueError(f"The password must be at least {MIN_LENGTH} characters")
        self.db.set_meta("auth_password", hash_password(pw))
        self.code_file.unlink(missing_ok=True)

    def check(self, pw: str) -> bool:
        return check_password(pw, self.db.get_meta("auth_password"))

    # ---------- rate limit ----------
    def limited(self, ip: str) -> bool:
        now = time.time()
        f = self._fails[ip] = [t for t in self._fails.get(ip, []) if now - t < 900]
        return len(f) >= 5

    def failed(self, ip: str) -> None:
        self._fails.setdefault(ip, []).append(time.time())

    # ---------- sessions ----------
    def new_session(self, agent: str = "") -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.db.execute("INSERT INTO sessions(token_hash, created, last_seen, agent) VALUES (?,?,?,?)",
                        [(_th(token), now, now, agent[:200])])
        return token

    def valid(self, token: str | None) -> bool:
        if not token or len(token) > 100:
            return False
        h, now = _th(token), time.time()
        rows = self.db.query("SELECT last_seen FROM sessions WHERE token_hash = ?", (h,))
        if not rows or now - rows[0]["last_seen"] > SESSION_DAYS * 86400:
            return False
        if now - self._touched.get(h, 0) > 300:  # sliding expiry, but don't write on every request
            self._touched[h] = now
            self.db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", [(now, h)])
        return True

    def end(self, token: str | None) -> None:
        if token:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", [(_th(token),)])

    def end_all(self, keep: str | None = None) -> None:
        self.db.execute("DELETE FROM sessions WHERE token_hash != ?", [(_th(keep or ""),)])

    def prune(self) -> None:
        self.db.execute("DELETE FROM sessions WHERE last_seen < ?", [(time.time() - SESSION_DAYS * 86400,)])
