from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    source TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS samples(
    ts REAL NOT NULL,
    target TEXT NOT NULL,
    ms REAL
);
CREATE INDEX IF NOT EXISTS ix_samples ON samples(target, ts);

CREATE TABLE IF NOT EXISTS syslog(
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    facility INTEGER,
    severity INTEGER,
    message TEXT
);
CREATE INDEX IF NOT EXISTS ix_syslog_ts ON syslog(ts);

CREATE TABLE IF NOT EXISTS devices(
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    name TEXT,
    trusted INTEGER NOT NULL DEFAULT 0,
    randomized INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS usage(
    ts REAL NOT NULL,
    mac TEXT NOT NULL,
    down REAL NOT NULL,
    up REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_usage ON usage(mac, ts);
CREATE INDEX IF NOT EXISTS ix_usage_ts ON usage(ts);

CREATE TABLE IF NOT EXISTS speedtests(
    ts REAL NOT NULL,
    down_mbps REAL,
    up_mbps REAL,
    ping_ms REAL
);

CREATE TABLE IF NOT EXISTS wifi(
    ts REAL NOT NULL,
    mac TEXT NOT NULL,
    signal REAL,
    conn TEXT
);
CREATE INDEX IF NOT EXISTS ix_wifi ON wifi(mac, ts);

CREATE TABLE IF NOT EXISTS calls(
    ts REAL PRIMARY KEY,
    ms REAL, jitter REAL, loss REAL, load REAL, grade TEXT
);

CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS push_subs(
    endpoint TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created REAL,
    user_agent TEXT
);
"""

DEVICE_COLS = ("mac", "ip", "hostname", "vendor", "name", "trusted", "randomized", "first_seen", "last_seen", "watch", "share")


class Database:
    """Thin SQLite wrapper. The calls are small and fast, so they run directly in the event loop."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        # Older databases lack these columns: watch (presence alerts), share (shown in smart-home modules)
        for col in ("watch", "share"):
            try:
                self._conn.execute(f"ALTER TABLE devices ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
        # Older versions used Swedish category names
        with self._conn:
            for old, new in (("intrång", "security"), ("störning", "disruption"), ("närvaro", "presence")):
                self._conn.execute("UPDATE events SET category = ? WHERE category = ?", (new, old))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- skrivning ---
    def insert_event(self, ts, category, severity, title, detail, source) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO events(ts, category, severity, title, detail, source) VALUES (?,?,?,?,?,?)",
                (ts, category, severity, title, detail, source),
            )
            return cur.lastrowid

    def insert_samples(self, rows: list[tuple[float, str, float | None]]) -> None:
        with self._lock, self._conn:
            self._conn.executemany("INSERT INTO samples(ts, target, ms) VALUES (?,?,?)", rows)

    def insert_syslog(self, ts, host, facility, severity, message) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO syslog(ts, host, facility, severity, message) VALUES (?,?,?,?,?)",
                (ts, host, facility, severity, message),
            )
            return cur.lastrowid

    def prune(self, sample_days: int, syslog_days: int) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM samples WHERE ts < ?", (now - sample_days * 86400,))
            self._conn.execute("DELETE FROM syslog WHERE ts < ?", (now - syslog_days * 86400,))
            self._conn.execute("DELETE FROM usage WHERE ts < ?", (now - max(sample_days, 30) * 86400,))
            self._conn.execute("DELETE FROM wifi WHERE ts < ?", (now - 30 * 86400,))
            self._conn.execute("DELETE FROM calls WHERE ts < ?", (now - 30 * 86400,))
            self._conn.execute("DELETE FROM speedtests WHERE ts < ?", (now - 90 * 86400,))
            self._conn.execute("DELETE FROM events WHERE ts < ?", (now - 365 * 86400,))

    # --- generiskt ---
    def query(self, sql: str, params=()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params)]

    def execute(self, sql: str, rows) -> None:
        """Runs sql for every row in rows (a list of tuples)."""
        with self._lock, self._conn:
            self._conn.executemany(sql, rows)

    # --- meta (key/value) ---
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            r = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return r["value"] if r else None

    def set_meta(self, key: str, value: str | None) -> None:
        with self._lock, self._conn:
            if value is None:
                self._conn.execute("DELETE FROM meta WHERE key = ?", (key,))
            else:
                self._conn.execute("INSERT INTO meta(key, value) VALUES (?, ?) "
                                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # --- devices ---
    def devices(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute("SELECT * FROM devices")]

    def device_upsert(self, d: dict) -> None:
        cols = ", ".join(DEVICE_COLS)
        marks = ", ".join("?" for _ in DEVICE_COLS)
        updates = ", ".join(f"{c} = excluded.{c}" for c in DEVICE_COLS if c != "mac")
        with self._lock, self._conn:
            self._conn.execute(f"INSERT INTO devices({cols}) VALUES ({marks}) ON CONFLICT(mac) DO UPDATE SET {updates}",
                               tuple(int(bool(d.get(c))) if c in ("watch", "share") else d.get(c) for c in DEVICE_COLS))

    def device_delete(self, mac: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))

    # --- push-prenumerationer ---
    def push_subs(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute("SELECT * FROM push_subs")]

    def push_add(self, endpoint: str, data: str, user_agent: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO push_subs(endpoint, data, created, user_agent) VALUES (?,?,?,?) "
                               "ON CONFLICT(endpoint) DO UPDATE SET data = excluded.data",
                               (endpoint, data, time.time(), user_agent))

    def push_delete(self, endpoint: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM push_subs WHERE endpoint = ?", (endpoint,))

    # --- reading ---
    def events(self, limit: int = 200, category: str | None = None, before_id: int | None = None) -> list[dict]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if category:
            sql += " AND category = ?"
            args.append(category)
        if before_id:
            sql += " AND id < ?"
            args.append(before_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args)]

    def syslog(self, limit: int = 300, host: str | None = None) -> list[dict]:
        sql = "SELECT * FROM syslog"
        args: list = []
        if host:
            sql += " WHERE host = ?"
            args.append(host)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args)]

    def samples(self, minutes: int, points: int = 300) -> dict:
        """Average and loss ratio per time bucket and target."""
        since = time.time() - minutes * 60
        bucket = max(5.0, minutes * 60 / points)
        sql = """
            SELECT target,
                   CAST(ts / ? AS INTEGER) * ? AS b,
                   AVG(ms) AS avg_ms,
                   SUM(CASE WHEN ms IS NULL THEN 1 ELSE 0 END) * 1.0 / COUNT(*) AS loss
            FROM samples WHERE ts >= ?
            GROUP BY target, b ORDER BY b
        """
        out: dict[str, list] = {}
        with self._lock:
            for r in self._conn.execute(sql, (bucket, bucket, since)):
                avg = round(r["avg_ms"], 2) if r["avg_ms"] is not None else None
                out.setdefault(r["target"], []).append([r["b"], avg, round(r["loss"], 3)])
        return {"bucket_s": bucket, "series": out}
