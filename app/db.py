"""SQLite access layer: schema, connections, small helpers.

Single writer (the scanner thread) + readers (web). WAL mode keeps reads
non-blocking. All writes go through short transactions.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable

from .config import config

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS scan_roots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mount_path TEXT NOT NULL UNIQUE,
    label TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    roots_json TEXT NOT NULL DEFAULT '[]',
    include_globs TEXT NOT NULL DEFAULT '',
    exclude_globs TEXT NOT NULL DEFAULT '',
    trigger_type TEXT NOT NULL DEFAULT 'manual'
        CHECK (trigger_type IN ('manual','daily','weekly','interval','notify_only')),
    trigger_json TEXT NOT NULL DEFAULT '{}',
    rate_meta INTEGER NOT NULL DEFAULT 2000,
    rate_hash INTEGER NOT NULL DEFAULT 50,
    window_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running','paused','completed','failed','cancelled')),
    phase TEXT NOT NULL DEFAULT 'walk',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    seen_gen INTEGER NOT NULL DEFAULT 0,
    checkpoint_json TEXT NOT NULL DEFAULT '{}',
    stats_json TEXT NOT NULL DEFAULT '{}',
    incomplete_reason TEXT,
    error TEXT,
    dirs_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
    dev INTEGER NOT NULL,
    ino INTEGER NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    ctime_ns INTEGER NOT NULL,
    nlink INTEGER NOT NULL DEFAULT 1,
    sha256 TEXT,
    sample_hash TEXT,
    hash_verified_at TEXT,
    seen_gen INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'present',
    PRIMARY KEY (dev, ino)
);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(size);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_gen ON files(seen_gen);

CREATE TABLE IF NOT EXISTS file_paths (
    dev INTEGER NOT NULL,
    ino INTEGER NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    root_id INTEGER NOT NULL,
    seen_gen INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dev, ino, path)
);
CREATE INDEX IF NOT EXISTS idx_paths_name ON file_paths(name);

CREATE TABLE IF NOT EXISTS content_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    member_count INTEGER NOT NULL,
    wasted_bytes INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS name_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    member_count INTEGER NOT NULL,
    same_content INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS review_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('content','name')),
    group_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','reviewed','skipped','needs_recheck')),
    policy TEXT NOT NULL DEFAULT 'earliest_mtime',
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(kind, group_key)
);

CREATE TABLE IF NOT EXISTS review_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    dev INTEGER NOT NULL,
    ino INTEGER NOT NULL,
    path TEXT NOT NULL,
    size INTEGER,
    mtime_ns INTEGER,
    decision TEXT NOT NULL DEFAULT 'undecided'
        CHECK (decision IN ('undecided','keep','delete','skip')),
    UNIQUE(group_id, path)
);
CREATE INDEX IF NOT EXISTS idx_items_group ON review_items(group_id);

CREATE TABLE IF NOT EXISTS delete_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    total_items INTEGER NOT NULL DEFAULT 0,
    releasable_bytes INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    size INTEGER,
    mtime_ns INTEGER,
    sha256 TEXT,
    keep_path TEXT,
    recheck_status TEXT NOT NULL DEFAULT 'pending',
    group_id INTEGER
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT,
    created_at TEXT NOT NULL,
    read_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class Database:
    """Thread-safe wrapper around a single sqlite3 connection."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or str(config.db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self.init_schema()

    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            cur = self._conn.execute("SELECT MAX(version) AS v FROM schema_version")
            row = cur.fetchone()
            if not row or row["v"] is None:
                self._conn.execute(
                    "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, now_iso()),
                )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- low level helpers -------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return cur

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def executescript(self, script: str) -> None:
        with self._lock:
            self._conn.executescript(script)
            self._conn.commit()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return cur.fetchall()

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- domain helpers ----------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.query_one("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.commit()

    def audit(self, actor: str, action: str, detail: str = "") -> None:
        self.execute(
            "INSERT INTO audit_log(ts, actor, action, detail) VALUES (?,?,?,?)",
            (now_iso(), actor, action, detail),
        )
        self.commit()

    def notify(self, kind: str, title: str, body: str = "") -> None:
        self.execute(
            "INSERT INTO notifications(kind, title, body, created_at) VALUES (?,?,?,?)",
            (kind, title, body, now_iso()),
        )
        self.commit()


_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        config.ensure_dirs()
        _db = Database()
    return _db


def reset_db_for_tests(path: str) -> Database:
    global _db
    if _db is not None:
        _db.close()
    _db = Database(path)
    return _db
