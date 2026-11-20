"""Scan engine: metadata walk, incremental diff, candidate hashing, grouping.

Design constraints (see docs/03-tech design):
- never follow symlinks, never open a file for writing;
- metadata phase is cheap and can finish in minutes for 120k files;
- hashing is rate limited and only runs for true candidates (same size,
  same head/tail sample); a file is called a duplicate only when the full
  SHA-256 matches;
- every run is resumable from a directory checkpoint.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import stat as statmod
import threading
import time

from .db import Database, now_iso

log = logging.getLogger("dupe.scan")

SAMPLE_BYTES = 4096
HASH_CHUNK = 1024 * 1024
BATCH_FILES = 500
ERROR_LIMIT = 50


class RateLimiter:
    """Simple token bucket: at most units_per_sec units per second, in total."""

    def __init__(self, units_per_sec: float) -> None:
        self.rate = max(1.0, float(units_per_sec))
        self._start = time.monotonic()
        self._units = 0.0

    def consume(self, units: float) -> None:
        self._units += units
        target = self._start + self._units / self.rate
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(min(delay, 5.0))


class ScanCancelled(Exception):
    pass


class Scanner:
    """Owns the single background scan thread."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._thread: threading.Thread | None = None
        self._run_id: int | None = None
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def current_run_id(self) -> int | None:
        return self._run_id if self.is_running() else None

    def start(self, plan_id: int | None) -> int:
        with self._lock:
            if self.is_running():
                raise RuntimeError("SCAN_RUNNING")
            plan = None
            if plan_id is not None:
                plan = self.db.query_one("SELECT * FROM scan_plans WHERE id=?", (plan_id,))
                if not plan:
                    raise ValueError("方案不存在")
            run_id = self._create_run(plan_id)
            self._run_id = run_id
            self._thread = threading.Thread(
                target=self._run_guarded, args=(run_id, plan), daemon=True, name="dupe-scan"
            )
            self._thread.start()
            return run_id

    # -- internals ---------------------------------------------------------
    def _create_run(self, plan_id: int | None) -> int:
        gen = int(self.db.get_setting("scan_gen", "0") or "0") + 1
        self.db.set_setting("scan_gen", str(gen))
        self.db.execute(
            "INSERT INTO scan_runs(plan_id, status, phase, started_at, seen_gen) "
            "VALUES (?, 'running', 'walk', ?, ?)",
            (plan_id, now_iso(), gen),
        )
        self.db.commit()
        row = self.db.query_one("SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1")
        assert row is not None
        return int(row["id"])

    def _run_guarded(self, run_id: int, plan) -> None:
        try:
            self._run(run_id, plan)
        except ScanCancelled:
            self._finish(run_id, "cancelled", error=None)
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("scan failed")
            self._finish(run_id, "failed", error=str(exc))
        finally:
            with self._lock:
                self._run_id = None

    def _finish(self, run_id: int, status: str, error: str | None) -> None:
        self.db.execute(
            "UPDATE scan_runs SET status=?, finished_at=?, error=? WHERE id=?",
            (status, now_iso(), error, run_id),
        )
        self.db.commit()
        if status == "failed":
            self.db.notify("scan", "扫描失败", f"任务 #{run_id}: {error}")

    def _check_state(self, run_id: int) -> None:
        row = self.db.query_one("SELECT status FROM scan_runs WHERE id=?", (run_id,))
        if row is None:
            raise ScanCancelled()
        status = row["status"]
        if status == "running":
            return
        if status == "paused":
            while True:
                time.sleep(1.0)
                row = self.db.query_one("SELECT status FROM scan_runs WHERE id=?", (run_id,))
                if row is None or row["status"] == "cancelled":
                    raise ScanCancelled()
                if row["status"] == "running":
                    return
        raise ScanCancelled()

    def _update_stats(self, run_id: int, stats: dict, phase: str, dirs_seen: int) -> None:
        self.db.execute(
            "UPDATE scan_runs SET stats_json=?, phase=?, dirs_seen=? WHERE id=?",
            (json.dumps(stats, ensure_ascii=False), phase, dirs_seen, run_id),
        )
        self.db.commit()

    def _run(self, run_id: int, plan) -> None:
        run = self.db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
        assert run is not None
        gen = int(run["seen_gen"])
        roots = self._resolve_roots(plan)
        if not roots:
            raise RuntimeError("没有可扫描的目录，请先配置扫描根")
        include = _split_globs(plan["include_globs"] if plan else "")
        exclude = _split_globs(plan["exclude_globs"] if plan else "")
        rate_meta = float(plan["rate_meta"] if plan else 2000)
        rate_hash = float(plan["rate_hash"] if plan else 50)
        window = json.loads(plan["window_json"]) if plan and plan["window_json"] else {}
        stats = {
            "files_seen": 0, "files_indexed": 0, "hashes_computed": 0,
            "bytes_hashed": 0, "dirs_scanned": 0, "errors": [],
        }
        meta_limiter = RateLimiter(rate_meta)
        hash_limiter = RateLimiter(rate_hash * 1024 * 1024)

        self._walk_all(run_id, gen, roots, include, exclude, meta_limiter, window, stats)
        self._finalize_walk(gen, roots, stats)
        self._check_state(run_id)
        self._update_stats(run_id, stats, "hash", stats["dirs_scanned"])

        self._hash_candidates(run_id, hash_limiter, window, stats)
        self._check_state(run_id)
        self._update_stats(run_id, stats, "group", stats["dirs_scanned"])

        counts = self._rebuild_groups()
        from . import review as review_mod  # local import avoids a cycle

        counts.update(review_mod.sync_groups(self.db))
        stats.update(counts)
        self._update_stats(run_id, stats, "done", stats["dirs_scanned"])
        self.db.execute(
            "UPDATE scan_runs SET status='completed', finished_at=?, stats_json=? WHERE id=?",
            (now_iso(), json.dumps(stats, ensure_ascii=False), run_id),
        )
        self.db.commit()
        self.db.notify(
            "scan", "扫描完成",
            f"{stats['files_indexed']} 个文件，发现 {counts.get('content_groups', 0)} 个内容重复组",
        )

    def _resolve_roots(self, plan) -> list:
        roots = self.db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
        if plan and plan["roots_json"]:
            wanted = set(json.loads(plan["roots_json"]))
            roots = [r for r in roots if r["id"] in wanted]
        return list(roots)

    def _walk_all(self, run_id, gen, roots, include, exclude, limiter, window, stats) -> None:
        batch = 0
        for root in roots:
            base = root["mount_path"]
            stack = [base]
            while stack:
                self._wait_window(window)
                dirpath = stack.pop()
                self._check_state(run_id)
                try:
                    entries = list(os.scandir(dirpath))
                except OSError as exc:
                    _record_error(stats, f"{dirpath}: {exc.strerror}")
                    continue
                stats["dirs_scanned"] += 1
                for entry in entries:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        _record_error(stats, f"{entry.path}: {exc.strerror}")
                        continue
                    rel = os.path.relpath(entry.path, base)
                    if _excluded(rel, exclude):
                        continue
                    if include and not _included(rel, include):
                        continue
                    if statmod.S_ISDIR(st.st_mode):
                        stack.append(entry.path)
                        continue
                    if not statmod.S_ISREG(st.st_mode):
                        continue  # symlinks, sockets, devices are never followed
                    limiter.consume(1)
                    self._upsert_file(st, entry.path, entry.name, root["id"], gen)
                    stats["files_seen"] += 1
                    stats["files_indexed"] += 1
                    batch += 1
                    if batch >= BATCH_FILES:
                        self.db.commit()
                        self._update_stats(run_id, stats, "walk", stats["dirs_scanned"])
                        batch = 0
                self.db.commit()
                self._update_stats(run_id, stats, "walk", stats["dirs_scanned"])
        self.db.commit()

    def _upsert_file(self, st, path: str, name: str, root_id: int, gen: int) -> None:
        db = self.db
        row = db.query_one(
            "SELECT size, mtime_ns, ctime_ns, sha256 FROM files WHERE dev=? AND ino=?",
            (st.st_dev, st.st_ino),
        )
        if row is None:
            db.execute(
                "INSERT INTO files(dev, ino, size, mtime_ns, ctime_ns, nlink, seen_gen) "
                "VALUES (?,?,?,?,?,?,?)",
                (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                 st.st_nlink, gen),
            )
        else:
            changed = (
                row["size"] != st.st_size
                or row["mtime_ns"] != st.st_mtime_ns
                or row["ctime_ns"] != st.st_ctime_ns
            )
            if changed:
                db.execute(
                    "UPDATE files SET size=?, mtime_ns=?, ctime_ns=?, nlink=?, sha256=NULL, "
                    "sample_hash=NULL, hash_verified_at=NULL, seen_gen=?, status='present' "
                    "WHERE dev=? AND ino=?",
                    (st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink, gen,
                     st.st_dev, st.st_ino),
                )
            else:
                db.execute(
                    "UPDATE files SET seen_gen=?, status='present' WHERE dev=? AND ino=?",
                    (gen, st.st_dev, st.st_ino),
                )
        db.execute(
            "INSERT INTO file_paths(dev, ino, path, name, root_id, seen_gen) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(dev, ino, path) DO UPDATE SET "
            "name=excluded.name, root_id=excluded.root_id, seen_gen=excluded.seen_gen",
            (st.st_dev, st.st_ino, path, name, root_id, gen),
        )

    def _finalize_walk(self, gen: int, roots, stats: dict) -> None:
        db = self.db
        for root in roots:
            db.execute("DELETE FROM file_paths WHERE root_id=? AND seen_gen<?", (root["id"], gen))
        db.commit()
        db.execute(
            "UPDATE files SET status='missing' WHERE seen_gen<? AND NOT EXISTS "
            "(SELECT 1 FROM file_paths p WHERE p.dev=files.dev AND p.ino=files.ino)",
            (gen,),
        )
        db.commit()
        counts = json.loads(db.get_setting("dir_counts_json", "{}") or "{}")
        prev_total = sum(counts.values())
        if prev_total and stats["dirs_scanned"] < prev_total * 0.8:
            db.execute(
                "UPDATE scan_runs SET incomplete_reason=? WHERE seen_gen=?",
                ("本次扫描目录数比上次少 20% 以上，可能挂载或权限异常", gen),
            )
            db.commit()
        db.set_setting(
            "dir_counts_json",
            json.dumps({str(r["id"]): stats["dirs_scanned"] for r in roots}),
        )

    # ---- hashing ---------------------------------------------------------
    def _hash_candidates(self, run_id, limiter, window, stats) -> None:
        db = self.db
        sizes = db.query(
            "SELECT size FROM files WHERE status='present' GROUP BY size "
            "HAVING COUNT(*)>=2 AND size>0 ORDER BY size"
        )
        for row in sizes:
            self._wait_window(window)
            self._check_state(run_id)
            # Every present member of the size bucket is a candidate, including
            # files that already carry a cached sha256. Restricting the query to
            # "sha256 IS NULL" used to hide the cached members, so a newly added
            # duplicate was sampled alone (bucket of 1), skipped, and never
            # joined its content group (review P1-02). Cached hashes stay valid
            # because the metadata phase clears sha256 whenever the
            # size/mtime/ctime fingerprint changes.
            members = db.query(
                "SELECT dev, ino, size, sha256 FROM files WHERE size=? AND status='present'",
                (row["size"],),
            )
            unhashed = [m for m in members if not m["sha256"]]
            if not unhashed:
                continue
            if any(m["sha256"] for m in members):
                # Cached members give us something to compare against, so one
                # full SHA-256 per new member settles duplicate membership
                # directly (at most O(new files) full hashes per size bucket).
                self._hash_members(run_id, unhashed, limiter, stats)
                db.commit()
                continue
            # Nothing in this bucket has been hashed yet: keep the cheap
            # two-stage path (head/tail sample first, full hash only for sample
            # collisions).
            sample_groups: dict[str, list] = {}
            for m in unhashed:
                path = self._first_path(m["dev"], m["ino"])
                if path is None:
                    continue
                try:
                    if m["size"] <= 2 * SAMPLE_BYTES:
                        digest, nbytes = _sha256_file(path, limiter)
                        limiter.consume(nbytes)
                        stats["bytes_hashed"] += nbytes
                        stats["hashes_computed"] += 1
                        db.execute(
                            "UPDATE files SET sha256=?, hash_verified_at=? WHERE dev=? AND ino=?",
                            (digest, now_iso(), m["dev"], m["ino"]),
                        )
                        continue
                    digest, nbytes = _sample_hash(path)
                    limiter.consume(nbytes)
                    stats["bytes_hashed"] += nbytes
                    sample_groups.setdefault(digest, []).append((m, path))
                except OSError as exc:
                    _record_error(stats, f"{path}: {exc.strerror}")
            db.commit()
            for digest, items in sample_groups.items():
                if len(items) < 2:
                    continue
                for m, path in items:
                    self._check_state(run_id)
                    try:
                        full, nbytes = _sha256_file(path, limiter)
                    except OSError as exc:
                        _record_error(stats, f"{path}: {exc.strerror}")
                        continue
                    limiter.consume(nbytes)
                    stats["bytes_hashed"] += nbytes
                    stats["hashes_computed"] += 1
                    db.execute(
                        "UPDATE files SET sha256=?, sample_hash=?, hash_verified_at=? "
                        "WHERE dev=? AND ino=?",
                        (full, digest, now_iso(), m["dev"], m["ino"]),
                    )
                db.commit()
        db.commit()

    def _first_path(self, dev: int, ino: int) -> str | None:
        row = self.db.query_one(
            "SELECT path FROM file_paths WHERE dev=? AND ino=? LIMIT 1", (dev, ino)
        )
        return row["path"] if row else None

    def _hash_members(self, run_id, members, limiter, stats) -> None:
        """Full-hash the given (dev, ino) rows and persist the result."""
        for m in members:
            self._check_state(run_id)
            path = self._first_path(m["dev"], m["ino"])
            if path is None:
                continue
            try:
                full, nbytes = _sha256_file(path, limiter)
            except OSError as exc:
                _record_error(stats, f"{path}: {exc.strerror}")
                continue
            limiter.consume(nbytes)
            stats["bytes_hashed"] += nbytes
            stats["hashes_computed"] += 1
            self.db.execute(
                "UPDATE files SET sha256=?, hash_verified_at=? WHERE dev=? AND ino=?",
                (full, now_iso(), m["dev"], m["ino"]),
            )

    # ---- grouping --------------------------------------------------------
    def _rebuild_groups(self) -> dict:
        db = self.db
        db.execute("DELETE FROM content_groups")
        db.execute("DELETE FROM name_groups")
        content = db.query(
            "SELECT sha256, size, COUNT(*) AS n FROM files "
            "WHERE sha256 IS NOT NULL AND status='present' GROUP BY sha256 HAVING n>=2"
        )
        for row in content:
            db.execute(
                "INSERT INTO content_groups(sha256, size, member_count, wasted_bytes, updated_at) "
                "VALUES (?,?,?,?,?)",
                (row["sha256"], row["size"], row["n"], row["size"] * (row["n"] - 1), now_iso()),
            )
        names = db.query(
            "SELECT p.name AS name, COUNT(DISTINCT f.ino) AS n, "
            "COUNT(DISTINCT COALESCE(f.sha256,'?')) AS shas, "
            "SUM(CASE WHEN f.sha256 IS NULL THEN 1 ELSE 0 END) AS unhashed "
            "FROM file_paths p JOIN files f ON f.dev=p.dev AND f.ino=p.ino "
            "WHERE f.status='present' GROUP BY p.name HAVING n>=2 ORDER BY n DESC"
        )
        for row in names:
            same_content = 1 if row["shas"] == 1 and row["unhashed"] == 0 else 0
            db.execute(
                "INSERT INTO name_groups(name, member_count, same_content, updated_at) "
                "VALUES (?,?,?,?)",
                (row["name"], row["n"], same_content, now_iso()),
            )
        db.commit()
        return {"content_groups": len(content), "name_groups": len(names)}

    # ---- window ----------------------------------------------------------
    def _wait_window(self, window: dict) -> None:
        start, end = window.get("start"), window.get("end")
        if not start or not end:
            return
        while not _in_window(time.strftime("%H:%M"), start, end):
            time.sleep(30)


def _in_window(now: str, start: str, end: str) -> bool:
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


def _split_globs(value: str) -> list[str]:
    if not value:
        return []
    return [g.strip() for g in value.split(",") if g.strip()]


def _excluded(rel: str, globs: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(rel), g) for g in globs
    )


def _included(rel: str, globs: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(rel), g) for g in globs
    )


def _record_error(stats: dict, message: str) -> None:
    errors = stats.setdefault("errors", [])
    if len(errors) < ERROR_LIMIT:
        errors.append(message)


def _sample_hash(path: str) -> tuple[str, int]:
    st = os.stat(path, follow_symlinks=False)
    size = st.st_size
    h = hashlib.sha256()
    nbytes = 0
    with open(path, "rb", buffering=0) as fh:
        head = fh.read(SAMPLE_BYTES)
        h.update(head)
        nbytes += len(head)
        fh.seek(max(0, size - SAMPLE_BYTES))
        tail = fh.read(SAMPLE_BYTES)
        h.update(tail)
        nbytes += len(tail)
    h.update(str(size).encode("ascii"))
    return h.hexdigest(), nbytes


def _sha256_file(path: str, limiter: RateLimiter) -> tuple[str, int]:
    h = hashlib.sha256()
    nbytes = 0
    with open(path, "rb", buffering=0) as fh:
        while True:
            chunk = fh.read(HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            nbytes += len(chunk)
            limiter.consume(0)
    return h.hexdigest(), nbytes
