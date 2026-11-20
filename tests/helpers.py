"""Shared helpers for the test suite."""
import hashlib
from pathlib import Path

from app.db import now_iso
from app.scanner import Scanner

PAYLOAD = b"duplicate-bytes-" * 2000  # 32 KB, bigger than the 8 KB sample threshold
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()


def add_root(db, path: Path, label: str | None = None) -> int:
    db.execute(
        "INSERT INTO scan_roots(mount_path, label, enabled, created_at) VALUES (?,?,1,?)",
        (str(path), label or path.name, now_iso()),
    )
    db.commit()
    return int(db.query_one("SELECT id FROM scan_roots WHERE mount_path=?", (str(path),))["id"])


def build_tree(root: Path) -> None:
    (root / "a").mkdir()
    (root / "b").mkdir()
    (root / "c").mkdir()
    (root / "a" / "dup.txt").write_bytes(PAYLOAD)
    (root / "b" / "dup_copy.txt").write_bytes(PAYLOAD)
    (root / "c" / "unique.txt").write_bytes(b"only-here-" * 100)
    (root / "a" / "same_name.txt").write_bytes(b"content-A-" * 100)
    (root / "c" / "same_name.txt").write_bytes(b"content-B-" * 100)


def add_plan(db, root_id: int, **kwargs) -> int:
    db.execute(
        "INSERT INTO scan_plans(name, roots_json, include_globs, exclude_globs, trigger_type, "
        "trigger_json, rate_meta, rate_hash, window_json, enabled, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,1,?,?)",
        (
            kwargs.get("name", "test plan"),
            f"[{root_id}]",
            kwargs.get("include_globs", ""),
            kwargs.get("exclude_globs", ""),
            kwargs.get("trigger_type", "manual"),
            kwargs.get("trigger_json", "{}"),
            kwargs.get("rate_meta", 100000),
            kwargs.get("rate_hash", 10000),
            kwargs.get("window_json", "{}"),
            now_iso(),
            now_iso(),
        ),
    )
    db.commit()
    return int(db.query_one("SELECT id FROM scan_plans ORDER BY id DESC LIMIT 1")["id"])


def run_scan(db, plan_id: int | None = None, timeout: float = 120.0) -> dict:
    engine = Scanner(db)
    run_id = engine.start(plan_id)
    engine._thread.join(timeout)
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    assert row is not None
    data = dict(row)
    assert data["status"] == "completed", f"scan failed: {data['error']}"
    return data
