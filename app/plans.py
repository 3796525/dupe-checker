"""Delete-plan generation and pre-deletion re-verification.

The tool never deletes anything. It produces a reviewed list of paths that
the operator may delete manually on the NAS. Every item is re-verified at
plan time: the file must still exist, keep its size/mtime, and its content
hash must still match the index.
"""
from __future__ import annotations

import hashlib
import os

from .db import Database, now_iso

CHUNK = 1024 * 1024


class PlanError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def recheck_path(path: str, expected_size: int | None, expected_mtime_ns: int | None,
                 expected_sha: str | None) -> tuple[str, str | None]:
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return "missing", None
    if expected_size is not None and st.st_size != expected_size:
        return "changed", None
    if expected_mtime_ns is not None and st.st_mtime_ns != expected_mtime_ns:
        return "changed", None
    try:
        digest = _hash_file(path)
    except OSError:
        return "error", None
    if expected_sha and digest != expected_sha:
        return "changed", digest
    return "consistent", digest


def _group_keep_and_kind(db: Database, group_id: int, kind: str,
                         grows: list) -> tuple[object, dict | None]:
    """Re-validate the safety invariants of one reviewed group at plan time."""
    keep = db.query_one(
        "SELECT * FROM review_items WHERE group_id=? AND decision='keep' "
        "ORDER BY mtime_ns ASC, path ASC LIMIT 1",
        (group_id,),
    )
    if keep is None:
        return None, {"group_id": group_id, "kind": kind, "reason": "no_keep"}
    f = db.query_one("SELECT sha256 FROM files WHERE dev=? AND ino=?", (keep["dev"], keep["ino"]))
    keep_sha = f["sha256"] if f else None
    state, _ = recheck_path(keep["path"], keep["size"], keep["mtime_ns"], keep_sha)
    if state != "consistent":
        return None, {"group_id": group_id, "kind": kind, "reason": f"keep_{state}"}
    if kind == "name":
        # A same-name group may only be deleted from when the index proves that
        # every member has identical content; otherwise the operator must use
        # the content view (review P1-06).
        shas = {keep_sha} if keep_sha else set()
        verified = bool(keep_sha)
        for row in grows:
            g = db.query_one(
                "SELECT sha256 FROM files WHERE dev=? AND ino=?", (row["dev"], row["ino"])
            )
            sha = g["sha256"] if g else None
            if not sha:
                verified = False
                break
            shas.add(sha)
        if not verified or len(shas) != 1:
            return None, {"group_id": group_id, "kind": kind, "reason": "name_unverified"}
    return keep, None


def generate_plan(db: Database, note: str = "") -> dict:
    rows = db.query(
        "SELECT i.*, g.id AS group_id, g.kind FROM review_items i "
        "JOIN review_groups g ON g.id=i.group_id "
        "WHERE g.status='reviewed' AND i.decision='delete' ORDER BY i.id"
    )
    if not rows:
        raise PlanError("VALIDATION_ERROR", "没有已审核通过的待删除项")

    by_group: dict[int, list] = {}
    for row in rows:
        by_group.setdefault(row["group_id"], []).append(row)

    # Second line of defence for BR-002/FR-018: even if a group somehow ends up
    # in the database without a keep item, no plan row is produced for it.
    accepted: list[tuple] = []
    violations: list[dict] = []
    for group_id, grows in by_group.items():
        keep, violation = _group_keep_and_kind(db, group_id, grows[0]["kind"], grows)
        if violation is not None:
            violations.append(violation)
        else:
            accepted.append((keep, grows))
    if not accepted:
        raise PlanError(
            "VALIDATION_ERROR",
            "没有可安全删除的项：所选分组均未通过保留项或内容一致性复核",
        )

    db.execute(
        "INSERT INTO delete_plans(note, status, created_at) VALUES (?, 'draft', ?)",
        (note, now_iso()),
    )
    plan_id = int(db.query_one("SELECT id FROM delete_plans ORDER BY id DESC LIMIT 1")["id"])
    total = 0
    total_bytes = 0
    counts = {"consistent": 0, "changed": 0, "missing": 0, "error": 0}
    for keep, grows in accepted:
        keep_path = keep["path"]
        for row in grows:
            f = db.query_one(
                "SELECT sha256 FROM files WHERE dev=? AND ino=?", (row["dev"], row["ino"])
            )
            expected_sha = f["sha256"] if f else None
            state, sha_now = recheck_path(row["path"], row["size"], row["mtime_ns"], expected_sha)
            counts[state] = counts.get(state, 0) + 1
            if state == "consistent":
                total += 1
                total_bytes += int(row["size"] or 0)
            db.execute(
                "INSERT INTO plan_items(plan_id, path, size, mtime_ns, sha256, keep_path, "
                "recheck_status, group_id, kind) VALUES (?,?,?,?,?,?,?,?,?)",
                (plan_id, row["path"], row["size"], row["mtime_ns"], sha_now or expected_sha,
                 keep_path, state, row["group_id"], row["kind"]),
            )
    clean = counts["changed"] == 0 and counts["missing"] == 0
    status = "final" if clean and not violations else "needs_review"
    db.execute(
        "UPDATE delete_plans SET status=?, total_items=?, releasable_bytes=? WHERE id=?",
        (status, total, total_bytes, plan_id),
    )
    db.commit()
    db.audit("user", "plan.generate", f"plan={plan_id} items={total} violations={len(violations)}")
    db.notify(
        "plan",
        "删除方案已生成",
        f"方案 #{plan_id} 共 {total} 项，需复核 {counts['changed'] + counts['missing']} 项，"
        f"未通过安全复核的分组 {len(violations)} 个",
    )
    return {
        "id": plan_id,
        "status": status,
        "total_items": total,
        "releasable_bytes": total_bytes,
        "counts": counts,
        "violations": violations,
    }


def plan_detail(db: Database, plan_id: int) -> dict | None:
    p = db.query_one("SELECT * FROM delete_plans WHERE id=?", (plan_id,))
    if p is None:
        return None
    items = db.query("SELECT * FROM plan_items WHERE plan_id=? ORDER BY id", (plan_id,))
    counts: dict[str, int] = {}
    for i in items:
        counts[i["recheck_status"]] = counts.get(i["recheck_status"], 0) + 1
    return {
        "id": p["id"],
        "note": p["note"],
        "status": p["status"],
        "total_items": p["total_items"],
        "releasable_bytes": p["releasable_bytes"],
        "created_at": p["created_at"],
        "counts": counts,
        "items": [
            {
                "id": i["id"],
                "path": i["path"],
                "size": i["size"],
                "mtime_ns": i["mtime_ns"],
                "sha256": i["sha256"],
                "keep_path": i["keep_path"],
                "recheck_status": i["recheck_status"],
                "group_id": i["group_id"],
                # The review group kind (content / name) is part of the item's
                # meaning, not an implementation detail: a same-name group may be
                # a non-duplicate and has to stay distinguishable from a content
                # duplicate in the plan page and in every export (review P1-06).
                "kind": i["kind"],
            }
            for i in items
        ],
    }


def list_plans(db: Database) -> list[dict]:
    rows = db.query("SELECT * FROM delete_plans ORDER BY id DESC")
    return [dict(r) for r in rows]
