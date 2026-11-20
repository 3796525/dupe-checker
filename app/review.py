"""Review workflow: turn duplicate groups into reviewable units with decisions."""
from __future__ import annotations

from .db import Database, now_iso

KINDS = ("content", "name")


class ReviewError(Exception):
    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


def sync_groups(db: Database) -> dict:
    """Create/refresh review groups from current content/name groups."""
    # --- content groups: one review group per sha256 ---
    rows = db.query("SELECT sha256, size, member_count FROM content_groups ORDER BY sha256")
    live_keys = set()
    for row in rows:
        key = row["sha256"]
        live_keys.add(key)
        members = db.query(
            "SELECT p.path, p.ino, p.dev, f.size, f.mtime_ns, f.sha256 "
            "FROM file_paths p JOIN files f ON f.dev=p.dev AND f.ino=p.ino "
            "WHERE f.sha256=? AND f.status='present' ORDER BY f.mtime_ns ASC, p.path ASC",
            (key,),
        )
        _ensure_group(db, "content", key, members)
    # drop content groups that no longer exist
    for rg in db.query("SELECT id, group_key FROM review_groups WHERE kind='content'"):
        if rg["group_key"] not in live_keys:
            db.execute("DELETE FROM review_items WHERE group_id=?", (rg["id"],))
            db.execute("DELETE FROM review_groups WHERE id=?", (rg["id"],))

    # --- name groups ---
    names = db.query("SELECT name FROM name_groups ORDER BY name")
    live_names = set()
    for row in names:
        key = row["name"]
        live_names.add(key)
        members = db.query(
            "SELECT p.path, p.ino, p.dev, f.size, f.mtime_ns, f.sha256 "
            "FROM file_paths p JOIN files f ON f.dev=p.dev AND f.ino=p.ino "
            "WHERE p.name=? AND f.status='present' "
            "ORDER BY f.mtime_ns ASC, p.path ASC",
            (key,),
        )
        _ensure_group(db, "name", key, members)
    for rg in db.query("SELECT id, group_key FROM review_groups WHERE kind='name'"):
        if rg["group_key"] not in live_names:
            db.execute("DELETE FROM review_items WHERE group_id=?", (rg["id"],))
            db.execute("DELETE FROM review_groups WHERE id=?", (rg["id"],))
    db.commit()
    total = db.query_one("SELECT COUNT(*) AS n FROM review_groups")
    return {
        "review_groups": int(total["n"]) if total else 0,
        "content_groups": len(live_keys),
        "name_groups": len(live_names),
    }


def _ensure_group(db: Database, kind: str, key: str, members) -> None:
    rg = db.query_one(
        "SELECT * FROM review_groups WHERE kind=? AND group_key=?", (kind, key)
    )
    now = now_iso()
    if rg is None:
        db.execute(
            "INSERT INTO review_groups(kind, group_key, status, policy, created_at, updated_at) "
            "VALUES (?,?,'pending','earliest_mtime',?,?)",
            (kind, key, now, now),
        )
        rg_id = int(db.query_one("SELECT id FROM review_groups ORDER BY id DESC LIMIT 1")["id"])
        status = "pending"
    else:
        rg_id = int(rg["id"])
        status = rg["status"]
    current = {
        r["path"]: r for r in db.query("SELECT path FROM review_items WHERE group_id=?", (rg_id,))
    }
    member_paths = set()
    for m in members:
        member_paths.add(m["path"])
        if m["path"] in current:
            db.execute(
                "UPDATE review_items SET size=?, mtime_ns=?, dev=?, ino=? "
                "WHERE group_id=? AND path=?",
                (m["size"], m["mtime_ns"], m["dev"], m["ino"], rg_id, m["path"]),
            )
        else:
            db.execute(
                "INSERT INTO review_items(group_id, dev, ino, path, size, mtime_ns, decision) "
                "VALUES (?,?,?,?,?,?,'undecided')",
                (rg_id, m["dev"], m["ino"], m["path"], m["size"], m["mtime_ns"]),
            )
    removed = [p for p in current if p not in member_paths]
    for p in removed:
        db.execute("DELETE FROM review_items WHERE group_id=? AND path=?", (rg_id, p))
    if removed or any(m["path"] not in current for m in members):
        if status in ("reviewed", "skipped"):
            db.execute(
                "UPDATE review_groups SET status='needs_recheck', updated_at=? WHERE id=?",
                (now, rg_id),
            )
            status = "needs_recheck"
    # default decision: earliest mtime keeps, only when nothing decided yet
    decided = db.query_one(
        "SELECT COUNT(*) AS n FROM review_items WHERE group_id=? AND decision!='undecided'",
        (rg_id,),
    )
    if decided and decided["n"] == 0:
        first = db.query_one(
            "SELECT id FROM review_items WHERE group_id=? ORDER BY mtime_ns ASC, path ASC LIMIT 1",
            (rg_id,),
        )
        if first:
            db.execute(
                "UPDATE review_items SET decision='keep' WHERE id=?", (first["id"],)
            )
    db.execute("UPDATE review_groups SET updated_at=? WHERE id=?", (now, rg_id))


def list_groups(
    db: Database,
    kind: str | None = None,
    status: str | None = None,
    query: str | None = None,
    min_size: int | None = None,
    cursor: int = 0,
    limit: int = 50,
) -> dict:
    limit = max(1, min(200, limit))
    sql = [
        "SELECT g.*, COUNT(i.id) AS member_count, "
        "COALESCE(SUM(CASE WHEN i.decision='delete' THEN i.size ELSE 0 END),0) AS planned_bytes, "
        "COALESCE(SUM(i.size),0) AS group_bytes "
        "FROM review_groups g LEFT JOIN review_items i ON i.group_id=g.id WHERE 1=1"
    ]
    params: list = []
    if kind:
        sql.append("AND g.kind=?")
        params.append(kind)
    if status:
        sql.append("AND g.status=?")
        params.append(status)
    if query:
        sql.append(
            "AND (g.group_key LIKE ? OR EXISTS (SELECT 1 FROM review_items x "
            "WHERE x.group_id=g.id AND x.path LIKE ?))"
        )
        params.extend([f"%{query}%", f"%{query}%"])
    if min_size:
        sql.append("AND EXISTS (SELECT 1 FROM review_items y WHERE y.group_id=g.id AND y.size>=?)")
        params.append(min_size)
    if cursor:
        sql.append("AND g.id>?")
        params.append(cursor)
    sql.append("GROUP BY g.id HAVING member_count>=2")
    sql.append("ORDER BY g.id ASC LIMIT ?")
    params.append(limit + 1)
    rows = db.query(" ".join(sql), params)
    items = []
    for r in rows[:limit]:
        items.append(
            {
                "id": r["id"],
                "kind": r["kind"],
                "key": r["group_key"],
                "status": r["status"],
                "policy": r["policy"],
                "member_count": r["member_count"],
                "planned_bytes": r["planned_bytes"],
                "group_bytes": r["group_bytes"],
            }
        )
    next_cursor = items[-1]["id"] if (len(rows) > limit and items) else None
    return {"items": items, "next_cursor": next_cursor}


def group_detail(db: Database, group_id: int) -> dict | None:
    g = db.query_one("SELECT * FROM review_groups WHERE id=?", (group_id,))
    if g is None:
        return None
    items = db.query(
        "SELECT * FROM review_items WHERE group_id=? ORDER BY mtime_ns ASC, path ASC",
        (group_id,),
    )
    return {
        "id": g["id"],
        "kind": g["kind"],
        "key": g["group_key"],
        "status": g["status"],
        "policy": g["policy"],
        "items": [
            {
                "id": i["id"],
                "path": i["path"],
                "size": i["size"],
                "mtime_ns": i["mtime_ns"],
                "decision": i["decision"],
            }
            for i in items
        ],
    }


def save_decisions(db: Database, group_id: int, policy: str | None, decisions: list[dict]) -> dict:
    g = db.query_one("SELECT * FROM review_groups WHERE id=?", (group_id,))
    if g is None:
        raise ReviewError("NOT_FOUND", "分组不存在")
    if policy:
        db.execute("UPDATE review_groups SET policy=? WHERE id=?", (policy, group_id))
    valid = {"keep", "delete", "skip"}
    for d in decisions:
        decision = d.get("decision")
        if decision not in valid:
            raise ReviewError("VALIDATION_ERROR", f"非法决策: {decision}")
        db.execute(
            "UPDATE review_items SET decision=? WHERE group_id=? AND id=?",
            (decision, group_id, d.get("item_id")),
        )
    items = db.query("SELECT decision FROM review_items WHERE group_id=?", (group_id,))
    keeps = sum(1 for i in items if i["decision"] == "keep")
    deletes = sum(1 for i in items if i["decision"] == "delete")
    if deletes > 0 and keeps == 0:
        db.commit()
        raise ReviewError(
            "GROUP_KEEP_VIOLATION", "每组至少保留 1 份，请先取消一个删除项", {"group_id": group_id}
        )
    all_decided = all(i["decision"] in ("keep", "delete") for i in items)
    status = "reviewed" if all_decided and deletes > 0 else (g["status"] if deletes == 0 else "pending")
    if deletes == 0 and all_decided:
        status = "skipped"
    db.execute(
        "UPDATE review_groups SET status=?, updated_at=? WHERE id=?",
        (status, now_iso(), group_id),
    )
    db.commit()
    db.audit("user", "review.save", f"group={group_id} keep={keeps} delete={deletes}")
    return {"id": group_id, "status": status, "keeps": keeps, "deletes": deletes}


def skip_group(db: Database, group_id: int) -> dict:
    db.execute(
        "UPDATE review_groups SET status='skipped', updated_at=? WHERE id=?",
        (now_iso(), group_id),
    )
    db.commit()
    return {"id": group_id, "status": "skipped"}


def recheck_group(db: Database, group_id: int) -> list[dict]:
    import os

    items = db.query("SELECT * FROM review_items WHERE group_id=?", (group_id,))
    results = []
    for i in items:
        state = "missing"
        size = None
        try:
            st = os.stat(i["path"], follow_symlinks=False)
            size = st.st_size
            if st.st_size != i["size"]:
                state = "changed"
            elif st.st_mtime_ns != i["mtime_ns"]:
                state = "changed"
            else:
                state = "consistent"
        except OSError:
            state = "missing"
        results.append(
            {"item_id": i["id"], "path": i["path"], "state": state, "size_now": size}
        )
    return results


def stats(db: Database) -> dict:
    rows = db.query("SELECT status, COUNT(*) AS n FROM review_groups GROUP BY status")
    by_status = {r["status"]: r["n"] for r in rows}
    agg = db.query_one(
        "SELECT COALESCE(SUM(CASE WHEN decision='delete' THEN size ELSE 0 END),0) AS bytes, "
        "COUNT(*) AS n FROM review_items"
    )
    total = db.query_one("SELECT COUNT(*) AS n FROM review_items")
    groups = db.query_one("SELECT COUNT(*) AS n FROM review_groups")
    return {
        "total_groups": groups["n"],
        "total_items": total["n"],
        "by_status": by_status,
        "pending": by_status.get("pending", 0),
        "reviewed": by_status.get("reviewed", 0),
        "skipped": by_status.get("skipped", 0),
        "needs_recheck": by_status.get("needs_recheck", 0),
        "planned_delete_bytes": agg["bytes"],
    }
