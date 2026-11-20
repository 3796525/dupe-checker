"""Review decisions, recheck and delete-plan generation."""
import os
import time

import pytest

from app import plans, review
from helpers import PAYLOAD, add_root, build_tree, run_scan


def _content_group(db):
    data = review.list_groups(db, kind="content", status=None)
    assert data["items"], "expected content duplicate groups"
    return data["items"][0]


def test_delete_without_keep_is_rejected(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    items = [{"item_id": i["id"], "decision": "delete"} for i in detail["items"]]
    with pytest.raises(review.ReviewError) as err:
        review.save_decisions(db, g["id"], None, items)
    assert err.value.code == "GROUP_KEEP_VIOLATION"


def test_save_keep_plus_delete_marks_group_reviewed(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    keep, delete = detail["items"][0], detail["items"][1]
    result = review.save_decisions(
        db, g["id"], "earliest_mtime",
        [{"item_id": keep["id"], "decision": "keep"}, {"item_id": delete["id"], "decision": "delete"}],
    )
    assert result["status"] == "reviewed"
    assert result["keeps"] == 1 and result["deletes"] == 1
    row = db.query_one("SELECT status FROM review_groups WHERE id=?", (g["id"],))
    assert row["status"] == "reviewed"


def test_skip_group(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    assert review.skip_group(db, g["id"])["status"] == "skipped"
    assert db.query_one("SELECT status FROM review_groups WHERE id=?", (g["id"],))["status"] == "skipped"


def test_recheck_reports_missing_and_changed(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    first, second = detail["items"][0], detail["items"][1]
    os.unlink(first["path"])
    with open(second["path"], "ab") as fh:
        fh.write(b"tail")
    states = {r["path"]: r["state"] for r in review.recheck_group(db, g["id"])}
    assert states[first["path"]] == "missing"
    assert states[second["path"]] == "changed"


def test_generate_plan_only_includes_approved_deletes(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    keep, delete = detail["items"][0], detail["items"][1]
    review.save_decisions(db, g["id"], None, [
        {"item_id": keep["id"], "decision": "keep"},
        {"item_id": delete["id"], "decision": "delete"},
    ])
    result = plans.generate_plan(db, "夜间清理")
    assert result["status"] == "final"
    assert result["total_items"] == 1
    assert result["counts"]["consistent"] == 1
    assert result["releasable_bytes"] == os.path.getsize(delete["path"])

    detail_plan = plans.plan_detail(db, result["id"])
    assert detail_plan["items"][0]["path"] == delete["path"]
    assert detail_plan["items"][0]["keep_path"] == keep["path"]


def test_generate_plan_without_review_fails(db, root):
    with pytest.raises(plans.PlanError):
        plans.generate_plan(db)


def test_changed_file_after_review_is_flagged(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    keep, delete = detail["items"][0], detail["items"][1]
    review.save_decisions(db, g["id"], None, [
        {"item_id": keep["id"], "decision": "keep"},
        {"item_id": delete["id"], "decision": "delete"},
    ])
    with open(delete["path"], "ab") as fh:
        fh.write(b"mutated")
    result = plans.generate_plan(db)
    assert result["status"] == "needs_review"
    assert result["counts"]["changed"] == 1
    assert result["total_items"] == 0


def test_stats_track_pending_and_planned_bytes(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    keep, delete = detail["items"][0], detail["items"][1]
    review.save_decisions(db, g["id"], None, [
        {"item_id": keep["id"], "decision": "keep"},
        {"item_id": delete["id"], "decision": "delete"},
    ])
    st = review.stats(db)
    assert st["total_groups"] >= 1
    assert st["planned_delete_bytes"] >= len(PAYLOAD)
