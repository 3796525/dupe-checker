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


# --- regression tests for review P0-01: keep invariant must be transactional ---

def test_violating_submission_rolls_back_previous_state(db, root):
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
    # Second request tries to delete the only kept copy of the group.
    with pytest.raises(review.ReviewError) as err:
        review.save_decisions(db, g["id"], None, [
            {"item_id": keep["id"], "decision": "delete"},
        ])
    assert err.value.code == "GROUP_KEEP_VIOLATION"
    decisions = {
        row["id"]: row["decision"]
        for row in db.query("SELECT id, decision FROM review_items WHERE group_id=?", (g["id"],))
    }
    assert decisions[keep["id"]] == "keep"
    assert decisions[delete["id"]] == "delete"
    row = db.query_one("SELECT status FROM review_groups WHERE id=?", (g["id"],))
    assert row["status"] == "reviewed"
    # ...and the plan still contains exactly one safe row.
    plan = plans.generate_plan(db)
    assert plan["total_items"] == 1
    assert plan["violations"] == []
    item = plans.plan_detail(db, plan["id"])["items"][0]
    assert item["path"] == delete["path"]
    assert item["keep_path"] == keep["path"]


def test_plan_refuses_group_without_keep_even_if_db_tampered(db, root):
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
    # Simulate a corrupted/legacy row set: group marked reviewed but no keep.
    db.execute("UPDATE review_items SET decision='delete' WHERE group_id=?", (g["id"],))
    db.commit()
    with pytest.raises(plans.PlanError):
        plans.generate_plan(db)
    assert db.query_one("SELECT COUNT(*) AS n FROM delete_plans")["n"] == 0


def test_plan_refuses_group_when_keep_copy_changed(db, root):
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
    with open(keep["path"], "ab") as fh:
        fh.write(b"keep-mutated")
    with pytest.raises(plans.PlanError):
        plans.generate_plan(db)


def test_name_group_with_different_content_never_reaches_plan(db, root):
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
    names = review.list_groups(db, kind="name", status=None)["items"]
    target = next(n for n in names if n["key"] == "same_name.txt")
    ndetail = review.group_detail(db, target["id"])
    nkeep, ndelete = ndetail["items"][0], ndetail["items"][1]
    review.save_decisions(db, target["id"], None, [
        {"item_id": nkeep["id"], "decision": "keep"},
        {"item_id": ndelete["id"], "decision": "delete"},
    ])
    plan = plans.generate_plan(db)
    assert plan["status"] == "needs_review"
    assert plan["total_items"] == 1  # only the verified content-group row
    reasons = {v["reason"] for v in plan["violations"]}
    assert "name_unverified" in reasons
    assert all(v["group_id"] != g["id"] for v in plan["violations"])


def test_list_groups_flags_missing_files(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    g = _content_group(db)
    detail = review.group_detail(db, g["id"])
    for item in detail["items"]:
        os.unlink(item["path"])
    item = next(i for i in review.list_groups(db, kind="content")["items"] if i["id"] == g["id"])
    assert item["sample_missing"] is True
