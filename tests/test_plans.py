"""Delete plan export formats: content and safety wording."""
import csv
import io
import json
import os

import pytest

from app import exporter, plans, review
from helpers import add_root, build_tree, run_scan


def _approved_plan(db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    data = review.list_groups(db, kind="content", status=None)
    g = data["items"][0]
    detail = review.group_detail(db, g["id"])
    keep, delete = detail["items"][0], detail["items"][1]
    review.save_decisions(db, g["id"], None, [
        {"item_id": keep["id"], "decision": "keep"},
        {"item_id": delete["id"], "decision": "delete"},
    ])
    return plans.generate_plan(db, "导出测试")["id"], delete["path"], keep["path"]


@pytest.mark.parametrize("fmt", ["csv", "json", "html"])
def test_export_never_contains_delete_commands(db, root, fmt):
    plan_id, delete_path, keep_path = _approved_plan(db, root)
    filename, media_type, payload = exporter.build_export(db, plan_id, fmt)
    text = payload.decode("utf-8-sig") if isinstance(payload, bytes) else str(payload)
    assert delete_path in text
    for bad in ("rm -rf", "rm -f", "unlink", "os.remove", "del /"):
        assert bad not in text, f"{fmt} export must not contain a delete command: {bad}"
    assert "不会执行删除" in text or "手工删除" in text or "手工核对" in text or "不会删除" in text


def test_json_export_structure(db, root):
    plan_id, delete_path, keep_path = _approved_plan(db, root)
    filename, media_type, payload = exporter.build_export(db, plan_id, "json")
    data = json.loads(payload)
    assert data["plan_id"] == plan_id
    assert data["items"][0]["path"] == delete_path
    assert data["items"][0]["keep_path"] == keep_path
    assert "notice" in data


def test_csv_export_columns(db, root):
    plan_id, delete_path, _ = _approved_plan(db, root)
    filename, media_type, payload = exporter.build_export(db, plan_id, "csv")
    text = payload.decode("utf-8-sig")
    body = "".join(line + "\n" for line in text.splitlines() if not line.startswith("#"))
    rows = list(csv.DictReader(io.StringIO(body)))
    assert rows and rows[0]["path"] == delete_path
    for col in ("path", "size_bytes", "mtime", "sha256", "keep_path", "recheck"):
        assert col in rows[0]


def test_html_export_has_no_script(db, root):
    plan_id, _, _ = _approved_plan(db, root)
    filename, media_type, payload = exporter.build_export(db, plan_id, "html")
    text = payload.decode("utf-8")
    assert "<script" not in text.lower()


def test_unknown_format_rejected(db, root):
    plan_id, _, _ = _approved_plan(db, root)
    with pytest.raises(exporter.ExportError):
        exporter.build_export(db, plan_id, "xlsx")


def test_export_missing_plan_rejected(db):
    with pytest.raises(exporter.ExportError):
        exporter.build_export(db, 999, "json")


def _csv_rows(db, plan_id):
    _, _, payload = exporter.build_export(db, plan_id, "csv")
    text = payload.decode("utf-8-sig")
    body = "".join(line + "\n" for line in text.splitlines() if not line.startswith("#"))
    return list(csv.DictReader(io.StringIO(body)))


def _mark_plan_status(db, plan_id, status):
    db.execute("UPDATE delete_plans SET status=? WHERE id=?", (status, plan_id))
    db.commit()


@pytest.mark.parametrize("fmt", ["json", "csv", "html"])
def test_export_rejects_plan_that_needs_review(db, root, fmt):
    plan_id, _, _ = _approved_plan(db, root)
    _mark_plan_status(db, plan_id, "needs_review")
    with pytest.raises(exporter.ExportError) as err:
        exporter.build_export(db, plan_id, fmt)
    assert err.value.code == "PLAN_NOT_FINAL"
    assert "禁止导出" in err.value.message


def test_export_rejects_draft_plan(db, root):
    plan_id, _, _ = _approved_plan(db, root)
    _mark_plan_status(db, plan_id, "draft")
    with pytest.raises(exporter.ExportError) as err:
        exporter.build_export(db, plan_id, "json")
    assert err.value.code == "PLAN_NOT_FINAL"


@pytest.mark.parametrize("fmt", ["json", "csv", "html"])
def test_export_rejects_when_keep_file_was_deleted(db, root, fmt):
    plan_id, _, keep_path = _approved_plan(db, root)
    os.unlink(keep_path)
    with pytest.raises(exporter.ExportError) as err:
        exporter.build_export(db, plan_id, fmt)
    assert err.value.code == "KEEP_RECHECK_FAILED"
    assert keep_path in err.value.message


def test_export_rejects_when_keep_file_changed(db, root):
    plan_id, _, keep_path = _approved_plan(db, root)
    with open(keep_path, "ab") as fh:
        fh.write(b"mutated-after-review")
    with pytest.raises(exporter.ExportError) as err:
        exporter.build_export(db, plan_id, "json")
    assert err.value.code == "KEEP_RECHECK_FAILED"
    assert keep_path in err.value.message


def test_json_export_carries_plan_status_and_item_kind(db, root):
    plan_id, delete_path, _ = _approved_plan(db, root)
    _, _, payload = exporter.build_export(db, plan_id, "json")
    data = json.loads(payload)
    assert data["plan_status"] == "final"
    assert data["status"] == "final"
    assert data["items"][0]["path"] == delete_path
    assert data["items"][0]["kind"] == "content"
    plan_item = plans.plan_detail(db, plan_id)["items"][0]
    assert plan_item["kind"] == "content"
    assert plan_item["group_id"] is not None


def test_csv_export_carries_status_and_kind_columns(db, root):
    plan_id, delete_path, _ = _approved_plan(db, root)
    rows = _csv_rows(db, plan_id)
    assert rows and rows[0]["path"] == delete_path
    assert rows[0]["status"] == "final"
    assert rows[0]["kind"] == "content"


def test_html_export_shows_plan_status_and_kind_text(db, root):
    plan_id, _, _ = _approved_plan(db, root)
    _, _, payload = exporter.build_export(db, plan_id, "html")
    text = payload.decode("utf-8")
    assert "方案状态" in text
    assert "已通过复核" in text
    assert "内容重复" in text

