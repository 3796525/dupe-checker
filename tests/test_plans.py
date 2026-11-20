"""Delete plan export formats: content and safety wording."""
import csv
import io
import json

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
