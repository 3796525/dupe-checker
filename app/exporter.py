"""Export delete plans as JSON / CSV / HTML.

Exports contain only descriptive data. They deliberately contain no shell
commands, no scripts and no executable content (requirement BR-011).

Two safety gates run before a single byte is produced (review P1-03/P0-01):

1. only a plan whose status is `final` may be exported - a draft or a plan
   that still needs review would hand out a delete list the review process
   never approved;
2. every `keep_path` is stat-ed again and must still match the size and
   mtime recorded when the group was reviewed. A missing or changed keep copy
   means deleting the listed paths could destroy the last copy, so the whole
   export is refused instead of silently shipping a risky plan.
"""
from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime

from .config import config
from .db import Database

NOTICE = (
    "本工具不会执行删除。请按下列路径在 NAS 上手工核对并删除；"
    "删除前请核对大小与 SHA-256，出现 changed/missing 的条目请先重新扫描。"
)
FORMATS = ("json", "csv", "html")

# Human-readable labels keep a same-name plan from being mistaken for an
# ordinary content-duplicate plan once it leaves the app (review P1-06).
KIND_LABELS = {
    "content": "内容重复",
    "name": "同名候选（请人工确认）",
}
STATUS_LABELS = {
    "draft": "草稿",
    "needs_review": "未通过复核",
    "final": "已通过复核",
}


class ExportError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def build_export(db: Database, plan_id: int, fmt: str) -> tuple[str, str, bytes]:
    """Return (filename, media_type, payload)."""
    from .plans import plan_detail

    if fmt not in FORMATS:
        raise ExportError("VALIDATION_ERROR", f"不支持的格式: {fmt}")
    plan = plan_detail(db, plan_id)
    if plan is None:
        raise ExportError("NOT_FOUND", "方案不存在")
    status = plan["status"]
    if status != "final":
        raise ExportError(
            "PLAN_NOT_FINAL",
            f"该方案尚未通过复核，禁止导出（当前状态：{_status_label(status)}）",
        )
    _verify_keep_copies(db, plan)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        payload = json.dumps(
            {
                "plan_id": plan["id"],
                "created_at": plan["created_at"],
                # `plan_status` is the canonical field; `status` is kept so
                # consumers looking for a plain status keep working.
                "plan_status": status,
                "status": status,
                "notice": NOTICE,
                "total_items": plan["total_items"],
                "releasable_bytes": plan["releasable_bytes"],
                "items": [
                    {
                        "path": i["path"],
                        "size": i["size"],
                        "mtime": _iso(i["mtime_ns"]),
                        "sha256": i["sha256"],
                        "keep_path": i["keep_path"],
                        "recheck": i["recheck_status"],
                        "kind": i["kind"],
                    }
                    for i in plan["items"]
                ],
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        return f"delete-plan-{plan_id}-{stamp}.json", "application/json", payload
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            ["path", "size_bytes", "mtime", "sha256", "keep_path", "recheck",
             "status", "kind"]
        )
        for i in plan["items"]:
            w.writerow(
                [i["path"], i["size"], _iso(i["mtime_ns"]), i["sha256"],
                 i["keep_path"], i["recheck_status"], status, i["kind"]]
            )
        # A leading comment line carries the safety notice; BOM keeps Excel happy
        # with UTF-8 paths. Tools reading the CSV should skip lines starting with '#'.
        payload = ("\ufeff# " + NOTICE + "\r\n" + buf.getvalue()).encode("utf-8")
        return f"delete-plan-{plan_id}-{stamp}.csv", "text/csv; charset=utf-8", payload
    rows = "".join(
        f"<tr class='{i['recheck_status']}'><td>{_escape(i['path'])}</td>"
        f"<td>{i['size']}</td><td>{_iso(i['mtime_ns'])}</td>"
        f"<td class='mono'>{_escape(i['sha256'] or '')}</td>"
        f"<td>{_escape(i['keep_path'])}</td><td>{i['recheck_status']}</td>"
        f"<td>{_escape(_kind_label(i['kind']))}</td></tr>"
        for i in plan["items"]
    )
    html = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>删除方案 #{plan['id']}</title>
<style>
body{{font-family:system-ui,-apple-system,'Noto Sans SC',sans-serif;margin:24px;color:#222}}
h1{{font-size:20px}} .notice{{background:#fff4e5;border-left:4px solid #f59e0b;padding:10px 14px;margin:16px 0}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}} .mono{{font-family:ui-monospace,monospace;font-size:11px;word-break:break-all}}
tr.changed td,tr.missing td{{background:#fee2e2}} tr.error td{{background:#fef3c7}}
</style></head><body>
<h1>删除方案 #{plan['id']}</h1>
<p>方案状态：{_status_label(status)}（{_escape(status)}）　生成时间：{plan['created_at']}　条目：{plan['total_items']}　可释放：{plan['releasable_bytes']} 字节</p>
<p class="notice">{NOTICE}</p>
<table><thead><tr><th>待删除路径</th><th>大小</th><th>修改时间</th><th>SHA-256</th>
<th>保留的文件</th><th>复核</th><th>分组类型</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
    return f"delete-plan-{plan_id}-{stamp}.html", "text/html; charset=utf-8", html.encode("utf-8")


def _verify_keep_copies(db: Database, plan: dict) -> None:
    """Refuse the export unless every promised keep copy is still intact."""
    by_group: dict[int, list] = {}
    for item in plan["items"]:
        group_id = item.get("group_id")
        if group_id is None:
            raise ExportError(
                "KEEP_RECHECK_FAILED",
                f"待删项 {item['path']} 缺少分组信息，禁止导出",
            )
        by_group.setdefault(int(group_id), []).append(item)
    for group_id, items in by_group.items():
        keeps = {
            keep["path"]: keep
            for keep in db.query(
                "SELECT path, size, mtime_ns FROM review_items "
                "WHERE group_id=? AND decision='keep'",
                (group_id,),
            )
        }
        if not keeps:
            raise ExportError(
                "KEEP_RECHECK_FAILED",
                f"分组 #{group_id} 没有已审核的保留项，禁止导出",
            )
        for item in items:
            keep_path = item["keep_path"]
            if not keep_path:
                raise ExportError(
                    "KEEP_RECHECK_FAILED",
                    f"待删项 {item['path']} 未记录保留文件，禁止导出",
                )
            keep = keeps.get(keep_path)
            if keep is None:
                raise ExportError(
                    "KEEP_RECHECK_FAILED",
                    f"保留文件 {keep_path} 不是该分组已审核的保留项，禁止导出",
                )
            try:
                st = os.stat(keep_path, follow_symlinks=False)
            except OSError:
                raise ExportError(
                    "KEEP_RECHECK_FAILED",
                    f"保留文件已不存在（可能已被删除或移动）：{keep_path}，禁止导出",
                )
            if st.st_size != keep["size"] or st.st_mtime_ns != keep["mtime_ns"]:
                raise ExportError(
                    "KEEP_RECHECK_FAILED",
                    f"保留文件在审核之后已发生变化：{keep_path}，"
                    "请重新扫描并审核后再导出",
                )


def _status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status or "未知")


def _kind_label(kind: str | None) -> str:
    return KIND_LABELS.get(kind or "", kind or "未知")


def _iso(mtime_ns: int | None) -> str:
    if not mtime_ns:
        return ""
    return datetime.fromtimestamp(mtime_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S")


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )
