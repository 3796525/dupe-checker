"""Export delete plans as JSON / CSV / HTML.

Exports contain only descriptive data. They deliberately contain no shell
commands, no scripts and no executable content (requirement BR-011).
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from .config import config
from .db import Database

NOTICE = (
    "本工具不会执行删除。请按下列路径在 NAS 上手工核对并删除；"
    "删除前请核对大小与 SHA-256，出现 changed/missing 的条目请先重新扫描。"
)
FORMATS = ("json", "csv", "html")


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
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        payload = json.dumps(
            {
                "plan_id": plan["id"],
                "created_at": plan["created_at"],
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
        w.writerow(["path", "size_bytes", "mtime", "sha256", "keep_path", "recheck"])
        for i in plan["items"]:
            w.writerow([i["path"], i["size"], _iso(i["mtime_ns"]), i["sha256"],
                        i["keep_path"], i["recheck_status"]])
        # A leading comment line carries the safety notice; BOM keeps Excel happy
        # with UTF-8 paths. Tools reading the CSV should skip lines starting with '#'.
        payload = ("\ufeff# " + NOTICE + "\r\n" + buf.getvalue()).encode("utf-8")
        return f"delete-plan-{plan_id}-{stamp}.csv", "text/csv; charset=utf-8", payload
    rows = "".join(
        f"<tr class='{i['recheck_status']}'><td>{_escape(i['path'])}</td>"
        f"<td>{i['size']}</td><td>{_iso(i['mtime_ns'])}</td>"
        f"<td class='mono'>{_escape(i['sha256'] or '')}</td>"
        f"<td>{_escape(i['keep_path'])}</td><td>{i['recheck_status']}</td></tr>"
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
<p>生成时间：{plan['created_at']}　条目：{plan['total_items']}　可释放：{plan['releasable_bytes']} 字节</p>
<p class="notice">{NOTICE}</p>
<table><thead><tr><th>待删除路径</th><th>大小</th><th>修改时间</th><th>SHA-256</th>
<th>保留的文件</th><th>复核</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
    return f"delete-plan-{plan_id}-{stamp}.html", "text/html; charset=utf-8", html.encode("utf-8")


def _iso(mtime_ns: int | None) -> str:
    if not mtime_ns:
        return ""
    return datetime.fromtimestamp(mtime_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S")


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )
