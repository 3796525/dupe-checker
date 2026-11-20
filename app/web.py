"""FastAPI application: JSON API + server-rendered pages.

Security posture (see ADR-001/ADR-008):
- no endpoint writes, moves, renames or deletes user files;
- no endpoint executes shell commands;
- every path-based action is validated against configured read-only roots;
- sessions are signed cookies; state-changing requests need a CSRF header.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import exporter, plans, review, scanner as scanner_mod
from .config import config
from .db import get_db, now_iso
from .guard import GuardReport, enforce_guard_or_exit
from .security import (
    CSRF_HEADER,
    SESSION_COOKIE,
    LoginRateLimiter,
    SessionManager,
    csrf_ok,
    hash_password,
    verify_password,
)

log = logging.getLogger("dupe.web")
BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="dupe-checker", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _ts_filter(mtime_ns) -> str:
    """Render a nanosecond mtime as local 'YYYY-MM-DD HH:MM:SS'."""
    try:
        value = int(mtime_ns) / 1_000_000_000
    except (TypeError, ValueError):
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


templates.env.filters["ts"] = _ts_filter

db = get_db()
sessions = SessionManager(db)
limiter = LoginRateLimiter()
scan_engine = scanner_mod.Scanner(db)
guard_report: GuardReport = GuardReport()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _session(request: Request) -> dict | None:
    return sessions.load(request.cookies.get(SESSION_COOKIE))


def _is_setup() -> bool:
    return bool(db.get_setting("password_hash"))


def _require_page(request: Request) -> RedirectResponse | None:
    if not _is_setup():
        return RedirectResponse("/setup", status_code=303)
    if not _session(request):
        return RedirectResponse("/login", status_code=303)
    return None


def _require_api(request: Request) -> dict:
    sess = _session(request)
    if sess is None:
        raise HTTPException(status_code=401, detail={"code": "AUTH_REQUIRED", "message": "请先登录"})
    # CSRF for state-changing methods
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not csrf_ok(sess.get("csrf"), request.headers.get(CSRF_HEADER)):
            raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "CSRF 校验失败"})
    return sess


def _root_paths() -> list[str]:
    rows = db.query("SELECT mount_path FROM scan_roots WHERE enabled=1")
    return [r["mount_path"] for r in rows]


def _validate_path(path: str) -> str:
    """Reject any path outside the configured read-only roots."""
    real = os.path.realpath(path)
    for root in _root_paths():
        root_real = os.path.realpath(root)
        if real == root_real or real.startswith(root_real + os.sep):
            return real
    raise HTTPException(
        status_code=403, detail={"code": "FORBIDDEN_PATH", "message": "路径不在已授权目录内"}
    )


def _page(request: Request, template: str, **ctx):
    ctx.setdefault("request", request)
    ctx.setdefault("version", config.version)
    ctx.setdefault("nav", template.replace(".html", ""))
    sess = _session(request)
    ctx.setdefault("csrf", (sess or {}).get("csrf", ""))
    return templates.TemplateResponse(request=request, name=template, context=ctx)


def _json_error(code: str, message: str, status: int, details: dict | None = None) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message, "details": details or {}}}, status_code=status
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"code": "ERROR", "message": str(exc.detail)}
    return JSONResponse({"error": detail}, status_code=exc.status_code)


# ---------------------------------------------------------------------------
# startup / scheduler
# ---------------------------------------------------------------------------
def _bootstrap_roots() -> None:
    for root in config.mount_roots:
        existing = db.query_one("SELECT id FROM scan_roots WHERE mount_path=?", (root,))
        if existing is None:
            db.execute(
                "INSERT INTO scan_roots(mount_path, label, enabled, created_at) VALUES (?,?,1,?)",
                (root, os.path.basename(root.rstrip("/")), now_iso()),
            )
    db.commit()


@app.on_event("startup")
def on_startup() -> None:
    global guard_report
    config.ensure_dirs()
    logging.basicConfig(level=logging.INFO)
    guard_report = enforce_guard_or_exit()
    _bootstrap_roots()
    db.set_setting("guard_report", json.dumps(guard_report.to_dict(), ensure_ascii=False))
    db.audit("system", "startup", "guard passed")
    from .scheduler import Scheduler

    Scheduler(db, scan_engine).start()


# ---------------------------------------------------------------------------
# system
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok" if guard_report.passed else "fatal",
            "guard": guard_report.to_dict(),
            "version": config.version,
        }
    )


@app.get("/api/v1/system/health")
def api_health() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok" if guard_report.passed else "fatal",
            "guard": guard_report.to_dict(),
            "db": {"ok": True, "schema_version": 1},
            "version": config.version,
        }
    )


@app.get("/api/v1/system/version")
def api_version() -> dict:
    return {"version": config.version, "name": "dupe-checker"}


@app.get("/api/v1/system/guard")
def api_guard(request: Request) -> dict:
    _require_api(request)
    return json.loads(db.get_setting("guard_report", "{}") or "{}")


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------
@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    if _is_setup():
        return RedirectResponse("/login", status_code=303)
    return _page(request, "setup.html")


@app.post("/api/v1/auth/setup")
async def api_setup(request: Request):
    if _is_setup():
        return _json_error("FORBIDDEN", "已初始化", 403)
    body = await request.json()
    password = str(body.get("password", ""))
    if len(password) < 10:
        return _json_error("VALIDATION_ERROR", "口令至少 10 位", 400)
    db.set_setting("password_hash", hash_password(password))
    token, csrf = sessions.create()
    resp = JSONResponse({"ok": True, "csrf_token": csrf})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=config.session_max_age)
    db.audit("user", "auth.setup", "")
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if not _is_setup():
        return RedirectResponse("/setup", status_code=303)
    return _page(request, "login.html", error="")


@app.post("/api/v1/auth/login")
async def api_login(request: Request):
    client = request.client.host if request.client else "unknown"
    if limiter.is_blocked(client):
        return _json_error("RATE_LIMITED", "尝试过于频繁，请 60 秒后再试", 429)
    body = await request.json()
    stored = db.get_setting("password_hash", "") or ""
    if not verify_password(str(body.get("password", "")), stored):
        limiter.record_failure(client)
        db.audit("user", "auth.login_failed", client)
        return _json_error("AUTH_INVALID", "口令错误", 401)
    limiter.reset(client)
    token, csrf = sessions.create()
    resp = JSONResponse({"ok": True, "csrf_token": csrf})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=config.session_max_age)
    db.audit("user", "auth.login", client)
    return resp


@app.post("/api/v1/auth/logout")
def api_logout(request: Request):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/v1/auth/me")
def api_me(request: Request) -> dict:
    sess = _require_api(request)
    return {"authenticated": True, "csrf_token": sess.get("csrf")}


# ---------------------------------------------------------------------------
# roots / plans
# ---------------------------------------------------------------------------
@app.get("/api/v1/roots")
def api_roots(request: Request) -> dict:
    _require_api(request)
    rows = db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
    return {"items": [{"id": r["id"], "path": r["mount_path"], "label": r["label"]} for r in rows]}


@app.get("/api/v1/roots/tree")
def api_tree(request: Request, root_id: int = 0) -> dict:
    _require_api(request)
    root = db.query_one("SELECT * FROM scan_roots WHERE id=? AND enabled=1", (root_id,))
    if root is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "目录不存在"})
    entries = []
    try:
        with os.scandir(root["mount_path"]) as it:
            for e in it:
                entries.append({"name": e.name, "is_dir": e.is_dir(follow_symlinks=False)})
    except OSError as exc:
        raise HTTPException(
            status_code=403, detail={"code": "FORBIDDEN_PATH", "message": str(exc.strerror)}
        )
    entries.sort(key=lambda x: (not x["is_dir"], x["name"]))
    return {"root": root["mount_path"], "items": entries[:500]}


def _plan_row(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "roots": json.loads(row["roots_json"] or "[]"),
        "include_globs": row["include_globs"],
        "exclude_globs": row["exclude_globs"],
        "trigger_type": row["trigger_type"],
        "trigger": json.loads(row["trigger_json"] or "{}"),
        "rate_meta": row["rate_meta"],
        "rate_hash": row["rate_hash"],
        "window": json.loads(row["window_json"] or "{}"),
        "enabled": bool(row["enabled"]),
    }


@app.get("/api/v1/plans")
def api_plans(request: Request) -> dict:
    _require_api(request)
    return {"items": [_plan_row(r) for r in db.query("SELECT * FROM scan_plans ORDER BY id")]}


@app.post("/api/v1/plans")
async def api_plan_create(request: Request) -> dict:
    _require_api(request)
    body = await request.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "方案名必填"})
    roots = body.get("root_ids") or [r["id"] for r in db.query("SELECT id FROM scan_roots WHERE enabled=1")]
    if not roots:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "至少选择一个目录"})
    trigger_type = body.get("trigger_type", "manual")
    if trigger_type not in ("manual", "daily", "weekly", "interval", "notify_only"):
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "无效触发方式"})
    now = now_iso()
    db.execute(
        "INSERT INTO scan_plans(name, roots_json, include_globs, exclude_globs, trigger_type, "
        "trigger_json, rate_meta, rate_hash, window_json, enabled, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,0,?,?)",
        (
            name,
            json.dumps(roots),
            str(body.get("include_globs") or ""),
            str(body.get("exclude_globs") or ""),
            trigger_type,
            json.dumps(body.get("trigger") or {}),
            int(body.get("rate_meta") or 2000),
            int(body.get("rate_hash") or 50),
            json.dumps(body.get("window") or {}),
            now,
            now,
        ),
    )
    db.commit()
    row = db.query_one("SELECT * FROM scan_plans ORDER BY id DESC LIMIT 1")
    db.audit("user", "plan.create", f"id={row['id']}")
    return _plan_row(row)


@app.patch("/api/v1/plans/{plan_id}")
async def api_plan_update(plan_id: int, request: Request) -> dict:
    _require_api(request)
    row = db.query_one("SELECT * FROM scan_plans WHERE id=?", (plan_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    body = await request.json()
    updates = {
        "name": body.get("name", row["name"]),
        "roots_json": json.dumps(body.get("root_ids", json.loads(row["roots_json"]))),
        "include_globs": body.get("include_globs", row["include_globs"]),
        "exclude_globs": body.get("exclude_globs", row["exclude_globs"]),
        "trigger_type": body.get("trigger_type", row["trigger_type"]),
        "trigger_json": json.dumps(body.get("trigger", json.loads(row["trigger_json"]))),
        "rate_meta": body.get("rate_meta", row["rate_meta"]),
        "rate_hash": body.get("rate_hash", row["rate_hash"]),
        "window_json": json.dumps(body.get("window", json.loads(row["window_json"]))),
        "enabled": int(body.get("enabled", row["enabled"])),
    }
    db.execute(
        "UPDATE scan_plans SET name=?, roots_json=?, include_globs=?, exclude_globs=?, "
        "trigger_type=?, trigger_json=?, rate_meta=?, rate_hash=?, window_json=?, enabled=?, "
        "updated_at=? WHERE id=?",
        (
            updates["name"], updates["roots_json"], updates["include_globs"],
            updates["exclude_globs"], updates["trigger_type"], updates["trigger_json"],
            updates["rate_meta"], updates["rate_hash"], updates["window_json"],
            updates["enabled"], now_iso(), plan_id,
        ),
    )
    db.commit()
    db.audit("user", "plan.update", f"id={plan_id}")
    return _plan_row(db.query_one("SELECT * FROM scan_plans WHERE id=?", (plan_id,)))


@app.delete("/api/v1/plans/{plan_id}")
def api_plan_delete(plan_id: int, request: Request) -> dict:
    _require_api(request)
    db.execute("DELETE FROM scan_plans WHERE id=?", (plan_id,))
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------------
@app.post("/api/v1/scans")
async def api_scan_start(request: Request) -> dict:
    _require_api(request)
    body = await request.json() if await request.body() else {}
    plan_id = body.get("plan_id") or None
    if plan_id is not None and db.query_one("SELECT id FROM scan_plans WHERE id=?", (plan_id,)) is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    if scan_engine.is_running():
        raise HTTPException(status_code=409, detail={"code": "SCAN_RUNNING", "message": "已有扫描在运行"})
    try:
        run_id = scan_engine.start(plan_id)
    except RuntimeError:
        raise HTTPException(status_code=409, detail={"code": "SCAN_RUNNING", "message": "已有扫描在运行"})
    db.audit("user", "scan.start", f"run={run_id} plan={plan_id}")
    return {"id": run_id, "status": "running"}


@app.get("/api/v1/scans/current")
def api_scan_current(request: Request) -> dict:
    _require_api(request)
    row = db.query_one(
        "SELECT * FROM scan_runs WHERE status IN ('running','paused') ORDER BY id DESC LIMIT 1"
    )
    if row is None:
        return {"current": None}
    return {"current": _run_row(row)}


def _run_row(row) -> dict:
    return {
        "id": row["id"],
        "plan_id": row["plan_id"],
        "status": row["status"],
        "phase": row["phase"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "incomplete_reason": row["incomplete_reason"],
        "stats": json.loads(row["stats_json"] or "{}"),
        "dirs_seen": row["dirs_seen"],
        "error": row["error"],
    }


@app.get("/api/v1/scans")
def api_scans(request: Request, limit: int = 20) -> dict:
    _require_api(request)
    rows = db.query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (min(limit, 100),))
    return {"items": [_run_row(r) for r in rows]}


@app.get("/api/v1/scans/{run_id}")
def api_scan_detail(run_id: int, request: Request) -> dict:
    _require_api(request)
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "任务不存在"})
    return _run_row(row)


@app.post("/api/v1/scans/{run_id}/{action}")
def api_scan_control(run_id: int, action: str, request: Request) -> dict:
    _require_api(request)
    mapping = {"pause": "paused", "resume": "running", "cancel": "cancelled"}
    if action not in mapping:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "未知操作"})
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "任务不存在"})
    db.execute("UPDATE scan_runs SET status=? WHERE id=?", (mapping[action], run_id))
    db.commit()
    db.audit("user", f"scan.{action}", f"run={run_id}")
    return {"id": run_id, "status": mapping[action]}


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------
@app.get("/api/v1/review/groups")
def api_review_groups(
    request: Request,
    kind: str | None = None,
    status: str | None = None,
    q: str | None = None,
    min_size: int | None = None,
    cursor: int = 0,
    limit: int = 50,
) -> dict:
    _require_api(request)
    data = review.list_groups(db, kind, status, q, min_size, cursor, limit)
    data["stats"] = review.stats(db)
    return data


@app.get("/api/v1/review/groups/{group_id}")
def api_review_group(group_id: int, request: Request) -> dict:
    _require_api(request)
    data = review.group_detail(db, group_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "分组不存在"})
    return data


@app.put("/api/v1/review/groups/{group_id}")
async def api_review_save(group_id: int, request: Request) -> dict:
    _require_api(request)
    body = await request.json()
    try:
        return review.save_decisions(db, group_id, body.get("policy"), body.get("items") or [])
    except review.ReviewError as exc:
        return _json_error(exc.code, exc.message, 422 if exc.code == "GROUP_KEEP_VIOLATION" else 400,
                           exc.details)


@app.post("/api/v1/review/groups/{group_id}/skip")
def api_review_skip(group_id: int, request: Request) -> dict:
    _require_api(request)
    return review.skip_group(db, group_id)


@app.post("/api/v1/review/groups/{group_id}/recheck")
def api_review_recheck(group_id: int, request: Request) -> dict:
    _require_api(request)
    return {"items": review.recheck_group(db, group_id)}


@app.get("/api/v1/review/stats")
def api_review_stats(request: Request) -> dict:
    _require_api(request)
    return review.stats(db)


# ---------------------------------------------------------------------------
# delete plans / export
# ---------------------------------------------------------------------------
@app.post("/api/v1/delete-plans")
async def api_plan_generate(request: Request) -> dict:
    _require_api(request)
    body = await request.json() if await request.body() else {}
    try:
        return plans.generate_plan(db, str(body.get("note") or ""))
    except plans.PlanError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})


@app.get("/api/v1/delete-plans")
def api_plans_list(request: Request) -> dict:
    _require_api(request)
    return {"items": plans.list_plans(db)}


@app.get("/api/v1/delete-plans/{plan_id}")
def api_plan_detail(plan_id: int, request: Request) -> dict:
    _require_api(request)
    data = plans.plan_detail(db, plan_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    return data


@app.get("/api/v1/delete-plans/{plan_id}/export")
def api_plan_export(plan_id: int, request: Request, format: str = "csv"):
    _require_api(request)
    try:
        filename, media_type, payload = exporter.build_export(db, plan_id, format)
    except exporter.ExportError as exc:
        raise HTTPException(status_code=404 if exc.code == "NOT_FOUND" else 400,
                            detail={"code": exc.code, "message": exc.message})
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# notifications / settings / stats
# ---------------------------------------------------------------------------
@app.get("/api/v1/notifications")
def api_notifications(request: Request, unread: int = 0) -> dict:
    _require_api(request)
    if unread:
        rows = db.query("SELECT * FROM notifications WHERE read_at IS NULL ORDER BY id DESC LIMIT 100")
    else:
        rows = db.query("SELECT * FROM notifications ORDER BY id DESC LIMIT 100")
    return {"items": [dict(r) for r in rows]}


@app.post("/api/v1/notifications/read")
async def api_notifications_read(request: Request) -> dict:
    _require_api(request)
    body = await request.json() if await request.body() else {}
    if body.get("all"):
        db.execute("UPDATE notifications SET read_at=? WHERE read_at IS NULL", (now_iso(),))
    else:
        for nid in body.get("ids") or []:
            db.execute("UPDATE notifications SET read_at=? WHERE id=?", (now_iso(), nid))
    db.commit()
    return {"ok": True}


@app.get("/api/v1/settings")
def api_settings(request: Request) -> dict:
    _require_api(request)
    return {
        "default_keep_policy": db.get_setting("default_keep_policy", "earliest_mtime"),
        "rate_meta": int(db.get_setting("rate_meta", "2000")),
        "rate_hash": int(db.get_setting("rate_hash", "50")),
        "notify_in_app": db.get_setting("notify_in_app", "1") == "1",
    }


@app.put("/api/v1/settings")
async def api_settings_update(request: Request) -> dict:
    _require_api(request)
    body = await request.json()
    for key in ("default_keep_policy", "rate_meta", "rate_hash", "notify_in_app"):
        if key in body:
            value = body[key]
            if isinstance(value, bool):
                value = "1" if value else "0"
            db.set_setting(key, str(value))
    return {"ok": True}


@app.post("/api/v1/settings/password")
async def api_password_change(request: Request) -> dict:
    _require_api(request)
    body = await request.json()
    stored = db.get_setting("password_hash", "") or ""
    if not verify_password(str(body.get("old_password", "")), stored):
        return _json_error("AUTH_INVALID", "旧口令错误", 401)
    new = str(body.get("new_password", ""))
    if len(new) < 10:
        return _json_error("VALIDATION_ERROR", "新口令至少 10 位", 400)
    db.set_setting("password_hash", hash_password(new))
    sessions.rotate_secret()
    db.audit("user", "auth.password_change", "")
    return {"ok": True}


@app.get("/api/v1/stats/overview")
def api_stats(request: Request) -> dict:
    _require_api(request)
    return _overview()


def _overview() -> dict:
    files = db.query_one("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS bytes FROM files WHERE status='present'")
    groups = db.query_one("SELECT COUNT(*) AS n, COALESCE(SUM(wasted_bytes),0) AS wasted FROM content_groups")
    st = review.stats(db)
    last = db.query_one("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1")
    return {
        "files": files["n"],
        "total_bytes": files["bytes"],
        "content_groups": groups["n"],
        "wasted_bytes": groups["wasted"],
        "review": st,
        "last_scan": _run_row(last) if last else None,
    }


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    return _page(request, "index.html", overview=_overview())


@app.get("/roots", response_class=HTMLResponse)
def roots_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    roots = db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
    trees = []
    for r in roots:
        entries = []
        try:
            with os.scandir(r["mount_path"]) as it:
                for e in it:
                    entries.append({"name": e.name, "is_dir": e.is_dir(follow_symlinks=False)})
        except OSError as exc:
            entries = [{"name": f"(无法读取: {exc.strerror})", "is_dir": False}]
        entries.sort(key=lambda x: (not x["is_dir"], x["name"]))
        trees.append({"root": r, "entries": entries[:200]})
    return _page(request, "roots.html", trees=trees)


@app.get("/plans", response_class=HTMLResponse)
def plans_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    roots = db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
    return _page(
        request, "plans.html",
        plans=[_plan_row(r) for r in db.query("SELECT * FROM scan_plans ORDER BY id")],
        roots=roots,
    )


@app.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    runs = [_run_row(r) for r in db.query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 20")]
    return _page(request, "scans.html", runs=runs)


@app.get("/review", response_class=HTMLResponse)
def review_page(request: Request, kind: str = "content", status: str = "pending", cursor: int = 0):
    redir = _require_page(request)
    if redir:
        return redir
    data = review.list_groups(db, kind, status or None, None, None, cursor, 50)
    return _page(
        request, "review.html",
        groups=data["items"], kind=kind, status=status,
        next_cursor=data.get("next_cursor"), stats=review.stats(db),
    )


@app.get("/review/{group_id}", response_class=HTMLResponse)
def review_detail_page(request: Request, group_id: int):
    redir = _require_page(request)
    if redir:
        return redir
    data = review.group_detail(db, group_id)
    if data is None:
        return RedirectResponse("/review", status_code=303)
    members = []
    for item in data["items"]:
        try:
            exists = os.path.exists(item["path"])
            reached = os.access(item["path"], os.R_OK)
        except OSError:
            exists, reached = False, False
        members.append({**item, "exists": exists, "readable": reached})
    return _page(request, "review_detail.html", group=data, members=members)


@app.get("/delete-plans", response_class=HTMLResponse)
def delete_plans_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    return _page(request, "delete_plans.html", plans=plans.list_plans(db))


@app.get("/delete-plans/{plan_id}", response_class=HTMLResponse)
def delete_plan_detail_page(request: Request, plan_id: int):
    redir = _require_page(request)
    if redir:
        return redir
    data = plans.plan_detail(db, plan_id)
    if data is None:
        return RedirectResponse("/delete-plans", status_code=303)
    return _page(request, "delete_plan.html", plan=data)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    return _page(
        request, "settings.html",
        settings={
            "default_keep_policy": db.get_setting("default_keep_policy", "earliest_mtime"),
            "rate_meta": db.get_setting("rate_meta", "2000"),
            "rate_hash": db.get_setting("rate_hash", "50"),
        },
        guard=guard_report.to_dict(),
    )


@app.get("/notifications", response_class=HTMLResponse)
def notifications_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    rows = db.query("SELECT * FROM notifications ORDER BY id DESC LIMIT 100")
    return _page(request, "notifications.html", items=[dict(r) for r in rows])


def create_app() -> FastAPI:
    return app
