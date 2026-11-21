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
import re
import stat as statmod
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
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

from . import exporter, guard as guard_mod, plans, review, scanner as scanner_mod
from .config import config
from .db import get_db, now_iso
from .guard import GuardReport, enforce_guard_or_exit
from .security import (
    CSRF_HEADER,
    SESSION_COOKIE,
    LoginRateLimiter,
    SessionManager,
    clear_setup_token,
    csrf_ok,
    ensure_setup_token,
    hash_password,
    load_setup_token,
    setup_token_ok,
    setup_token_path,
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


def _bytes_filter(value) -> str:
    """Render a byte count in a human friendly unit."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ""
    units = ("B", "KB", "MB", "GB", "TB")
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024
        idx += 1
    if idx == 0:
        return f"{int(n)} B"
    return f"{n:.1f} {units[idx]}"


def _basename_filter(path) -> str:
    text = str(path or "")
    return text.rsplit("/", 1)[-1] or text


templates.env.filters["ts"] = _ts_filter
templates.env.filters["bytes"] = _bytes_filter
templates.env.filters["basename"] = _basename_filter

db = get_db()
sessions = SessionManager(db)
limiter = LoginRateLimiter()
# Separate limiter: /setup is unauthenticated, so it needs its own counter.
setup_limiter = LoginRateLimiter()
scan_engine = scanner_mod.Scanner(db)
guard_report: GuardReport = GuardReport()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _session(request: Request) -> dict | None:
    return sessions.load(request.cookies.get(SESSION_COOKIE))


def _is_setup() -> bool:
    return bool(db.get_setting("password_hash"))


def _auth_disabled() -> bool:
    """AUTH_MODE=none: trusted-LAN deployment without a login password."""
    return config.auth_mode == "none"


def _require_page(request: Request) -> RedirectResponse | None:
    if _auth_disabled():
        return None
    if not _is_setup():
        return RedirectResponse("/setup", status_code=303)
    if not _session(request):
        return RedirectResponse("/login", status_code=303)
    return None


def _require_api(request: Request) -> dict:
    sess = _session(request)
    if sess is None:
        if _auth_disabled():
            raise HTTPException(
                status_code=401,
                detail={"code": "SESSION_MISSING", "message": "会话尚未建立，请刷新页面后重试"},
            )
        raise HTTPException(status_code=401, detail={"code": "AUTH_REQUIRED", "message": "请先登录"})
    # CSRF for state-changing methods
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not csrf_ok(sess.get("csrf"), request.headers.get(CSRF_HEADER)):
            raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "CSRF 校验失败"})
    return sess


def _page(request: Request, template: str, **ctx):
    ctx.setdefault("request", request)
    ctx.setdefault("version", config.version)
    ctx.setdefault("nav", template.replace(".html", ""))
    ctx.setdefault("auth_disabled", _auth_disabled())
    sess = _session(request)
    new_token = None
    if sess is None and _auth_disabled():
        # Trusted-LAN mode: issue a CSRF-protected session on the first page
        # load so state-changing API calls still require the token header.
        new_token, csrf = sessions.create()
        sess = {"csrf": csrf}
    ctx.setdefault("csrf", (sess or {}).get("csrf", ""))
    resp = templates.TemplateResponse(request=request, name=template, context=ctx)
    if new_token:
        _set_session_cookie(resp, new_token, request)
    return resp


def _json_error(code: str, message: str, status: int, details: dict | None = None) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message, "details": details or {}}}, status_code=status
    )


# ---------------------------------------------------------------------------
# request hardening (DEF-01..DEF-06, DEF-11, DEF-12)
# ---------------------------------------------------------------------------
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB: no endpoint accepts a larger JSON body
SQLITE_INT_MAX = 2**63 - 1  # sqlite3 binds Python ints to signed 64 bit
PASSWORD_MAX = 200
PLAN_NAME_MAX = 200
PLAN_NOTE_MAX = 2000
KEEP_POLICIES = ("earliest_mtime", "longest_path")
SETTINGS_INT_RANGES = {"rate_meta": (1, 2000), "rate_hash": (1, 1000)}
# DEF-02: read-only glob preview budget. The walk never writes and stops early
# instead of turning a preview click into a full NAS traversal.
PREVIEW_MATCH_LIMIT = 200
PREVIEW_ENTRY_LIMIT = 50000
# DEF-06: in-app log viewer. Only these names (plus midnight-rotation backups)
# may ever be read or downloaded; anything else is a 404.
LOG_FILE_BASE = "app.log"
LOG_NAME_RE = re.compile(r"^(?:app|dupe)\.log(?:\.\d{4}-\d{2}-\d{2})?$")
LOG_TAIL_BYTES = 256 * 1024
LOG_LINE_MAX = 1000


def _payload_too_large() -> HTTPException:
    return HTTPException(
        status_code=413,
        detail={
            "code": "PAYLOAD_TOO_LARGE",
            "message": "请求体超过 1 MiB 上限",
            "details": {"limit_bytes": MAX_BODY_BYTES},
        },
    )


async def _read_body_limited(request: Request, max_bytes: int = MAX_BODY_BYTES) -> bytes:
    """Read the request body, refusing to buffer more than *max_bytes*.

    DEF-04: a declared Content-Length is checked before reading, and the
    streamed body is counted as it arrives so a lying/absent Content-Length
    cannot bypass the limit.
    """
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > max_bytes:
                raise _payload_too_large()
        except ValueError:
            pass  # malformed header: fall back to counting the stream
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise _payload_too_large()
        chunks.append(chunk)
    return b"".join(chunks)


async def json_body(request: Request, *, required: bool = False) -> dict:
    """Return the request body as a JSON object or raise a 4xx.

    DEF-01/DEF-02: every endpoint that reads a JSON body goes through this
    helper, so malformed JSON / a non-object body can never surface as a 500.
    An empty body is allowed unless *required* is true.
    """
    raw = await _read_body_limited(request)
    if not raw.strip():
        if required:
            raise HTTPException(
                status_code=400,
                detail={"code": "VALIDATION_ERROR", "message": "请求体不能为空", "details": {}},
            )
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=400,
            detail={"code": "VALIDATION_ERROR", "message": "请求体不是合法的 JSON", "details": {}},
        )
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail={"code": "VALIDATION_ERROR", "message": "请求体必须是 JSON 对象", "details": {}},
        )
    return data


def _check_path_id(value: int, label: str = "记录") -> int:
    """Reject ids that sqlite3 cannot bind (DEF-03), as a normal 404."""
    if value < 0 or value > SQLITE_INT_MAX:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"{label}不存在", "details": {}},
        )
    return value


def _check_query_int(value: int, name: str, minimum: int = 0) -> int:
    """Validate an integer query parameter before it reaches sqlite (DEF-03)."""
    if value < minimum or value > SQLITE_INT_MAX:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{name} 超出允许范围",
                "details": {"field": name},
            },
        )
    return value


def _clamp_limit(value: int, default: int, maximum: int = 200) -> int:
    """Clamp a list limit into [1, maximum] (DEF-11)."""
    if value < 1:
        return 1
    return min(value, maximum)


def _glob_list(value: str | None) -> list[str]:
    """The read-only array view of a stored comma-separated glob string."""
    return scanner_mod._split_globs(value or "")


def _preview_globs(roots, include_value: str, exclude_value: str) -> dict:
    """Walk plan roots read-only and report what the current rules match.

    DEF-02: this mirrors the scanner's walk semantics (exclude first, then
    include, never follow symlinks) but writes nothing: no index rows, no
    database writes, no filesystem writes. The walk is budgeted so one click
    cannot turn into a full NAS traversal.
    """
    include = _glob_list(include_value)
    exclude = _glob_list(exclude_value)
    matched: list[dict] = []
    total = 0
    included = 0
    excluded = 0
    scanned = 0
    truncated = False
    for root in roots:
        if truncated:
            break
        base = root["mount_path"]
        stack = [base]
        while stack and not truncated:
            dirpath = stack.pop()
            try:
                entries = list(os.scandir(dirpath))
            except OSError:
                continue  # an unreadable directory is skipped, not an error
            for entry in entries:
                scanned += 1
                if scanned > PREVIEW_ENTRY_LIMIT:
                    truncated = True
                    break
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                rel = os.path.relpath(entry.path, base)
                if scanner_mod._excluded(rel, exclude):
                    excluded += 1
                    continue
                if include and not scanner_mod._included(rel, include):
                    continue
                is_dir = statmod.S_ISDIR(st.st_mode)
                total += 1
                if not is_dir:
                    included += 1
                if len(matched) < PREVIEW_MATCH_LIMIT:
                    matched.append(
                        {
                            "path": entry.path,
                            "size": 0 if is_dir else st.st_size,
                            "is_dir": is_dir,
                        }
                    )
                if is_dir:
                    stack.append(entry.path)
    return {
        "matched": matched,
        "total": total,
        "included": included,
        "excluded": excluded,
        "scanned": scanned,
        "truncated": truncated,
        "limit": PREVIEW_MATCH_LIMIT,
    }


# ---------------------------------------------------------------------------
# DEF-06: in-app log viewing (whitelisted files only, bounded tail reads)
# ---------------------------------------------------------------------------
def _log_files() -> list[dict]:
    """List whitelisted files in LOG_DIR (rotation backups included)."""
    try:
        entries = list(config.log_dir.iterdir())
    except OSError:
        return []
    files: list[dict] = []
    for path in entries:
        if not LOG_NAME_RE.match(path.name):
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        if not statmod.S_ISREG(st.st_mode):
            continue
        files.append(
            {
                "name": path.name,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    files.sort(key=lambda item: item["name"])
    return files


def _resolve_log_path(name: object) -> Path | None:
    """Return a whitelisted log file, or None.

    Only an exact whitelisted name (optionally with a rotation date suffix) is
    accepted, so traversal sequences such as ../ can never resolve to a file;
    the resolved parent is re-checked against LOG_DIR as defence in depth.
    """
    if not isinstance(name, str) or not LOG_NAME_RE.match(name):
        return None
    directory = config.log_dir.resolve()
    try:
        candidate = (directory / name).resolve()
    except OSError:
        return None
    if candidate.parent != directory or not candidate.is_file():
        return None
    return candidate


def _read_log_tail(path: Path, limit: int) -> tuple[list[str], bool]:
    """Read at most LOG_TAIL_BYTES from the end of *path* (never unbounded)."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        if size > LOG_TAIL_BYTES:
            fh.seek(size - LOG_TAIL_BYTES)
        raw = fh.read(LOG_TAIL_BYTES)
    lines = raw.decode("utf-8", errors="replace").splitlines()
    truncated = size > LOG_TAIL_BYTES
    if len(lines) > limit:
        lines = lines[-limit:]
        truncated = True
    return lines, truncated


def _setup_file_logging():
    """Write app.log under LOG_DIR while keeping stdout/stderr logging.

    Called once at startup after basicConfig (so the stream handler stays).
    Returns the handler, or None when LOG_DIR is not writable: logging must
    never take the service down.
    """
    try:
        config.log_dir.mkdir(parents=True, exist_ok=True)
        root = logging.getLogger()
        for handler in root.handlers:
            if getattr(handler, "_dupe_log_file", False):
                return handler
        handler = TimedRotatingFileHandler(
            str(config.log_dir / LOG_FILE_BASE),
            when="midnight",
            backupCount=7,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        handler._dupe_log_file = True
        root.addHandler(handler)
        return handler
    except OSError as exc:
        log.warning("无法写入日志文件目录 %s: %s", config.log_dir, exc)
        return None


def _body_str(
    body: dict,
    key: str,
    default: str = "",
    *,
    maximum: int | None = None,
    label: str | None = None,
) -> str:
    value = body.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{label or key}必须是字符串",
                "details": {"field": key},
            },
        )
    if maximum is not None and len(value) > maximum:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{label or key}长度不能超过 {maximum} 个字符",
                "details": {"field": key},
            },
        )
    return value


def _body_int(
    body: dict,
    key: str,
    default: int,
    *,
    minimum: int = 0,
    maximum: int = SQLITE_INT_MAX,
) -> int:
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{key} 必须是整数",
                "details": {"field": key},
            },
        )
    if value < minimum or value > maximum:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{key} 超出允许范围（{minimum}..{maximum}）",
                "details": {"field": key},
            },
        )
    return value


def _body_obj(body: dict, key: str) -> dict:
    value = body.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{key} 必须是 JSON 对象",
                "details": {"field": key},
            },
        )
    return value


def _body_id_list(body: dict, key: str, label: str, default=None):
    value = body.get(key, default)
    if value is None:
        return None
    if not isinstance(value, list):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"{key} 必须是数组",
                "details": {"field": key},
            },
        )
    out: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0 or item > SQLITE_INT_MAX:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "VALIDATION_ERROR",
                    "message": f"{key} 包含非法{label}",
                    "details": {"field": key},
                },
            )
        out.append(item)
    return out


def _valid_password(value) -> str | None:
    """Return an error message for an unacceptable password, else None."""
    if not isinstance(value, str):
        return "口令必须是字符串"
    if len(value) < 10:
        return "口令至少 10 位"
    if len(value) > PASSWORD_MAX:
        return f"口令长度不能超过 {PASSWORD_MAX} 个字符"
    return None


def _guard_ok(guard: dict) -> bool:
    return bool(guard.get("passed")) and not bool(guard.get("unsafe"))


def _guard_status(guard: dict) -> str:
    return "ok" if _guard_ok(guard) else "fatal"


def _guard_public(guard: dict) -> dict:
    """Path-free guard summary for anonymous health endpoints (DEF-07)."""
    roots = guard.get("roots") or []
    passed = 0
    for root in roots:
        if not isinstance(root, dict):
            continue
        if (
            root.get("exists")
            and root.get("is_dir")
            and root.get("readable")
            and root.get("readonly")
            and not root.get("nested_writable")
        ):
            passed += 1
    return {
        "passed": bool(guard.get("passed")),
        "unsafe": bool(guard.get("unsafe")),
        "roots_total": len(roots),
        "roots_passed": passed,
    }


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _cookie_secure(request: Request) -> bool:
    """SESSION_COOKIE_SECURE=auto/always/never (P1-04)."""
    mode = config.session_cookie_secure
    if mode == "always":
        return True
    if mode == "never":
        return False
    forwarded = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if forwarded == "https":
        return True
    return request.url.scheme == "https"


def _set_session_cookie(resp: Response, token: str, request: Request) -> None:
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        max_age=config.session_ttl_seconds,
    )


def _guard_snapshot() -> dict:
    """Live guard state (falls back to the startup snapshot in tests)."""
    report = guard_mod.current_report()
    data = report.to_dict() if report.roots else guard_report.to_dict()
    data["unsafe"] = guard_mod.is_unsafe()
    data["unsafe_reason"] = guard_mod.unsafe_reason()
    data["verified_at"] = data.get("verified_at") or guard_mod.current_verified_at() or ""
    return data


def _guard_unsafe_response() -> JSONResponse | None:
    """409 for mutating/exporting routes while the read-only self check fails."""
    if not guard_mod.is_unsafe():
        return None
    reason = guard_mod.unsafe_reason() or "只读自检未通过"
    return _json_error(
        "GUARD_UNSAFE",
        f"只读自检未通过，为保护数据已暂停该操作：{reason}",
        409,
    )


def _init_setup_token() -> None:
    """First run: create the one-time /setup token and announce it on stdout."""
    if _auth_disabled():
        log.info("AUTH_MODE=none: 已关闭口令登录，跳过初始化令牌")
        return
    if _is_setup():
        clear_setup_token()
        return
    try:
        token = ensure_setup_token()
    except OSError as exc:  # pg: DATA_DIR unwritable
        log.error("首次启动无法生成初始化令牌（/setup 将不可用）: %s", exc)
        return
    banner = (
        "\n" + "=" * 76 + "\n"
        "  首次启动：初始化令牌（setup token）\n"
        f"  {token}\n"
        "  打开 /setup 并填入该令牌以设置管理员口令。\n"
        "  请先查看容器日志获取初始化令牌（docker compose logs）。\n"
        "  令牌仅保存在本机数据卷 setup_token 文件中（权限 0600），设置成功后自动删除。\n"
        + "=" * 76 + "\n"
    )
    print(banner, flush=True)
    log.warning("初始化令牌已写入 %s（0600），设置口令成功后自动删除", setup_token_path())


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"code": "ERROR", "message": str(exc.detail)}
    return JSONResponse({"error": detail}, status_code=exc.status_code)


# DEF-06: defence-in-depth headers on every response (pages, JSON and files).
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


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
    # DEF-06: keep the stderr handler and add a rotating file under LOG_DIR so
    # the in-app log viewer has something to show inside the container.
    _setup_file_logging()
    guard_report = enforce_guard_or_exit()
    _init_setup_token()
    _bootstrap_roots()
    db.set_setting("guard_report", json.dumps(guard_report.to_dict(), ensure_ascii=False))
    db.audit("system", "startup", "guard passed")
    # Pause/resume/restart left "running" rows with no worker thread; repair
    # them before any page is served so the UI never shows a frozen scan.
    scan_engine.reconcile_orphans()
    # Periodic read-only recheck (P1-05): a mount remounted writable at
    # runtime flips the global guard state and protected routes answer 409.
    guard_mod.start_periodic(db)
    from .scheduler import Scheduler

    Scheduler(db, scan_engine).start()


# ---------------------------------------------------------------------------
# system
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> JSONResponse:
    """Anonymous liveness probe: no internal paths or guard detail (DEF-07)."""
    guard = _guard_snapshot()
    return JSONResponse(
        {
            "status": _guard_status(guard),
            "guard_passed": _guard_ok(guard),
            "version": config.version,
        }
    )


@app.get("/api/v1/system/health")
def api_health() -> JSONResponse:
    """Anonymous health details, with guard roots reduced to counts (DEF-07)."""
    guard = _guard_snapshot()
    return JSONResponse(
        {
            "status": _guard_status(guard),
            "guard": _guard_public(guard),
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
    data = _guard_snapshot()
    if data.get("roots"):
        return data
    return json.loads(db.get_setting("guard_report", "{}") or "{}") or data


@app.get("/api/v1/system/logs")
def api_logs(request: Request, name: str | None = None, limit: int = 200) -> dict:
    """DEF-06: tail a whitelisted log file; names are never paths."""
    _require_api(request)
    limit = _clamp_limit(limit, 200, LOG_LINE_MAX)
    files = _log_files()
    if name is None:
        names = [item["name"] for item in files]
        name = LOG_FILE_BASE if LOG_FILE_BASE in names else (names[0] if names else None)
    if name is None:
        return {"files": files, "name": None, "lines": [], "truncated": False}
    path = _resolve_log_path(name)
    if path is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "日志文件不存在"})
    lines, truncated = _read_log_tail(path, limit)
    return {"files": files, "name": path.name, "lines": lines, "truncated": truncated}


@app.get("/api/v1/system/logs/download")
def api_log_download(request: Request, name: str = ""):
    """DEF-06: download one whitelisted log file (never an arbitrary path)."""
    _require_api(request)
    path = _resolve_log_path(name)
    if path is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "日志文件不存在"})
    return FileResponse(path, media_type="text/plain; charset=utf-8", filename=path.name)


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------
def _setup_token_page(request: Request, error: str = "") -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="setup_token.html",
        context={
            "request": request,
            "version": config.version,
            "nav": "setup",
            "error": error,
        },
        status_code=403,
    )


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, token: str = ""):
    if _auth_disabled():
        return RedirectResponse("/", status_code=303)
    if _is_setup():
        return RedirectResponse("/login", status_code=303)
    expected = load_setup_token()
    if not setup_token_ok(expected, token):
        # No valid token: never render the password form. 403 without leaking
        # whether a token exists at all.
        return _setup_token_page(request)
    return _page(request, "setup.html", setup_token=token)


@app.post("/api/v1/auth/setup")
async def api_setup(request: Request):
    if _auth_disabled():
        return _json_error("AUTH_DISABLED", "当前已关闭口令登录（AUTH_MODE=none）", 403)
    if _is_setup():
        return _json_error("FORBIDDEN", "已初始化", 403)
    client = _client_ip(request)
    if setup_limiter.is_blocked(client):
        return _json_error("RATE_LIMITED", "初始化尝试过于频繁，请 60 秒后再试", 429)
    body = await json_body(request, required=False)
    provided = body.get("token", "")
    if not isinstance(provided, str):
        provided = ""
    if not setup_token_ok(load_setup_token(), provided):
        setup_limiter.record_failure(client)
        db.audit("user", "auth.setup_failed", client)
        # Deliberately vague: do not reveal whether a token exists/expired.
        return _json_error("SETUP_FORBIDDEN", "初始化令牌无效或已失效", 403)
    password = body.get("password", "")
    error = _valid_password(password)
    if error:
        return _json_error("VALIDATION_ERROR", error, 400)
    setup_limiter.reset(client)
    db.set_setting("password_hash", hash_password(password))
    clear_setup_token()
    token, csrf = sessions.create()
    resp = JSONResponse({"ok": True, "csrf_token": csrf})
    _set_session_cookie(resp, token, request)
    db.audit("user", "auth.setup", "")
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if _auth_disabled():
        return RedirectResponse("/", status_code=303)
    if not _is_setup():
        return RedirectResponse("/setup", status_code=303)
    return _page(request, "login.html", error="")


@app.post("/api/v1/auth/login")
async def api_login(request: Request):
    if _auth_disabled():
        return _json_error("AUTH_DISABLED", "当前已关闭口令登录（AUTH_MODE=none）", 403)
    client = request.client.host if request.client else "unknown"
    if limiter.is_blocked(client):
        return _json_error("RATE_LIMITED", "尝试过于频繁，请 60 秒后再试", 429)
    try:
        body = await json_body(request, required=True)
    except HTTPException:
        # Malformed bodies are a failed attempt: no free 5xx/log-flood path.
        limiter.record_failure(client)
        db.audit("user", "auth.login_bad_request", client)
        raise
    password = body.get("password", "")
    stored = db.get_setting("password_hash", "") or ""
    if not isinstance(password, str):
        limiter.record_failure(client)
        db.audit("user", "auth.login_bad_request", client)
        return _json_error("VALIDATION_ERROR", "口令必须是字符串", 400)
    if not verify_password(password, stored):
        limiter.record_failure(client)
        db.audit("user", "auth.login_failed", client)
        return _json_error("AUTH_INVALID", "口令错误", 401)
    limiter.reset(client)
    token, csrf = sessions.create()
    resp = JSONResponse({"ok": True, "csrf_token": csrf})
    _set_session_cookie(resp, token, request)
    db.audit("user", "auth.login", client)
    return resp


@app.post("/api/v1/auth/logout")
def api_logout(request: Request):
    sess = _session(request)
    if sess is not None:
        if not csrf_ok(sess.get("csrf"), request.headers.get(CSRF_HEADER)):
            raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "CSRF 校验失败"})
        # Server-side revocation (P1-04): bump the epoch so every issued
        # cookie is invalid even if the browser keeps it.
        sessions.revoke_all()
        db.audit("user", "auth.logout", "")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(
        SESSION_COOKIE, path="/", secure=_cookie_secure(request), httponly=True, samesite="lax"
    )
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


def _dir_has_children(path: str) -> bool:
    """Whether a directory has at least one entry (an OSError counts as empty)."""
    try:
        with os.scandir(path) as it:
            return next(it, None) is not None
    except OSError:
        return False


@app.get("/api/v1/roots/tree")
def api_tree(request: Request, root_id: int = 0) -> dict:
    _require_api(request)
    _check_path_id(root_id, "目录")
    root = db.query_one("SELECT * FROM scan_roots WHERE id=? AND enabled=1", (root_id,))
    if root is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "目录不存在"})
    entries = []
    try:
        with os.scandir(root["mount_path"]) as it:
            for e in it:
                is_dir = e.is_dir(follow_symlinks=False)
                entries.append(
                    {
                        "name": e.name,
                        "path": e.path,
                        # DEF-09: drilling down one level needs to know whether
                        # a directory hides more entries (never a full walk).
                        "is_dir": is_dir,
                        "has_children": _dir_has_children(e.path) if is_dir else False,
                    }
                )
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
        # DEF-09: read-only array view; the stored/write contract stays a
        # comma-separated string for backwards compatibility.
        "globs": {
            "include": _glob_list(row["include_globs"]),
            "exclude": _glob_list(row["exclude_globs"]),
        },
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


@app.post("/api/v1/plans", status_code=201)
async def api_plan_create(request: Request) -> dict:
    _require_api(request)
    body = await json_body(request, required=True)
    name = _body_str(body, "name", label="方案名", maximum=PLAN_NAME_MAX).strip()
    if not name:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "方案名必填"})
    roots = _body_id_list(body, "root_ids", "目录编号")
    if not roots:
        roots = [r["id"] for r in db.query("SELECT id FROM scan_roots WHERE enabled=1")]
    if not roots:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "至少选择一个目录"})
    trigger_type = _body_str(body, "trigger_type", "manual", label="触发方式")
    if trigger_type not in ("manual", "daily", "weekly", "interval", "notify_only"):
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "无效触发方式"})
    trigger = _body_obj(body, "trigger")
    window = _body_obj(body, "window")
    include_globs = _body_str(body, "include_globs", maximum=2000, label="包含规则")
    exclude_globs = _body_str(body, "exclude_globs", maximum=2000, label="排除规则")
    rate_meta = _body_int(body, "rate_meta", 2000, minimum=0)
    rate_hash = _body_int(body, "rate_hash", 50, minimum=0)
    now = now_iso()
    db.execute(
        "INSERT INTO scan_plans(name, roots_json, include_globs, exclude_globs, trigger_type, "
        "trigger_json, rate_meta, rate_hash, window_json, enabled, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,0,?,?)",
        (
            name,
            json.dumps(roots),
            include_globs,
            exclude_globs,
            trigger_type,
            json.dumps(trigger),
            rate_meta,
            rate_hash,
            json.dumps(window),
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
    _check_path_id(plan_id, "方案")
    row = db.query_one("SELECT * FROM scan_plans WHERE id=?", (plan_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    body = await json_body(request, required=False)
    target = dict(row)
    if "name" in body:
        target["name"] = _body_str(body, "name", label="方案名", maximum=PLAN_NAME_MAX).strip()
        if not target["name"]:
            raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "方案名必填"})
    if "root_ids" in body:
        target["roots_json"] = json.dumps(_body_id_list(body, "root_ids", "目录编号") or [])
    if "include_globs" in body:
        target["include_globs"] = _body_str(body, "include_globs", maximum=2000, label="包含规则")
    if "exclude_globs" in body:
        target["exclude_globs"] = _body_str(body, "exclude_globs", maximum=2000, label="排除规则")
    if "trigger_type" in body:
        target["trigger_type"] = _body_str(body, "trigger_type", label="触发方式")
        if target["trigger_type"] not in ("manual", "daily", "weekly", "interval", "notify_only"):
            raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "无效触发方式"})
    if "trigger" in body:
        target["trigger_json"] = json.dumps(_body_obj(body, "trigger"))
    if "window" in body:
        target["window_json"] = json.dumps(_body_obj(body, "window"))
    if "rate_meta" in body:
        target["rate_meta"] = _body_int(body, "rate_meta", 0, minimum=0)
    if "rate_hash" in body:
        target["rate_hash"] = _body_int(body, "rate_hash", 0, minimum=0)
    if "enabled" in body:
        enabled = body["enabled"]
        if isinstance(enabled, bool):
            target["enabled"] = 1 if enabled else 0
        elif isinstance(enabled, int) and enabled in (0, 1):
            target["enabled"] = enabled
        else:
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "enabled 必须是布尔值", "details": {"field": "enabled"}})
    updates = {
        "name": target["name"],
        "roots_json": target["roots_json"],
        "include_globs": target["include_globs"],
        "exclude_globs": target["exclude_globs"],
        "trigger_type": target["trigger_type"],
        "trigger_json": target["trigger_json"],
        "rate_meta": target["rate_meta"],
        "rate_hash": target["rate_hash"],
        "window_json": target["window_json"],
        "enabled": target["enabled"],
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


@app.post("/api/v1/plans/{plan_id}/test-globs")
async def api_plan_test_globs(plan_id: int, request: Request) -> dict:
    """DEF-02: read-only preview of what the plan's glob rules would match.

    Nothing is written: no index rows, no plan mutations, no filesystem
    changes. Guard-unsafe deployments refuse here just like scans/export.
    """
    _require_api(request)
    _check_path_id(plan_id, "方案")
    blocked = _guard_unsafe_response()
    if blocked is not None:
        return blocked
    row = db.query_one("SELECT * FROM scan_plans WHERE id=?", (plan_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    body = await json_body(request, required=False)
    include_value = row["include_globs"] or ""
    exclude_value = row["exclude_globs"] or ""
    # Optional overrides let the form preview unsaved rules; stored values win
    # only when a field is absent.
    if "include_globs" in body:
        include_value = _body_str(body, "include_globs", maximum=2000, label="包含规则")
    if "exclude_globs" in body:
        exclude_value = _body_str(body, "exclude_globs", maximum=2000, label="排除规则")
    roots = []
    for rid in json.loads(row["roots_json"] or "[]"):
        root = db.query_one("SELECT * FROM scan_roots WHERE id=? AND enabled=1", (rid,))
        if root is not None:
            roots.append(root)
    if not roots:
        # A plan without explicit roots scans every enabled root.
        roots = db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
    preview = _preview_globs(roots, include_value, exclude_value)
    preview["plan_id"] = plan_id
    preview["roots"] = [root["mount_path"] for root in roots]
    preview["include_globs"] = _glob_list(include_value)
    preview["exclude_globs"] = _glob_list(exclude_value)
    return preview


@app.delete("/api/v1/plans/{plan_id}")
def api_plan_delete(plan_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(plan_id, "方案")
    db.execute("DELETE FROM scan_plans WHERE id=?", (plan_id,))
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------------
@app.post("/api/v1/scans")
async def api_scan_start(request: Request) -> dict:
    _require_api(request)
    blocked = _guard_unsafe_response()
    if blocked is not None:
        return blocked
    body = await json_body(request, required=False)
    plan_id = body.get("plan_id")
    if plan_id in (None, "", 0):
        plan_id = None
    if plan_id is not None:
        if isinstance(plan_id, bool) or not isinstance(plan_id, int):
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "plan_id 必须是整数", "details": {"field": "plan_id"}})
        _check_path_id(plan_id, "方案")
        if db.query_one("SELECT id FROM scan_plans WHERE id=?", (plan_id,)) is None:
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
    limit = _clamp_limit(limit, 20, 100)
    rows = db.query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,))
    return {"items": [_run_row(r) for r in rows]}


@app.get("/api/v1/scans/{run_id}")
def api_scan_detail(run_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(run_id, "任务")
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "任务不存在"})
    return _run_row(row)


@app.post("/api/v1/scans/{run_id}/{action}")
def api_scan_control(run_id: int, action: str, request: Request) -> dict:
    """Pause / resume / cancel a scan with a guarded state transition.

    UAT 2026-11-20: clicking 暂停 on a scan that had just finished flipped the
    row to paused, then 继续 flipped it to running — with no worker thread left,
    so the progress bar stayed frozen forever. Terminal runs are now rejected
    and every transition is a conditional UPDATE (id + expected status +
    finished_at IS NULL), so a late click can never resurrect a dead run.
    """
    _require_api(request)
    _check_path_id(run_id, "任务")
    # action -> (new status, allowed current statuses)
    mapping = {
        "pause": ("paused", ("running",)),
        "resume": ("running", ("paused",)),
        "cancel": ("cancelled", ("running", "paused")),
    }
    labels = {"pause": "暂停", "resume": "继续", "cancel": "取消"}
    if action not in mapping:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "未知操作"})
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "任务不存在"})
    target, allowed = mapping[action]
    if row["status"] in ("completed", "cancelled", "failed") or row["finished_at"]:
        raise HTTPException(
            status_code=409,
            detail={"code": "SCAN_FINISHED", "message": "该任务已经结束，不需要再操作；要重新检查请新建一次扫描"},
        )
    if row["status"] not in allowed:
        raise HTTPException(
            status_code=409,
            detail={"code": "SCAN_STATE", "message": f"当前状态不能执行「{labels[action]}」，请刷新页面"},
        )
    marks = ",".join("?" for _ in allowed)
    cur = db.execute(
        f"UPDATE scan_runs SET status=? WHERE id=? AND status IN ({marks}) AND finished_at IS NULL",
        (target, run_id, *allowed),
    )
    db.commit()
    if (cur.rowcount or 0) == 0:
        raise HTTPException(
            status_code=409,
            detail={"code": "SCAN_STATE", "message": "任务状态刚刚发生变化，请刷新页面再试"},
        )
    db.audit("user", f"scan.{action}", f"run={run_id}")
    return {"id": run_id, "status": target}


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
    dir: str | None = None,
    ext: str | None = None,
    cursor: int = 0,
    limit: int = 50,
) -> dict:
    _require_api(request)
    cursor = _check_query_int(cursor, "cursor")
    if min_size is not None:
        min_size = _check_query_int(min_size, "min_size")
    limit = _clamp_limit(limit, 50, 200)
    if dir is not None and len(dir) > 1024:
        raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "dir 过长", "details": {"field": "dir"}})
    if ext is not None and len(ext) > 64:
        raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "ext 过长", "details": {"field": "ext"}})
    data = review.list_groups(
        db, kind, status, q, min_size, cursor, limit,
        dir_prefix=dir, ext=ext,
    )
    data["stats"] = review.stats(db)
    return data


@app.get("/api/v1/review/groups/{group_id}")
def api_review_group(group_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(group_id, "分组")
    data = review.group_detail(db, group_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "分组不存在"})
    return data


@app.put("/api/v1/review/groups/{group_id}")
async def api_review_save(group_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(group_id, "分组")
    body = await json_body(request, required=True)
    policy = body.get("policy")
    if policy is not None:
        if not isinstance(policy, str) or policy not in KEEP_POLICIES:
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "保留策略不合法", "details": {"field": "policy"}})
    items = body.get("items") or []
    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "items 必须是数组"})
    decisions: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "items 的每一项必须是对象"})
        item_id = item.get("item_id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 0 or item_id > SQLITE_INT_MAX:
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "item_id 不合法", "details": {"field": "item_id"}})
        decision = item.get("decision")
        if not isinstance(decision, str):
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "decision 不合法", "details": {"field": "decision"}})
        decisions.append({"item_id": item_id, "decision": decision})
    try:
        return review.save_decisions(db, group_id, policy, decisions)
    except review.ReviewError as exc:
        return _json_error(exc.code, exc.message, 422 if exc.code == "GROUP_KEEP_VIOLATION" else 400,
                           exc.details)


@app.post("/api/v1/review/groups/{group_id}/skip")
def api_review_skip(group_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(group_id, "分组")
    return review.skip_group(db, group_id)


@app.post("/api/v1/review/groups/{group_id}/recheck")
def api_review_recheck(group_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(group_id, "分组")
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
    blocked = _guard_unsafe_response()
    if blocked is not None:
        return blocked
    body = await json_body(request, required=False)
    note = _body_str(body, "note", label="备注", maximum=PLAN_NOTE_MAX)
    try:
        return plans.generate_plan(db, note)
    except plans.PlanError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})


@app.get("/api/v1/delete-plans")
def api_plans_list(request: Request) -> dict:
    _require_api(request)
    return {"items": plans.list_plans(db)}


@app.get("/api/v1/delete-plans/{plan_id}")
def api_plan_detail(plan_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(plan_id, "方案")
    data = plans.plan_detail(db, plan_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    return data


@app.post("/api/v1/delete-plans/{plan_id}/recheck")
def api_plan_recheck(plan_id: int, request: Request) -> dict:
    _require_api(request)
    _check_path_id(plan_id, "方案")
    data = plans.recheck_plan(db, plan_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "方案不存在"})
    return data


@app.get("/api/v1/delete-plans/{plan_id}/export")
def api_plan_export(plan_id: int, request: Request, format: str = "csv"):
    _require_api(request)
    _check_path_id(plan_id, "方案")
    blocked = _guard_unsafe_response()
    if blocked is not None:
        return blocked
    try:
        filename, media_type, payload = exporter.build_export(db, plan_id, format)
    except exporter.ExportError as exc:
        # NOT_FOUND/validation keep their old meaning; every other refusal
        # (e.g. plan still needs review) is a state conflict -> 409.
        status = {"NOT_FOUND": 404, "VALIDATION_ERROR": 400}.get(exc.code, 409)
        raise HTTPException(status_code=status,
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
    body = await json_body(request, required=False)
    if "all" in body and not isinstance(body["all"], bool):
        raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "all 必须是布尔值", "details": {"field": "all"}})
    if body.get("all"):
        db.execute("UPDATE notifications SET read_at=? WHERE read_at IS NULL", (now_iso(),))
    else:
        ids = _body_id_list(body, "ids", "通知编号") or []
        for nid in ids:
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
    body = await json_body(request, required=True)
    unknown = sorted(set(body) - set(SETTINGS_INT_RANGES) - {"default_keep_policy", "notify_in_app"})
    if unknown:
        raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": f"未知设置项: {', '.join(unknown)}", "details": {"fields": unknown}})
    if "default_keep_policy" in body:
        policy = body["default_keep_policy"]
        if policy not in KEEP_POLICIES:
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "保留策略不合法", "details": {"field": "default_keep_policy"}})
        db.set_setting("default_keep_policy", policy)
    for key, (low, high) in SETTINGS_INT_RANGES.items():
        if key in body:
            value = body[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": f"{key} 必须是 {low}..{high} 的整数", "details": {"field": key}})
            db.set_setting(key, str(value))
    if "notify_in_app" in body:
        value = body["notify_in_app"]
        if not isinstance(value, bool):
            raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "notify_in_app 必须是布尔值", "details": {"field": "notify_in_app"}})
        db.set_setting("notify_in_app", "1" if value else "0")
    return {"ok": True}


@app.post("/api/v1/settings/password")
async def api_password_change(request: Request) -> dict:
    _require_api(request)
    body = await json_body(request, required=True)
    old = body.get("old_password", "")
    if not isinstance(old, str):
        return _json_error("VALIDATION_ERROR", "旧口令必须是字符串", 400)
    stored = db.get_setting("password_hash", "") or ""
    if not verify_password(old, stored):
        return _json_error("AUTH_INVALID", "旧口令错误", 401)
    new = body.get("new_password", "")
    error = _valid_password(new)
    if error:
        return _json_error("VALIDATION_ERROR", error.replace("口令", "新口令", 1), 400)
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
    name_groups = db.query_one("SELECT COUNT(*) AS n FROM review_groups WHERE kind='name'")
    completed = db.query_one("SELECT COUNT(*) AS n FROM scan_runs WHERE status='completed'")
    roots = db.query_one("SELECT COUNT(*) AS n FROM scan_roots WHERE enabled=1")
    plans = db.query_one("SELECT COUNT(*) AS n FROM scan_plans")
    return {
        "files": files["n"],
        "total_bytes": files["bytes"],
        "content_groups": groups["n"],
        "name_groups": int(name_groups["n"]) if name_groups else 0,
        "wasted_bytes": groups["wasted"],
        "review": st,
        "last_scan": _run_row(last) if last else None,
        "roots": int(roots["n"]) if roots else 0,
        "plans": int(plans["n"]) if plans else 0,
        "completed_scans": int(completed["n"]) if completed else 0,
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


def _root_summary(mount_path: str) -> dict:
    """File counts/sizes per top-level entry, from the last known index."""
    prefix = mount_path.rstrip("/") + "/"
    start = len(prefix) + 1  # SQLite substr() is 1-based over characters
    total = db.query_one(
        "SELECT COUNT(*) AS n, COALESCE(SUM(f.size),0) AS bytes "
        "FROM file_paths p JOIN files f ON f.dev=p.dev AND f.ino=p.ino "
        "WHERE f.status='present' AND p.path LIKE ?",
        (prefix + "%",),
    )
    tops = db.query(
        "SELECT CASE WHEN instr(substr(p.path, ?), '/') > 0 "
        "THEN substr(p.path, ?, instr(substr(p.path, ?), '/') - 1) "
        "ELSE '' END AS name, COUNT(*) AS n, COALESCE(SUM(f.size),0) AS bytes "
        "FROM file_paths p JOIN files f ON f.dev=p.dev AND f.ino=p.ino "
        "WHERE f.status='present' AND p.path LIKE ? GROUP BY name",
        (start, start, start, prefix + "%"),
    )
    return {
        "files": int(total["n"]) if total else 0,
        "bytes": int(total["bytes"]) if total else 0,
        "tops": [
            {"name": t["name"] or "", "files": int(t["n"]), "bytes": int(t["bytes"])}
            for t in tops
        ],
    }


@app.get("/roots", response_class=HTMLResponse)
def roots_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    roots = db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
    guard = _guard_snapshot()
    guard_by_path = {g.get("path"): g for g in guard.get("roots", [])}
    trees = []
    for r in roots:
        entries = []
        try:
            with os.scandir(r["mount_path"]) as it:
                for e in it:
                    entries.append({
                        "name": e.name,
                        "is_dir": e.is_dir(follow_symlinks=False),
                    })
        except OSError as exc:
            entries = [{"name": f"(无法读取: {exc.strerror})", "is_dir": False}]
        entries.sort(key=lambda x: (not x["is_dir"], x["name"]))
        summary = _root_summary(r["mount_path"])
        counts = {t["name"]: t for t in summary["tops"] if t["name"]}
        merged = []
        for e in entries:
            stat = counts.pop(e["name"], None) if e["is_dir"] else None
            merged.append({
                "name": e["name"],
                "is_dir": e["is_dir"],
                "files": stat["files"] if stat else None,
                "bytes": stat["bytes"] if stat else None,
            })
        # directories that only exist in the index because they were removed later
        for name, stat in sorted(counts.items(), key=lambda kv: -kv[1]["bytes"])[:20]:
            merged.append({"name": name, "is_dir": True, "files": stat["files"],
                           "bytes": stat["bytes"], "stale": True})
        trees.append({
            "root": r,
            "entries": merged[:200],
            "summary": summary,
            "guard": guard_by_path.get(r["mount_path"]),
        })
    return _page(request, "roots.html", trees=trees, guard=guard)


WEEKDAY_NAMES = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")
STATUS_TEXT = {
    "running": "扫描中",
    "completed": "已完成",
    "paused": "已暂停",
    "cancelled": "已取消",
    "failed": "失败",
}
PHASE_TEXT = {
    "walk": "扫描目录和文件",
    "hash": "比对文件内容",
    "group": "整理重复分组",
    "done": "已完成",
}


def _trigger_text(plan: dict) -> str:
    trig = plan.get("trigger") or {}
    ttype = plan.get("trigger_type")
    if ttype == "manual":
        return "仅手动发起"
    if ttype == "daily":
        return f"每天 {trig.get('time', '02:00')}"
    if ttype == "weekly":
        try:
            day = WEEKDAY_NAMES[int(trig.get("day", 1)) - 1]
        except (ValueError, IndexError):
            day = "周一"
        return f"每{day} {trig.get('time', '02:00')}"
    if ttype == "interval":
        return f"每 {trig.get('minutes', 1440)} 分钟"
    if ttype == "notify_only":
        return f"每天 {trig.get('time', '02:00')} 提醒（不自动扫描）"
    return str(ttype)


@app.get("/plans", response_class=HTMLResponse)
def plans_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    roots = db.query("SELECT * FROM scan_roots WHERE enabled=1 ORDER BY id")
    root_labels = {r["id"]: (r["label"] or r["mount_path"]) for r in roots}
    rows = []
    for r in db.query("SELECT * FROM scan_plans ORDER BY id"):
        item = _plan_row(r)
        item["trigger_text"] = _trigger_text(item)
        item["roots_text"] = "、".join(
            root_labels.get(rid, f"目录 #{rid}") for rid in item["roots"]
        ) or "全部目录"
        rows.append(item)
    return _page(request, "plans.html", plans=rows, roots=roots)


@app.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    runs = [_run_row(r) for r in db.query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 20")]
    for run in runs:
        run["phase_text"] = PHASE_TEXT.get(run["phase"], run["phase"])
        run["status_text"] = STATUS_TEXT.get(run["status"], run["status"])
    completed = [r for r in runs if r["status"] == "completed"]
    baseline = int((completed[0]["stats"] or {}).get("files_indexed") or 0) if completed else 0
    current = next(
        (r for r in runs if r["status"] in ("running", "paused")), None
    )
    return _page(
        request, "scans.html", runs=runs, baseline=baseline, current=current,
        status_text=STATUS_TEXT, phase_text=PHASE_TEXT,
    )


@app.get("/review", response_class=HTMLResponse)
def review_page(
    request: Request,
    kind: str = "content",
    status: str = "pending",
    dir: str = "",
    ext: str = "",
    cursor: int = 0,
):
    redir = _require_page(request)
    if redir:
        return redir
    cursor = 0 if cursor < 0 else min(cursor, SQLITE_INT_MAX)
    filters = {"dir": dir.strip(), "ext": ext.strip()}
    data = review.list_groups(
        db, kind, status or None, None, None, cursor, 50,
        dir_prefix=filters["dir"] or None, ext=filters["ext"] or None,
    )
    return _page(
        request, "review.html",
        groups=data["items"], kind=kind, status=status,
        dir=filters["dir"], ext=filters["ext"],
        next_cursor=data.get("next_cursor"), stats=review.stats(db),
    )


@app.get("/review/{group_id}", response_class=HTMLResponse)
def review_detail_page(request: Request, group_id: int):
    redir = _require_page(request)
    if redir:
        return redir
    if group_id < 0 or group_id > SQLITE_INT_MAX:
        return RedirectResponse("/review", status_code=303)
    data = review.group_detail(db, group_id)
    if data is None:
        return RedirectResponse("/review", status_code=303)
    members = []
    missing_count = 0
    changed_count = 0
    for item in data["items"]:
        state, exists, reached = "missing", False, False
        try:
            st = os.stat(item["path"], follow_symlinks=False)
            exists = True
            reached = os.access(item["path"], os.R_OK)
            if st.st_size != item["size"] or st.st_mtime_ns != item["mtime_ns"]:
                state = "changed"
            else:
                state = "consistent"
        except OSError:
            pass
        if state == "missing":
            missing_count += 1
        elif state == "changed":
            changed_count += 1
        members.append(
            {**item, "exists": exists, "readable": reached, "state": state}
        )
    return _page(
        request, "review_detail.html", group=data, members=members,
        missing_count=missing_count, changed_count=changed_count,
    )


@app.get("/delete-plans", response_class=HTMLResponse)
def delete_plans_page(request: Request):
    redir = _require_page(request)
    if redir:
        return redir
    return _page(
        request, "delete_plans.html",
        plans=plans.list_plans(db), stats=review.stats(db),
    )


@app.get("/delete-plans/{plan_id}", response_class=HTMLResponse)
def delete_plan_detail_page(request: Request, plan_id: int):
    redir = _require_page(request)
    if redir:
        return redir
    if plan_id < 0 or plan_id > SQLITE_INT_MAX:
        return RedirectResponse("/delete-plans", status_code=303)
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
        guard=_guard_snapshot(),
        log_files=_log_files(),
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
