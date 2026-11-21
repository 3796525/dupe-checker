"""HTTP API: auth/session hardening, guard gating and the read-only review workflow."""
import importlib
import os

import pytest
from fastapi.testclient import TestClient

from app import guard as guard_mod
from app.config import config
from app.db import now_iso
from app.exporter import ExportError
from app.guard import GuardReport, RootCheck
from app.scanner import Scanner
from app.security import (
    CSRF_HEADER,
    SESSION_COOKIE,
    SETUP_TOKEN_ENV,
    LoginRateLimiter,
    SessionManager,
    clear_setup_token,
    ensure_setup_token,
    setup_token_path,
)
from helpers import add_root, build_tree, run_scan

PASSWORD = "test-password-123"
TEST_SETUP_TOKEN = "test-setup-token-6f4c2a"


@pytest.fixture()
def web(db, monkeypatch):
    module = importlib.import_module("app.web")
    monkeypatch.setattr(module, "db", db)
    monkeypatch.setattr(module, "sessions", SessionManager(db))
    monkeypatch.setattr(module, "limiter", LoginRateLimiter())
    monkeypatch.setattr(module, "setup_limiter", LoginRateLimiter())
    monkeypatch.setattr(module, "scan_engine", Scanner(db))
    monkeypatch.setattr(module, "guard_report", GuardReport())
    monkeypatch.setenv(SETUP_TOKEN_ENV, TEST_SETUP_TOKEN)
    guard_mod.reset_state()
    clear_setup_token()
    yield module
    guard_mod.reset_state()
    clear_setup_token()


@pytest.fixture()
def client(web):
    return TestClient(web.app)


def login(client, token: str = TEST_SETUP_TOKEN) -> str:
    resp = client.post("/api/v1/auth/setup", json={"password": PASSWORD, "token": token})
    assert resp.status_code == 200, resp.text
    return resp.json()["csrf_token"]


def test_requires_auth(client):
    assert client.get("/api/v1/plans").status_code == 401
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"] == "/setup"


# ---------------------------------------------------------------------------
# P1-01: one-time setup token
# ---------------------------------------------------------------------------
def test_setup_page_requires_token(client):
    assert client.get("/setup", follow_redirects=False).status_code == 403
    assert client.get("/setup", params={"token": "wrong-token"}).status_code == 403
    ok = client.get("/setup", params={"token": TEST_SETUP_TOKEN})
    assert ok.status_code == 200
    assert 'name="password"' in ok.text
    assert f'value="{TEST_SETUP_TOKEN}"' in ok.text


def test_setup_rejects_missing_or_wrong_token(client, db):
    assert client.post("/api/v1/auth/setup", json={"password": PASSWORD}).status_code == 403
    assert client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": "wrong-token"}
    ).status_code == 403
    assert not db.get_setting("password_hash"), "no account may be created without a token"
    assert client.get("/api/v1/plans").status_code == 401


def test_setup_token_rate_limited(client, db):
    for _ in range(5):
        assert client.post(
            "/api/v1/auth/setup", json={"password": PASSWORD, "token": "bad-token"}
        ).status_code == 403
    blocked = client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": TEST_SETUP_TOKEN}
    )
    assert blocked.status_code == 429
    assert not db.get_setting("password_hash")


def test_setup_token_file_removed_after_success(client, monkeypatch):
    monkeypatch.delenv(SETUP_TOKEN_ENV, raising=False)
    clear_setup_token()
    token = ensure_setup_token()
    path = setup_token_path()
    assert path.exists()
    assert (path.stat().st_mode & 0o777) == 0o600

    assert client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": "nope"}
    ).status_code == 403
    resp = client.post("/api/v1/auth/setup", json={"password": PASSWORD, "token": token})
    assert resp.status_code == 200, resp.text
    assert not path.exists(), "one-time setup token file must be removed after success"
    assert client.get("/api/v1/plans").status_code == 200


def test_first_run_setup_token_banner_and_cleanup(web, db, monkeypatch, capsys):
    monkeypatch.delenv(SETUP_TOKEN_ENV, raising=False)
    clear_setup_token()
    web._init_setup_token()
    out = capsys.readouterr().out
    path = setup_token_path()
    assert path.exists()
    token = path.read_text(encoding="utf-8").strip()
    assert token
    assert token in out, "the token must be visible in the startup banner"
    assert "初始化令牌" in out
    assert "请先查看容器日志获取初始化令牌" in out

    # Once a password exists the token file is removed on the next startup.
    db.set_setting("password_hash", "already-set")
    web._init_setup_token()
    assert not path.exists()


def test_short_password_rejected(client):
    resp = client.post(
        "/api/v1/auth/setup", json={"password": "short", "token": TEST_SETUP_TOKEN}
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# P1-04: cookie flags, TTL and server-side logout
# ---------------------------------------------------------------------------
def test_setup_cookie_secure_behind_tls_proxy(client):
    resp = client.post(
        "/api/v1/auth/setup",
        json={"password": PASSWORD, "token": TEST_SETUP_TOKEN},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert resp.status_code == 200, resp.text
    cookie = resp.headers["set-cookie"]
    assert "; secure" in cookie.lower()
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()


def test_cookie_not_secure_on_plain_http(client):
    resp = client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": TEST_SETUP_TOKEN}
    )
    assert resp.status_code == 200
    assert "; secure" not in resp.headers["set-cookie"].lower()


def test_cookie_secure_mode_always(client, monkeypatch):
    monkeypatch.setattr(config, "session_cookie_secure", "always")
    resp = client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": TEST_SETUP_TOKEN}
    )
    assert "; secure" in resp.headers["set-cookie"].lower()


def test_session_ttl_sets_cookie_max_age(client, monkeypatch):
    monkeypatch.setattr(config, "session_ttl_seconds", 120)
    resp = client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": TEST_SETUP_TOKEN}
    )
    assert "Max-Age=120" in resp.headers["set-cookie"]


def test_default_session_ttl_is_eight_hours():
    assert config.session_ttl_seconds == 8 * 3600


def test_logout_requires_csrf(client):
    login(client)
    assert client.post("/api/v1/auth/logout").status_code == 403


def test_logout_revokes_old_cookie_server_side(client):
    csrf = login(client)
    old_cookie = client.cookies.get(SESSION_COOKIE)
    assert old_cookie

    resp = client.post("/api/v1/auth/logout", headers={CSRF_HEADER: csrf})
    assert resp.status_code == 200
    assert client.get("/api/v1/plans").status_code == 401

    # Even if the browser replays the old cookie, the server-side epoch bump
    # makes it useless.
    client.cookies.set(SESSION_COOKIE, old_cookie)
    assert client.get("/api/v1/plans").status_code == 401


# ---------------------------------------------------------------------------
# existing auth / CSRF behaviour
# ---------------------------------------------------------------------------
def test_setup_then_csrf_is_enforced(client):
    csrf = login(client)
    assert client.post(
        "/api/v1/auth/setup", json={"password": PASSWORD, "token": TEST_SETUP_TOKEN}
    ).status_code == 403
    assert client.get("/api/v1/plans").status_code == 200

    # a state-changing call without the header is refused
    assert client.post("/api/v1/plans", json={"name": "x"}).status_code == 403
    ok = client.post(
        "/api/v1/plans",
        json={"name": "夜间扫描", "root_ids": [1], "trigger_type": "manual"},
        headers={CSRF_HEADER: csrf},
    )
    # root id 1 does not exist here, but validation happens after roots lookup: either 201 or 400 is fine,
    # what matters is that CSRF is accepted and the request reaches the handler.
    assert ok.status_code in (201, 400)
    assert ok.status_code != 403


def test_wrong_password_and_rate_limit(client):
    csrf = login(client)
    assert client.post("/api/v1/auth/logout", headers={CSRF_HEADER: csrf}).status_code == 200
    for _ in range(5):
        r = client.post("/api/v1/auth/login", json={"password": "wrong-password-1"})
        assert r.status_code == 401
    blocked = client.post("/api/v1/auth/login", json={"password": PASSWORD})
    assert blocked.status_code == 429


def test_pages_render(client):
    login(client)
    for path in ("/", "/roots", "/plans", "/scans", "/review", "/delete-plans", "/settings", "/notifications"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert "text/html" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# P1-05: guard unsafe blocks protected routes
# ---------------------------------------------------------------------------
def test_guard_unsafe_blocks_protected_routes(client, db):
    csrf = login(client)
    headers = {CSRF_HEADER: csrf}
    bad = GuardReport(
        verified_at="2026-01-01T00:00:00+0800",
        roots=[RootCheck(
            path="/mnt/readonly", exists=True, is_dir=True, readable=True,
            readonly=False, error="目录可写！必须以只读方式挂载",
        )],
    )
    guard_mod.apply_report(bad, db)
    assert guard_mod.is_unsafe() is True
    try:
        scan = client.post("/api/v1/scans", json={}, headers=headers)
        assert scan.status_code == 409
        assert scan.json()["error"]["code"] == "GUARD_UNSAFE"

        plan = client.post("/api/v1/delete-plans", json={"note": "x"}, headers=headers)
        assert plan.status_code == 409
        assert plan.json()["error"]["code"] == "GUARD_UNSAFE"

        export = client.get("/api/v1/delete-plans/1/export", params={"format": "csv"})
        assert export.status_code == 409
        assert "只读自检" in export.json()["error"]["message"]

        globs = client.post("/api/v1/plans/1/test-globs", json={}, headers=headers)
        assert globs.status_code == 409
        assert globs.json()["error"]["code"] == "GUARD_UNSAFE"

        assert client.get("/health").json()["status"] == "fatal"
        assert client.get("/api/v1/system/guard").status_code == 200
    finally:
        guard_mod.reset_state()


def test_export_conflict_maps_to_409(client, web, monkeypatch):
    login(client)

    def boom(db, plan_id, fmt):
        raise ExportError("PLAN_NOT_FINAL", "该方案尚未通过复核，禁止导出")

    monkeypatch.setattr(web.exporter, "build_export", boom)
    resp = client.get("/api/v1/delete-plans/1/export")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "PLAN_NOT_FINAL"


def test_export_unknown_plan_maps_to_404(client):
    login(client)
    assert client.get("/api/v1/delete-plans/999999/export").status_code == 404


# ---------------------------------------------------------------------------
# read-only review workflow end to end
# ---------------------------------------------------------------------------
def test_full_read_only_workflow(client, web, db, root):
    csrf = login(client)
    headers = {CSRF_HEADER: csrf}
    root_id = add_root(db, root)
    build_tree(root)

    plan = client.post(
        "/api/v1/plans",
        json={"name": "e2e", "root_ids": [root_id], "trigger_type": "manual",
              "rate_meta": 100000, "rate_hash": 10000},
        headers=headers,
    )
    assert plan.status_code == 201, plan.text
    plan_id = plan.json()["id"]

    started = client.post("/api/v1/scans", json={"plan_id": plan_id}, headers=headers)
    assert started.status_code == 200, started.text
    web.scan_engine._thread.join(120)
    run_id = started.json()["id"]
    run = client.get(f"/api/v1/scans/{run_id}").json()
    assert run["status"] == "completed"

    groups = client.get("/api/v1/review/groups", params={"kind": "content"}).json()
    assert groups["items"], "scan must produce content duplicate groups"
    group_id = groups["items"][0]["id"]
    detail = client.get(f"/api/v1/review/groups/{group_id}").json()
    keep, delete = detail["items"][0], detail["items"][1]

    bad = client.put(
        f"/api/v1/review/groups/{group_id}",
        json={"items": [{"item_id": keep["id"], "decision": "delete"},
                        {"item_id": delete["id"], "decision": "delete"}]},
        headers=headers,
    )
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "GROUP_KEEP_VIOLATION"

    saved = client.put(
        f"/api/v1/review/groups/{group_id}",
        json={"items": [{"item_id": keep["id"], "decision": "keep"},
                        {"item_id": delete["id"], "decision": "delete"}]},
        headers=headers,
    )
    assert saved.status_code == 200
    assert saved.json()["status"] == "reviewed"

    made = client.post("/api/v1/delete-plans", json={"note": "api"}, headers=headers)
    assert made.status_code == 200, made.text
    delete_plan_id = made.json()["id"]
    assert made.json()["total_items"] == 1

    csv_resp = client.get(f"/api/v1/delete-plans/{delete_plan_id}/export", params={"format": "csv"})
    assert csv_resp.status_code == 200
    assert delete["path"] in csv_resp.text
    for bad_command in ("rm -rf", "rm -f", "unlink("):
        assert bad_command not in csv_resp.text

    # the API exposes no delete/move endpoint at all
    paths = {r.path for r in web.app.routes}
    assert not any("delete" in p and "delete-plans" not in p for p in paths), paths
    assert not any(p.endswith("/files/{path}") or "/move" in p or "/rename" in p for p in paths)

# ---------------------------------------------------------------------------
# UAT 2026-11-20: pausing a scan that had just finished froze the progress bar
# forever (status stayed "running" with no worker thread)
# ---------------------------------------------------------------------------
def _insert_run(db, status: str, finished_at: str | None, phase: str = "done") -> int:
    db.execute(
        "INSERT INTO scan_runs(plan_id, status, phase, started_at, finished_at, stats_json) "
        "VALUES (NULL, ?, ?, ?, ?, '{}')",
        (status, phase, now_iso(), finished_at),
    )
    db.commit()
    return int(db.query_one("SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1")["id"])


def test_finished_run_rejects_pause_resume_cancel(client, db):
    csrf = login(client)
    headers = {CSRF_HEADER: csrf}
    run_id = _insert_run(db, "completed", now_iso())
    for action in ("pause", "resume", "cancel"):
        resp = client.post(f"/api/v1/scans/{run_id}/{action}", headers=headers)
        assert resp.status_code == 409, (action, resp.text)
        assert resp.json()["error"]["code"] == "SCAN_FINISHED"
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    assert row["status"] == "completed", "a late click must never revive a finished run"


def test_reconcile_completes_stuck_finished_run(db):
    # Real shape of run #4 on the NAS: the work finished and finished_at was
    # recorded, but a pause/resume race left status="running".
    run_id = _insert_run(db, "running", "2026-11-20T23:08:38+0800")
    engine = Scanner(db)
    assert engine.reconcile_orphans() == 1
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    assert row["status"] == "completed"
    assert row["phase"] == "done"
    assert row["finished_at"] == "2026-11-20T23:08:38+0800"
    assert engine.reconcile_orphans() == 0, "reconciling twice must be a no-op"


def test_reconcile_cancels_orphan_paused_run(db):
    run_id = _insert_run(db, "paused", None, phase="walk")
    engine = Scanner(db)
    assert engine.reconcile_orphans() == 1
    row = db.query_one("SELECT * FROM scan_runs WHERE id=?", (run_id,))
    assert row["status"] == "cancelled"
    assert "重启" in (row["incomplete_reason"] or "")
    assert row["finished_at"]


def test_start_reconciles_orphans_before_new_scan(db, root):
    add_root(db, root)
    build_tree(root)
    stale = _insert_run(db, "running", None, phase="hash")
    engine = Scanner(db)
    try:
        new_id = engine.start(None)
        engine._thread.join(60)
    finally:
        engine._thread = None
    old = db.query_one("SELECT * FROM scan_runs WHERE id=?", (stale,))
    assert old["status"] == "cancelled"
    new = db.query_one("SELECT * FROM scan_runs WHERE id=?", (new_id,))
    assert new["status"] == "completed"



def test_tree_endpoint_rejects_unknown_root(client):
    login(client)
    assert client.get("/api/v1/roots/tree", params={"root_id": 999}).status_code == 404


def test_health_endpoint_is_public(client):
    resp = client.get("/api/v1/system/version")
    assert resp.status_code == 200
    assert resp.json()["name"] == "dupe-checker"


# ---------------------------------------------------------------------------
# Human-facing pages: the review detail page used to 500 on a template typo
# ({{$loop.index}}), so every page is now rendered in the test suite.
# ---------------------------------------------------------------------------
def _prepared_scan(client, db, root):
    add_root(db, root)
    build_tree(root)
    run_scan(db)
    return login(client)


def _groups(client, kind="content", status="pending"):
    resp = client.get("/api/v1/review/groups", params={"kind": kind, "status": status})
    assert resp.status_code == 200, resp.text
    return resp.json()["items"]


def test_all_pages_render_after_scan(client, db, root):
    _prepared_scan(client, db, root)
    for path in ("/", "/roots", "/plans", "/scans", "/review",
                 "/delete-plans", "/settings", "/notifications"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path}: {resp.status_code} {resp.text[:400]}"
    index = client.get("/").text
    assert "开始使用" in index
    # 迭代 7 UI 改版：纵向侧边栏 + KPI 卡片 + 建议卡
    assert 'class="sidebar"' in index
    assert "kpi-grid" in index
    assert "优化建议" in index
    assert "怎么用" in client.get("/delete-plans").text


def test_review_detail_content_group_renders(client, db, root):
    _prepared_scan(client, db, root)
    group = _groups(client)[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    assert detail["same_content"] is True
    assert detail["suggested_keep"] == detail["items"][0]["id"]

    page = client.get(f"/review/{group['id']}")
    assert page.status_code == 200
    assert "内容重复" in page.text
    assert "保留这一份" in page.text
    assert "采用建议" in page.text


def test_review_detail_name_group_warns_about_different_content(client, db, root):
    _prepared_scan(client, db, root)
    group = _groups(client, kind="name")[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    assert detail["same_content"] is False
    page = client.get(f"/review/{group['id']}")
    assert page.status_code == 200
    assert "同名候选（请谨慎）" in page.text


def test_delete_plan_pages_render(client, db, root):
    csrf = _prepared_scan(client, db, root)
    group = _groups(client)[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    keep, delete = detail["items"][0], detail["items"][1]
    saved = client.put(
        f"/api/v1/review/groups/{group['id']}",
        json={"items": [{"item_id": keep["id"], "decision": "keep"},
                        {"item_id": delete["id"], "decision": "delete"}]},
        headers={CSRF_HEADER: csrf},
    )
    assert saved.status_code == 200
    made = client.post("/api/v1/delete-plans", json={"note": "ui"}, headers={CSRF_HEADER: csrf})
    assert made.status_code == 200, made.text
    plan_id = made.json()["id"]

    listing = client.get("/delete-plans")
    assert listing.status_code == 200 and f"/delete-plans/{plan_id}" in listing.text

    page = client.get(f"/delete-plans/{plan_id}")
    assert page.status_code == 200
    assert "待删除文件" in page.text
    assert "下载 CSV" in page.text
    assert "rm -rf" not in page.text and "unlink(" not in page.text


def test_needs_review_plan_page_hides_export(client, db, root):
    csrf = _prepared_scan(client, db, root)
    group = _groups(client)[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    keep, delete = detail["items"][0], detail["items"][1]
    saved = client.put(
        f"/api/v1/review/groups/{group['id']}",
        json={"items": [{"item_id": keep["id"], "decision": "keep"},
                        {"item_id": delete["id"], "decision": "delete"}]},
        headers={CSRF_HEADER: csrf},
    )
    assert saved.status_code == 200
    # touch the file after review: the plan must flag it and forbid export
    with open(delete["path"], "ab") as fh:
        fh.write(b"changed-after-review")

    made = client.post("/api/v1/delete-plans", json={"note": "ui"}, headers={CSRF_HEADER: csrf})
    assert made.status_code == 200, made.text
    assert made.json()["status"] == "needs_review"
    plan_id = made.json()["id"]

    page = client.get(f"/delete-plans/{plan_id}")
    assert page.status_code == 200
    assert "这份清单不能导出" in page.text
    assert f"/api/v1/delete-plans/{plan_id}/export?format=csv" not in page.text


# ---------------------------------------------------------------------------
# Plan-level recheck + stale-file hints (UAT: files change between review and
# manual deletion, review pages must say so).
# ---------------------------------------------------------------------------
def _approved_plan_via_api(client, db, root, note="recheck"):
    csrf = _prepared_scan(client, db, root)
    group = _groups(client)[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    keep, delete = detail["items"][0], detail["items"][1]
    saved = client.put(
        f"/api/v1/review/groups/{group['id']}",
        json={"items": [{"item_id": keep["id"], "decision": "keep"},
                        {"item_id": delete["id"], "decision": "delete"}]},
        headers={CSRF_HEADER: csrf},
    )
    assert saved.status_code == 200
    made = client.post("/api/v1/delete-plans", json={"note": note}, headers={CSRF_HEADER: csrf})
    assert made.status_code == 200, made.text
    return csrf, made.json()["id"], delete["path"]


def test_plan_recheck_endpoint_flags_missing_file(client, db, root):
    csrf, plan_id, delete_path = _approved_plan_via_api(client, db, root)
    assert "重新校验所有文件" in client.get(f"/delete-plans/{plan_id}").text

    os.unlink(delete_path)
    resp = client.post(
        f"/api/v1/delete-plans/{plan_id}/recheck", json={}, headers={CSRF_HEADER: csrf}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "needs_review"
    assert body["counts"]["missing"] == 1
    assert "这份清单不能导出" in client.get(f"/delete-plans/{plan_id}").text


def test_plan_recheck_requires_auth(client):
    assert client.post("/api/v1/delete-plans/1/recheck", json={}).status_code == 401


def test_review_detail_page_warns_when_file_missing(client, db, root):
    _prepared_scan(client, db, root)
    group = _groups(client)[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    os.unlink(detail["items"][0]["path"])
    page = client.get(f"/review/{group['id']}")
    assert page.status_code == 200
    assert "索引与磁盘不一致" in page.text
    assert "文件已不存在" in page.text

# ---------------------------------------------------------------------------
# 迭代 8: AUTH_MODE=none (trusted LAN, read-only deployment)
# ---------------------------------------------------------------------------
def _csrf_from_page(html: str) -> str:
    marker = '<meta name="csrf" content="'
    start = html.index(marker) + len(marker)
    return html[start:html.index('"', start)]


def test_auth_disabled_opens_pages_without_password(web, monkeypatch):
    monkeypatch.setattr(web.config, "auth_mode", "none")
    client = TestClient(web.app)
    home = client.get("/")
    assert home.status_code == 200
    assert "免登录模式" in home.text
    assert 'onclick="doLogout()"' not in home.text
    # A CSRF-protected session is still issued on the first page load.
    assert SESSION_COOKIE in client.cookies
    settings = client.get("/settings")
    assert settings.status_code == 200
    assert "已关闭口令登录" in settings.text
    assert 'id="pwd-form"' not in settings.text


def test_auth_disabled_redirects_auth_pages_and_endpoints(web, monkeypatch):
    monkeypatch.setattr(web.config, "auth_mode", "none")
    client = TestClient(web.app)
    setup = client.get("/setup", follow_redirects=False)
    assert setup.status_code == 303 and setup.headers["location"] == "/"
    login_page = client.get("/login", follow_redirects=False)
    assert login_page.status_code == 303 and login_page.headers["location"] == "/"
    login_api = client.post("/api/v1/auth/login", json={"password": "whatever-123"})
    assert login_api.status_code == 403
    assert login_api.json()["error"]["code"] == "AUTH_DISABLED"
    setup_api = client.post("/api/v1/auth/setup", json={"password": "whatever-123", "token": "x"})
    assert setup_api.status_code == 403
    assert setup_api.json()["error"]["code"] == "AUTH_DISABLED"


def test_auth_disabled_still_requires_session_and_csrf(web, monkeypatch):
    monkeypatch.setattr(web.config, "auth_mode", "none")
    client = TestClient(web.app)
    # No page loaded yet -> no session cookie -> API refuses instead of trusting.
    assert client.post("/api/v1/scans", json={"plan_id": 1}).status_code == 401
    csrf = _csrf_from_page(client.get("/").text)
    body = {"default_keep_policy": "earliest_mtime"}
    forged = client.put("/api/v1/settings", json=body)
    assert forged.status_code == 403
    ok = client.put("/api/v1/settings", json=body, headers={CSRF_HEADER: csrf})
    assert ok.status_code == 200


def test_roots_and_plans_pages_use_compact_layout(client, db, root):
    _prepared_scan(client, db, root)
    roots_html = client.get("/roots").text
    assert 'class="root-row"' in roots_html
    assert "kpi-inline" in roots_html
    assert "查看顶层内容" in roots_html
    plans_html = client.get("/plans").text
    assert 'class="picker-item"' in plans_html
    assert 'id="root-count"' in plans_html
    assert "全选" in plans_html and "全不选" in plans_html

# ---------------------------------------------------------------------------
# QA DEF-01..DEF-07 / DEF-11 / DEF-12 regression: release hardening
# ---------------------------------------------------------------------------
INT_MAX = 2**63 - 1
HUGE_ID = 10**30


def _raw_headers(csrf: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers[CSRF_HEADER] = csrf
    return headers


@pytest.mark.parametrize("raw", ["not-json", "[]", '"text"', "null", "1", "true"])
def test_malformed_login_body_is_a_client_error(client, raw):
    """DEF-01: malformed JSON bodies used to escape as HTTP 500."""
    resp = client.post("/api/v1/auth/login", content=raw, headers=_raw_headers())
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_login_empty_and_wrongly_typed_password_are_client_errors(client):
    empty = client.post("/api/v1/auth/login", content="", headers=_raw_headers())
    assert empty.status_code == 400
    assert empty.json()["error"]["code"] == "VALIDATION_ERROR"
    odd = client.post("/api/v1/auth/login", json={"password": []})
    assert odd.status_code == 400
    assert odd.json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.get("/api/v1/plans").status_code == 401


def test_setup_malformed_body_is_a_client_error(client, db):
    resp = client.post("/api/v1/auth/setup", content="{broken", headers=_raw_headers())
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"
    assert db.get_setting("password_hash") is None


@pytest.mark.parametrize("raw", ["{broken", "[]", '"text"', "null"])
def test_malformed_authenticated_bodies_are_client_errors(client, raw):
    """DEF-01/DEF-02: plan create, review save, settings and password change."""
    csrf = login(client)
    headers = _raw_headers(csrf)
    plan = client.post("/api/v1/plans", content=raw, headers=headers)
    assert plan.status_code == 400, plan.text
    assert plan.json()["error"]["code"] == "VALIDATION_ERROR"
    settings = client.put("/api/v1/settings", content=raw, headers=headers)
    assert settings.status_code == 400, settings.text
    assert settings.json()["error"]["code"] == "VALIDATION_ERROR"
    password = client.post("/api/v1/settings/password", content=raw, headers=headers)
    assert password.status_code == 400, password.text
    assert password.json()["error"]["code"] == "VALIDATION_ERROR"
    group = client.put("/api/v1/review/groups/1", content=raw, headers=headers)
    assert group.status_code == 400, group.text
    assert group.json()["error"]["code"] == "VALIDATION_ERROR"


def test_plan_body_fields_are_validated(client, db, root):
    csrf = login(client)
    headers = _raw_headers(csrf)
    root_id = add_root(db, root)
    long_name = client.post("/api/v1/plans", json={"name": "x" * 201, "root_ids": [root_id]}, headers=headers)
    assert long_name.status_code == 422
    assert long_name.json()["error"]["code"] == "VALIDATION_ERROR"
    non_list = client.post("/api/v1/plans", json={"name": "p", "root_ids": "1"}, headers=headers)
    assert non_list.status_code == 422
    bad_id = client.post("/api/v1/plans", json={"name": "p", "root_ids": [HUGE_ID]}, headers=headers)
    assert bad_id.status_code == 422
    bad_rate = client.post(
        "/api/v1/plans", json={"name": "p", "root_ids": [root_id], "rate_meta": "fast"}, headers=headers
    )
    assert bad_rate.status_code == 422
    assert not db.query("SELECT id FROM scan_plans")


def test_body_larger_than_one_mib_is_rejected(client):
    """DEF-04: the 1 MiB request body cap is enforced before JSON parsing."""
    csrf = login(client)
    resp = client.post(
        "/api/v1/plans", content=b"x" * (1024 * 1024 + 1), headers=_raw_headers(csrf)
    )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_scan_start_rejects_wrongly_typed_plan_id(client):
    csrf = login(client)
    resp = client.post("/api/v1/scans", json={"plan_id": "1"}, headers=_raw_headers(csrf))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_notifications_read_validates_body(client):
    csrf = login(client)
    headers = _raw_headers(csrf)
    malformed = client.post("/api/v1/notifications/read", content="not-json", headers=headers)
    assert malformed.status_code == 400
    bad = client.post("/api/v1/notifications/read", json={"all": "yes"}, headers=headers)
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize("bad", [
    {"rate_meta": "abc"},
    {"rate_meta": -5},
    {"rate_meta": 99999},
    {"rate_meta": True},
    {"rate_hash": 0},
    {"rate_hash": 1001},
    {"default_keep_policy": "bogus"},
    {"notify_in_app": "yes"},
    {"unknown_key": 1},
])
def test_settings_reject_out_of_contract_values(client, db, bad):
    """DEF-05: settings are whitelisted, range checked and never silently stored."""
    csrf = login(client)
    before = {key: db.get_setting(key) for key in bad}
    resp = client.put("/api/v1/settings", json=bad, headers=_raw_headers(csrf))
    assert resp.status_code == 422, resp.text
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"
    assert {key: db.get_setting(key) for key in bad} == before


def test_settings_valid_update_persists(client, db):
    csrf = login(client)
    resp = client.put(
        "/api/v1/settings",
        json={"default_keep_policy": "longest_path", "rate_meta": 500,
              "rate_hash": 100, "notify_in_app": True},
        headers=_raw_headers(csrf),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert db.get_setting("default_keep_policy") == "longest_path"
    assert db.get_setting("rate_meta") == "500"
    assert db.get_setting("rate_hash") == "100"
    assert db.get_setting("notify_in_app") == "1"


def test_password_change_rejects_short_new_password(client):
    csrf = login(client)
    resp = client.post(
        "/api/v1/settings/password",
        json={"old_password": PASSWORD, "new_password": "short"},
        headers=_raw_headers(csrf),
    )
    assert resp.status_code == 400
    assert "新口令" in resp.json()["error"]["message"]


def test_review_save_rejects_bad_policy_and_item_fields(client, db, root):
    csrf = _prepared_scan(client, db, root)
    group = _groups(client)[0]
    headers = _raw_headers(csrf)
    keep_id = client.get(f"/api/v1/review/groups/{group['id']}").json()["items"][0]["id"]
    bad_policy = client.put(f"/api/v1/review/groups/{group['id']}", json={"policy": "bogus"}, headers=headers)
    assert bad_policy.status_code == 422
    huge_item = client.put(
        f"/api/v1/review/groups/{group['id']}",
        json={"items": [{"item_id": HUGE_ID, "decision": "keep"}]},
        headers=headers,
    )
    assert huge_item.status_code == 422
    bad_decision = client.put(
        f"/api/v1/review/groups/{group['id']}",
        json={"items": [{"item_id": keep_id, "decision": 1}]},
        headers=headers,
    )
    assert bad_decision.status_code == 422
    bad_items = client.put(f"/api/v1/review/groups/{group['id']}", json={"items": "nope"}, headers=headers)
    assert bad_items.status_code == 400


def test_delete_plan_note_length_is_capped(client, db, root):
    csrf = _prepared_scan(client, db, root)
    resp = client.post("/api/v1/delete-plans", json={"note": "n" * 2001}, headers=_raw_headers(csrf))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_plan_update_validates_body(client, db, root):
    csrf = login(client)
    headers = _raw_headers(csrf)
    root_id = add_root(db, root)
    made = client.post("/api/v1/plans", json={"name": "patch-me", "root_ids": [root_id]}, headers=headers)
    assert made.status_code == 201, made.text
    plan_id = made.json()["id"]
    malformed = client.patch(f"/api/v1/plans/{plan_id}", content="not-json", headers=headers)
    assert malformed.status_code == 400
    bad_trigger = client.patch(f"/api/v1/plans/{plan_id}", json={"trigger_type": "minutely"}, headers=headers)
    assert bad_trigger.status_code == 400
    long_name = client.patch(f"/api/v1/plans/{plan_id}", json={"name": "n" * 201}, headers=headers)
    assert long_name.status_code == 422
    ok = client.patch(f"/api/v1/plans/{plan_id}", json={"enabled": True}, headers=headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["enabled"] is True


@pytest.mark.parametrize("method,path", [
    ("get", "/api/v1/review/groups/{id}"),
    ("get", "/api/v1/scans/{id}"),
    ("post", "/api/v1/scans/{id}/pause"),
    ("get", "/api/v1/delete-plans/{id}"),
    ("post", "/api/v1/delete-plans/{id}/recheck"),
    ("get", "/api/v1/delete-plans/{id}/export"),
    ("patch", "/api/v1/plans/{id}"),
    ("delete", "/api/v1/plans/{id}"),
])
@pytest.mark.parametrize("bad_id", [HUGE_ID, -1])
def test_out_of_range_path_ids_are_not_500(client, method, path, bad_id):
    """DEF-03: sqlite3 cannot bind ids outside signed 64 bit; never 500."""
    csrf = login(client)
    kwargs = {"headers": _raw_headers(csrf)}
    if method in ("post", "patch"):
        kwargs["json"] = {}
    resp = client.request(method, path.format(id=bad_id), **kwargs)
    assert resp.status_code in (404, 422), (method, path, resp.status_code, resp.text)
    assert resp.json()["error"]["code"] in ("NOT_FOUND", "VALIDATION_ERROR")


@pytest.mark.parametrize("params", [
    {"cursor": HUGE_ID}, {"cursor": -1}, {"min_size": HUGE_ID}, {"min_size": -5},
])
def test_review_groups_rejects_out_of_range_query_ints(client, params):
    login(client)
    resp = client.get("/api/v1/review/groups", params=params)
    assert resp.status_code == 422, resp.text
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_tree_endpoint_rejects_out_of_range_root_id(client):
    login(client)
    resp = client.get("/api/v1/roots/tree", params={"root_id": HUGE_ID})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "NOT_FOUND"


def test_scans_limit_is_clamped(client, db):
    """DEF-11: limit below 1 used to mean 'no limit' in SQLite."""
    login(client)
    for _ in range(3):
        _insert_run(db, "completed", now_iso())

    def items(params):
        return client.get("/api/v1/scans", params=params).json()["items"]

    assert len(items({"limit": -3})) == 1
    assert len(items({"limit": 0})) == 1
    assert len(items({"limit": 999})) == 3


def test_security_headers_are_added_to_every_response(client):
    """DEF-06: CSP / nosniff / frame denial / referrer policy."""
    login(client)
    for path in ("/health", "/api/v1/system/version", "/", "/settings"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        csp = resp.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "img-src 'self' data:" in csp
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "no-referrer"
    err = client.get("/api/v1/review/groups/999999")
    assert err.status_code == 404
    assert err.headers["x-content-type-options"] == "nosniff"


def test_health_is_minimal_and_path_free(client, db):
    """DEF-07: anonymous health must not leak filesystem paths."""
    csrf = login(client)
    assert csrf
    report = GuardReport(
        verified_at=now_iso(),
        roots=[RootCheck(path="/secret/path/do-not-leak", exists=True, is_dir=True,
                         readable=True, readonly=False, error="目录可写")],
    )
    guard_mod.apply_report(report, db)
    try:
        health = client.get("/health")
        assert health.status_code == 200
        body = health.json()
        assert body["status"] == "fatal"
        assert body["guard_passed"] is False
        assert body["version"] == config.version
        assert "guard" not in body
        assert "/secret" not in health.text

        system = client.get("/api/v1/system/health")
        assert system.status_code == 200
        assert "/secret" not in system.text
        assert system.json()["guard"] == {
            "passed": False, "unsafe": True, "roots_total": 1, "roots_passed": 0,
        }

        # the authenticated report still carries full detail for the operator
        full = client.get("/api/v1/system/guard")
        assert full.status_code == 200
        assert "/secret/path/do-not-leak" in full.text
    finally:
        guard_mod.reset_state()


def test_dead_path_validator_is_removed(web):
    """DEF-12: _validate_path/_root_paths were unreachable dead code."""
    assert not hasattr(web, "_validate_path")
    assert not hasattr(web, "_root_paths")
    with open(web.__file__, encoding="utf-8") as fh:
        source = fh.read()
    assert "_validate_path" not in source
    assert "_root_paths" not in source



# ---------------------------------------------------------------------------
# QA functional defects: DEF-02 / DEF-05 / DEF-06 / DEF-07 / DEF-09
# ---------------------------------------------------------------------------
def test_plan_test_globs_preview_is_read_only_and_csrf_guarded(client, db, root):
    """DEF-02: read-only glob preview, no plan/index mutation, CSRF required."""
    csrf = _prepared_scan(client, db, root)
    root_id = db.query_one("SELECT id FROM scan_roots")["id"]
    plan = client.post(
        "/api/v1/plans",
        json={"name": "preview-me", "root_ids": [root_id]},
        headers=_raw_headers(csrf),
    )
    assert plan.status_code == 201, plan.text
    plan_id = plan.json()["id"]
    plans_before = [row["id"] for row in db.query("SELECT id FROM scan_plans ORDER BY id")]
    files_before = db.query_one("SELECT COUNT(*) AS n FROM files")["n"]

    resp = client.post(
        f"/api/v1/plans/{plan_id}/test-globs",
        json={"include_globs": "*", "exclude_globs": "*.tmp"},
        headers=_raw_headers(csrf),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["plan_id"] == plan_id
    assert data["include_globs"] == ["*"]
    assert data["excluded"] == 0
    assert data["included"] == 5  # a/dup.txt, b/dup_copy.txt, c/unique.txt, 2x same_name.txt
    assert data["total"] == 8  # + the three directories
    paths = {item["path"] for item in data["matched"]}
    assert str(root / "a" / "dup.txt") in paths

    # nothing was written: same plans, same file index, root untouched
    assert [row["id"] for row in db.query("SELECT id FROM scan_plans ORDER BY id")] == plans_before
    assert db.query_one("SELECT COUNT(*) AS n FROM files")["n"] == files_before
    assert not list(root.rglob(".dupe_write_probe_*"))

    # CSRF is enforced on this POST, and an unknown plan is a 404
    assert client.post(f"/api/v1/plans/{plan_id}/test-globs", json={}).status_code == 403
    missing = client.post(
        "/api/v1/plans/999999/test-globs", json={}, headers=_raw_headers(csrf)
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"


def test_plan_response_exposes_globs_array_view(client, db, root):
    """DEF-09: GET /plans keeps the string fields and adds parsed arrays."""
    csrf = _prepared_scan(client, db, root)
    root_id = db.query_one("SELECT id FROM scan_roots")["id"]
    created = client.post(
        "/api/v1/plans",
        json={
            "name": "globs",
            "root_ids": [root_id],
            "include_globs": "*.jpg,*.png",
            "exclude_globs": "@eaDir/**",
        },
        headers=_raw_headers(csrf),
    )
    assert created.status_code == 201
    body = created.json()
    assert body["include_globs"] == "*.jpg,*.png"
    assert body["globs"] == {"include": ["*.jpg", "*.png"], "exclude": ["@eaDir/**"]}

    listed = client.get("/api/v1/plans").json()["items"]
    assert listed[0]["globs"]["include"] == ["*.jpg", "*.png"]


def test_tree_endpoint_has_path_and_has_children(client, db, root):
    """DEF-09: one-level tree entries carry path and a drill-down hint."""
    csrf = _prepared_scan(client, db, root)
    root_id = db.query_one("SELECT id FROM scan_roots")["id"]
    data = client.get(
        "/api/v1/roots/tree", params={"root_id": root_id}, headers=_raw_headers(csrf)
    ).json()
    by_name = {item["name"]: item for item in data["items"]}
    assert set(by_name) == {"a", "b", "c"}
    for name in ("a", "b", "c"):
        entry = by_name[name]
        assert entry["is_dir"] is True
        assert entry["has_children"] is True
        assert entry["path"] == str(root / name)


def test_review_detail_page_warns_about_hardlinks(client, db, root):
    """DEF-05: nlink > 1 is shown with the frees-no-space warning."""
    _prepared_scan(client, db, root)
    group = _groups(client)[0]
    detail = client.get(f"/api/v1/review/groups/{group['id']}").json()
    target = detail["items"][0]["path"]
    os.link(target, os.path.join(os.path.dirname(target), "hardlink-copy.txt"))

    refreshed = client.get(f"/api/v1/review/groups/{group['id']}").json()
    linked = next(item for item in refreshed["items"] if item["path"] == target)
    assert linked["nlink"] == 2, "hard link count must be exposed"
    for item in refreshed["items"]:
        assert item["dir"] == os.path.dirname(item["path"])

    page = client.get(f"/review/{group['id']}")
    assert page.status_code == 200
    assert "硬链接" in page.text
    assert "所属目录" in page.text
    assert "不会释放空间" in page.text or "不释放空间" in page.text


def test_logs_listing_tail_and_download(client, monkeypatch, tmp_path):
    """DEF-06: whitelisted log files can be listed, tailed and downloaded."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "app.log").write_text("first line\nsecond line\n", encoding="utf-8")
    (log_dir / "unrelated.txt").write_text("must not be listed", encoding="utf-8")
    monkeypatch.setattr(config, "log_dir", log_dir)
    login(client)

    resp = client.get("/api/v1/system/logs", params={"limit": 200})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["name"] == "app.log"
    assert data["lines"][-2:] == ["first line", "second line"]
    assert [item["name"] for item in data["files"]] == ["app.log"]

    download = client.get("/api/v1/system/logs/download", params={"name": "app.log"})
    assert download.status_code == 200
    assert download.text == "first line\nsecond line\n"
    assert "attachment" in download.headers["content-disposition"]

    settings_page = client.get("/settings")
    assert settings_page.status_code == 200
    assert "运行日志" in settings_page.text
    assert "app.log" in settings_page.text


@pytest.mark.parametrize("name", ["../config.py", "/etc/passwd", "app.log/../config.py", "unrelated.txt", ""])
def test_logs_reject_non_whitelisted_names(client, monkeypatch, tmp_path, name):
    """DEF-06: only exact whitelisted names; traversal can never resolve."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "app.log").write_text("ok\n", encoding="utf-8")
    (tmp_path / "config.py").write_text("secret", encoding="utf-8")
    monkeypatch.setattr(config, "log_dir", log_dir)
    login(client)

    assert client.get("/api/v1/system/logs", params={"name": name}).status_code == 404
    assert client.get("/api/v1/system/logs/download", params={"name": name}).status_code == 404
    # a missing rotation backup is a plain 404 too
    assert client.get(
        "/api/v1/system/logs", params={"name": "app.log.2026-01-01"}
    ).status_code == 404


def test_review_groups_filter_by_dir_and_ext(client, db, root):
    """DEF-07: directory-prefix and extension filters narrow the review list."""
    _prepared_scan(client, db, root)

    def ids(params):
        resp = client.get("/api/v1/review/groups", params={"kind": "content", "status": "", **params})
        assert resp.status_code == 200, resp.text
        return [item["id"] for item in resp.json()["items"]]

    all_ids = ids({})
    assert all_ids, "expected a content group from the scan"
    assert ids({"dir": "a"}) == all_ids
    assert ids({"dir": "b"}) == all_ids  # b/dup_copy.txt is the other member
    assert ids({"dir": "no-such-dir"}) == []
    assert ids({"ext": ".txt"}) == all_ids
    assert ids({"ext": "txt"}) == all_ids  # a leading dot is optional
    assert ids({"ext": ".TXT"}) == all_ids  # case insensitive
    assert ids({"ext": ".png"}) == []
    # escaping: % and _ are literal, not wildcards
    assert ids({"dir": "%"}) == []

    page = client.get("/review", params={"kind": "content", "status": "", "dir": "a", "ext": ".txt"})
    assert page.status_code == 200
    assert "所属目录" in page.text
    filtered = client.get("/review", params={"kind": "content", "status": "", "dir": "no-such-dir"})
    assert filtered.status_code == 200
    assert "没有符合条件的重复组" in filtered.text

