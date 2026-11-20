"""HTTP API: auth/session hardening, guard gating and the read-only review workflow."""
import importlib

import pytest
from fastapi.testclient import TestClient

from app import guard as guard_mod
from app.config import config
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
    # root id 1 does not exist here, but validation happens after roots lookup: either 200 or 400 is fine,
    # what matters is that CSRF is accepted and the request reaches the handler.
    assert ok.status_code in (200, 400)
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
    assert plan.status_code == 200, plan.text
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
    assert "开始使用" in client.get("/").text
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
