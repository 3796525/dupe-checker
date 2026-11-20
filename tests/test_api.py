"""HTTP API: auth, CSRF, and the read-only review workflow end to end."""
import importlib

import pytest
from fastapi.testclient import TestClient

from app.guard import GuardReport
from app.scanner import Scanner
from app.security import LoginRateLimiter, SessionManager
from helpers import add_root, build_tree

PASSWORD = "test-password-123"


@pytest.fixture()
def web(db, monkeypatch):
    module = importlib.import_module("app.web")
    monkeypatch.setattr(module, "db", db)
    monkeypatch.setattr(module, "sessions", SessionManager(db))
    monkeypatch.setattr(module, "limiter", LoginRateLimiter())
    monkeypatch.setattr(module, "scan_engine", Scanner(db))
    monkeypatch.setattr(module, "guard_report", GuardReport())
    return module


@pytest.fixture()
def client(web):
    return TestClient(web.app)


def login(client) -> str:
    resp = client.post("/api/v1/auth/setup", json={"password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return resp.json()["csrf_token"]


def test_requires_auth(client):
    assert client.get("/api/v1/plans").status_code == 401
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"] == "/setup"


def test_short_password_rejected(client):
    assert client.post("/api/v1/auth/setup", json={"password": "short"}).status_code == 400


def test_setup_then_csrf_is_enforced(client):
    csrf = login(client)
    assert client.post("/api/v1/auth/setup", json={"password": PASSWORD}).status_code == 403
    assert client.get("/api/v1/plans").status_code == 200

    # a state-changing call without the header is refused
    assert client.post("/api/v1/plans", json={"name": "x"}).status_code == 403
    ok = client.post(
        "/api/v1/plans",
        json={"name": "夜间扫描", "root_ids": [1], "trigger_type": "manual"},
        headers={"X-CSRF-Token": csrf},
    )
    # root id 1 does not exist here, but validation happens after roots lookup: either 200 or 400 is fine,
    # what matters is that CSRF is accepted and the request reaches the handler.
    assert ok.status_code in (200, 400)
    assert ok.status_code != 403


def test_wrong_password_and_rate_limit(client, web):
    login(client)
    client.post("/api/v1/auth/logout")
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


def test_full_read_only_workflow(client, web, db, root):
    csrf = login(client)
    headers = {"X-CSRF-Token": csrf}
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
