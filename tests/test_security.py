"""Password hashing, sessions, CSRF, login rate limiting and setup tokens."""
import pytest

from app.config import Config, config
from app.security import (
    SETUP_TOKEN_ENV,
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


def test_password_roundtrip(db):
    hashed = hash_password("correct-horse-1234")
    assert hashed.startswith("$2")
    assert verify_password("correct-horse-1234", hashed) is True
    assert verify_password("wrong-password-1234", hashed) is False
    assert verify_password("", hashed) is False


def test_session_roundtrip(db):
    sessions = SessionManager(db)
    token, csrf = sessions.create()
    loaded = sessions.load(token)
    assert loaded is not None
    assert loaded["csrf"] == csrf
    assert sessions.load("garbage") is None
    assert sessions.load(None) is None


def test_session_secret_rotation_invalidates_tokens(db):
    sessions = SessionManager(db)
    token, _ = sessions.create()
    sessions.rotate_secret()
    assert sessions.load(token) is None


def test_session_epoch_revokes_every_issued_cookie(db):
    sessions = SessionManager(db)
    old_token, _ = sessions.create()
    assert sessions.load(old_token) is not None

    new_epoch = sessions.revoke_all()
    assert new_epoch == 1
    assert sessions.load(old_token) is None, "cookie issued before logout must be rejected"

    fresh, _ = sessions.create()
    assert sessions.load(fresh) is not None
    assert sessions.epoch() == 1


def test_session_ttl_configuration():
    assert config.session_ttl_seconds == 8 * 3600, "default TTL must be 8 hours, not 7 days"
    assert config.session_max_age == config.session_ttl_seconds


def test_config_session_env_overrides(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_SECONDS", "900")
    assert Config().session_ttl_seconds == 900
    monkeypatch.delenv("SESSION_TTL_SECONDS")
    monkeypatch.setenv("SESSION_MAX_AGE", "600")
    assert Config().session_ttl_seconds == 600, "legacy SESSION_MAX_AGE is a backwards-compatible alias"

    monkeypatch.setenv("SESSION_COOKIE_SECURE", "always")
    assert Config().session_cookie_secure == "always"
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "never")
    assert Config().session_cookie_secure == "never"
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "bogus")
    assert Config().session_cookie_secure == "auto"


def test_csrf_comparison():
    assert csrf_ok("abc", "abc") is True
    assert csrf_ok("abc", "abd") is False
    assert csrf_ok(None, None) is False
    assert csrf_ok("abc", None) is False


def test_login_rate_limiter_blocks_after_five_failures():
    limiter = LoginRateLimiter(limit=5, window=60)
    for _ in range(5):
        assert limiter.is_blocked("1.2.3.4") is False
        limiter.record_failure("1.2.3.4")
    assert limiter.is_blocked("1.2.3.4") is True
    assert limiter.is_blocked("5.6.7.8") is False
    limiter.reset("1.2.3.4")
    assert limiter.is_blocked("1.2.3.4") is False


# ---------------------------------------------------------------------------
# one-time setup token (P1-01)
# ---------------------------------------------------------------------------
@pytest.fixture()
def clean_setup_token(monkeypatch):
    monkeypatch.delenv(SETUP_TOKEN_ENV, raising=False)
    clear_setup_token()
    yield
    clear_setup_token()


def test_setup_token_file_is_private(clean_setup_token):
    token = ensure_setup_token()
    path = setup_token_path()
    assert path.exists()
    assert len(token) >= 20
    assert (path.stat().st_mode & 0o777) == 0o600
    assert load_setup_token() == token

    clear_setup_token()
    assert not path.exists()


def test_setup_token_env_override(clean_setup_token, monkeypatch):
    monkeypatch.setenv(SETUP_TOKEN_ENV, "env-setup-token-abc")
    assert ensure_setup_token() == "env-setup-token-abc"
    assert load_setup_token() == "env-setup-token-abc"
    assert setup_token_path().read_text(encoding="utf-8") == "env-setup-token-abc"


def test_setup_token_compare_is_constant_time_and_strict():
    assert setup_token_ok("abc", "abc") is True
    assert setup_token_ok("abc", "abd") is False
    assert setup_token_ok(None, "abc") is False
    assert setup_token_ok("abc", None) is False
    assert setup_token_ok("", "") is False
