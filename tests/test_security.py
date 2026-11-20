"""Password hashing, sessions, CSRF and login rate limiting."""
import time

from app.security import (
    LoginRateLimiter,
    SessionManager,
    csrf_ok,
    hash_password,
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
