"""Authentication primitives: password hashing, signed sessions, CSRF, rate limit."""
from __future__ import annotations

import hmac
import secrets
import time

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import config
from .db import Database

SESSION_COOKIE = "dupe_session"
CSRF_HEADER = "X-CSRF-Token"


def hash_password(plain: str) -> str:
    if len(plain) < 10:
        raise ValueError("口令至少 10 位")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


class SessionManager:
    """Stateless signed cookies; the secret lives in settings (DB)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def _secret(self) -> str:
        secret = self.db.get_setting("session_secret")
        if not secret:
            secret = secrets.token_urlsafe(48)
            self.db.set_setting("session_secret", secret)
        return secret

    def _serializer(self) -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(self._secret(), salt="dupe-session")

    def create(self) -> tuple[str, str]:
        """Return (cookie_value, csrf_token)."""
        csrf = secrets.token_urlsafe(24)
        token = self._serializer().dumps({"csrf": csrf, "v": 1})
        return token, csrf

    def load(self, token: str | None) -> dict | None:
        if not token:
            return None
        try:
            return self._serializer().loads(token, max_age=config.session_max_age)
        except (BadSignature, SignatureExpired):
            return None

    def rotate_secret(self) -> None:
        self.db.set_setting("session_secret", secrets.token_urlsafe(48))


class LoginRateLimiter:
    """In-memory sliding window: N failures per window per client IP."""

    def __init__(self, limit: int | None = None, window: int | None = None) -> None:
        self.limit = limit if limit is not None else config.login_rate_limit
        self.window = window if window is not None else config.login_rate_window
        self._hits: dict[str, list[float]] = {}

    def is_blocked(self, key: str) -> bool:
        now = time.time()
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        self._hits[key] = hits
        return len(hits) >= self.limit

    def record_failure(self, key: str) -> None:
        self._hits.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


def csrf_ok(expected: str | None, provided: str | None) -> bool:
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)
