"""Authentication primitives: password hashing, signed sessions, CSRF, rate limit."""
from __future__ import annotations

import hmac
import logging
import os
import secrets
import time
from pathlib import Path

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import config
from .db import Database

log = logging.getLogger("dupe.security")

SESSION_COOKIE = "dupe_session"
CSRF_HEADER = "X-CSRF-Token"
SETUP_TOKEN_ENV = "DUPE_SETUP_TOKEN"
SETUP_TOKEN_FILENAME = "setup_token"


def hash_password(plain: str) -> str:
    if len(plain) < 10:
        raise ValueError("口令至少 10 位")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# One-time setup token (P1-01)
# ---------------------------------------------------------------------------
def setup_token_path() -> Path:
    return config.data_dir / SETUP_TOKEN_FILENAME


def _read_setup_token_file() -> str | None:
    try:
        token = setup_token_path().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def _write_setup_token_file(token: str) -> None:
    path = setup_token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - chmod can only fail on exotic mounts
        log.warning("无法将 setup token 文件权限设为 0600: %s", path)


def ensure_setup_token() -> str:
    """Return the active setup token, creating a 0600 file when needed.

    DUPE_SETUP_TOKEN takes precedence (useful for automation/deployments);
    it is also mirrored to the file so a single code path can load it.
    """
    env_token = os.environ.get(SETUP_TOKEN_ENV, "").strip()
    if env_token:
        try:
            _write_setup_token_file(env_token)
        except OSError as exc:  # pragma: no cover - DATA_DIR should be writable
            log.warning("无法写入 setup token 文件: %s", exc)
        return env_token
    existing = _read_setup_token_file()
    if existing:
        return existing
    token = secrets.token_urlsafe(24)
    _write_setup_token_file(token)
    return token


def load_setup_token() -> str | None:
    env_token = os.environ.get(SETUP_TOKEN_ENV, "").strip()
    if env_token:
        return env_token
    return _read_setup_token_file()


def setup_token_ok(expected: str | None, provided: str | None) -> bool:
    """Constant-time comparison; a missing token never matches."""
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


def clear_setup_token() -> None:
    """Invalidate the one-time token (called right after setup succeeds)."""
    try:
        setup_token_path().unlink()
    except FileNotFoundError:
        return
    except OSError as exc:  # pragma: no cover - keep setup working, log loudly
        log.error("setup token 文件删除失败（令牌已在进程内作废）: %s", exc)


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

    def epoch(self) -> int:
        """Current server-side session epoch (revocation counter)."""
        try:
            return int(self.db.get_setting("session_epoch", "0") or "0")
        except (TypeError, ValueError):
            return 0

    def create(self) -> tuple[str, str]:
        """Return (cookie_value, csrf_token)."""
        csrf = secrets.token_urlsafe(24)
        token = self._serializer().dumps({"csrf": csrf, "v": 1, "epoch": self.epoch()})
        return token, csrf

    def load(self, token: str | None) -> dict | None:
        if not token:
            return None
        try:
            payload = self._serializer().loads(token, max_age=config.session_ttl_seconds)
        except (BadSignature, SignatureExpired):
            return None
        # Server-side revocation (P1-04): logout bumps the epoch, so every
        # cookie issued before it stops being accepted immediately.
        try:
            token_epoch = int(payload.get("epoch", 0))
        except (TypeError, ValueError):
            return None
        if token_epoch != self.epoch():
            return None
        return payload

    def revoke_all(self) -> int:
        """Invalidate all issued cookies; returns the new epoch."""
        new_epoch = self.epoch() + 1
        self.db.set_setting("session_epoch", str(new_epoch))
        return new_epoch

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
