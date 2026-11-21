"""Runtime configuration from environment (12-factor style)."""
from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


class Config:
    """All paths are inside the container; mounts are read-only by design."""

    def __init__(self) -> None:
        self.data_dir = Path(_env("DATA_DIR", "/data"))
        self.db_path = Path(_env("DB_PATH", str(self.data_dir / "db" / "dupe.db")))
        self.export_dir = Path(_env("EXPORT_DIR", str(self.data_dir / "exports")))
        self.log_dir = Path(_env("LOG_DIR", str(self.data_dir / "logs")))
        self.host = _env("HOST", "0.0.0.0")
        self.port = int(_env("PORT", "8080"))
        self.timezone = _env("TZ", "Asia/Shanghai")
        # MOUNT_ROOTS: colon/comma separated read-only mount points
        raw = _env("MOUNT_ROOTS", "")
        self.mount_roots = [p for p in raw.replace(",", ":").split(":") if p.strip()]
        # Session lifetime (P1-04): 8h default instead of the old 7 days.
        # SESSION_MAX_AGE is kept as a backwards-compatible alias.
        legacy_max_age = _env("SESSION_MAX_AGE", "")
        self.session_ttl_seconds = int(
            _env("SESSION_TTL_SECONDS", legacy_max_age or str(8 * 3600))
        )
        # Kept for callers that still read the old name.
        self.session_max_age = self.session_ttl_seconds
        # auto / always / never (P1-04). "auto" adds Secure when the request is
        # HTTPS (directly or through a TLS reverse proxy).
        secure_mode = _env("SESSION_COOKIE_SECURE", "auto").lower()
        self.session_cookie_secure = secure_mode if secure_mode in ("auto", "always", "never") else "auto"
        # AUTH_MODE=password (default) requires a login password.  "none" is
        # for a trusted LAN-only deployment of this read-only tool: pages open
        # without a password, but a CSRF-protected session is still created so
        # state-changing API calls cannot be forged by other websites.
        auth_mode = _env("AUTH_MODE", "password").lower()
        self.auth_mode = auth_mode if auth_mode in ("password", "none") else "password"
        self.login_rate_limit = int(_env("LOGIN_RATE_LIMIT", "5"))
        self.login_rate_window = int(_env("LOGIN_RATE_WINDOW", "60"))
        # Guard deep check (P1-05): per-root nested sampling + periodic recheck.
        self.guard_interval_seconds = max(60, int(_env("GUARD_INTERVAL_SECONDS", "1800")))
        self.guard_sample_limit = max(0, int(_env("GUARD_SAMPLE_LIMIT", "20")))
        self.guard_max_depth = max(1, int(_env("GUARD_MAX_DEPTH", "3")))
        self.version = "0.1.7"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.db_path.parent, self.export_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)


config = Config()
