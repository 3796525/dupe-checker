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
        self.session_max_age = int(_env("SESSION_MAX_AGE", str(7 * 24 * 3600)))
        self.login_rate_limit = int(_env("LOGIN_RATE_LIMIT", "5"))
        self.login_rate_window = int(_env("LOGIN_RATE_WINDOW", "60"))
        self.version = "0.1.0"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.db_path.parent, self.export_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)


config = Config()
