"""Read-only self check executed at startup.

The tool must never be able to write into scanned data. Two independent
layers protect this:
  1. docker compose mounts every scan root with ":ro";
  2. this probe actively verifies each mount really rejects writes.

If any root accepts a write, the process refuses to start (exit code 2).
"""
from __future__ import annotations

import errno
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field

from .config import config

log = logging.getLogger("dupe.guard")

WRITE_ERRNOS = {errno.EACCES, errno.EPERM, errno.EROFS}


@dataclass
class RootCheck:
    path: str
    exists: bool = False
    is_dir: bool = False
    readable: bool = False
    readonly: bool = False
    error: str = ""


@dataclass
class GuardReport:
    roots: list[RootCheck] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.roots) and all(
            r.exists and r.is_dir and r.readable and r.readonly for r in self.roots
        )

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "roots": [
                {
                    "path": r.path,
                    "exists": r.exists,
                    "is_dir": r.is_dir,
                    "readable": r.readable,
                    "readonly": r.readonly,
                    "error": r.error,
                }
                for r in self.roots
            ],
        }


def probe_readonly(path: str) -> RootCheck:
    """Create a temp file in the root; success means the mount is writable."""
    chk = RootCheck(path=path)
    chk.exists = os.path.exists(path)
    if not chk.exists:
        chk.error = "挂载点不存在"
        return chk
    chk.is_dir = os.path.isdir(path)
    if not chk.is_dir:
        chk.error = "挂载点不是目录"
        return chk
    try:
        with os.scandir(path) as it:
            next(it, None)
        chk.readable = True
    except OSError as exc:
        chk.error = f"目录不可读: {exc.strerror}"
        return chk
    probe = os.path.join(path, f".dupe_write_probe_{uuid.uuid4().hex}")
    try:
        fd = os.open(probe, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno in WRITE_ERRNOS:
            chk.readonly = True
        else:
            chk.error = f"写探测异常: {exc.strerror}"
        return chk
    # Should never happen on a read-only mount: clean up and report failure.
    try:
        os.close(fd)
        os.unlink(probe)
    except OSError:
        pass
    chk.error = "目录可写！必须以只读方式挂载"
    return chk


def run_guard() -> GuardReport:
    report = GuardReport()
    for root in config.mount_roots:
        chk = probe_readonly(root)
        log.info(
            "guard root=%s exists=%s readable=%s readonly=%s %s",
            chk.path, chk.exists, chk.readable, chk.readonly, chk.error,
        )
        report.roots.append(chk)
    return report


def enforce_guard_or_exit() -> GuardReport:
    report = run_guard()
    if not report.roots:
        log.error("MOUNT_ROOTS 未配置：必须至少一个只读挂载的扫描根（启动中止）")
        sys.exit(2)
    if not report.passed:
        bad = [r for r in report.roots if not (r.exists and r.is_dir and r.readable and r.readonly)]
        for r in bad:
            log.error("只读自检失败: %s (%s)", r.path, r.error or "未知原因")
        log.error("启动中止：扫描根必须存在、可读、且严格只读")
        sys.exit(2)
    return report
