"""Read-only self check executed at startup and periodically afterwards.

The tool must never be able to write into scanned data. Three independent
layers protect this:
  1. docker compose mounts every scan root with ":ro";
  2. this probe actively verifies each mount (and sampled nested subdirectories)
     really rejects writes at startup;
  3. a background thread re-runs the probe every GUARD_INTERVAL_SECONDS. If a
     mount is remounted read-write or replaced at runtime, the global state is
     marked unsafe, an audit entry + notification are written, and the web
     layer refuses new scans / delete plans / exports with HTTP 409.

Probes only create a hidden file with O_CREAT|O_EXCL and delete it immediately;
file contents are never modified. A failed nested-directory probe is treated as
"not writable" (safe); for a scan root, unexpected errors such as ENOSPC/EIO are
fail-closed and mark the root unhealthy, because they may hide a writable mount.
"""
from __future__ import annotations

import errno
import logging
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

from .config import config

log = logging.getLogger("dupe.guard")

WRITE_ERRNOS = {errno.EACCES, errno.EPERM, errno.EROFS}
PROBE_PREFIX = ".dupe_write_probe_"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


@dataclass
class RootCheck:
    path: str
    exists: bool = False
    is_dir: bool = False
    readable: bool = False
    readonly: bool = False
    error: str = ""
    nested_checked: int = 0
    nested_writable: list[str] = field(default_factory=list)


@dataclass
class GuardReport:
    roots: list[RootCheck] = field(default_factory=list)
    verified_at: str = ""

    @property
    def passed(self) -> bool:
        return bool(self.roots) and all(
            r.exists and r.is_dir and r.readable and r.readonly and not r.nested_writable
            for r in self.roots
        )

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "verified_at": self.verified_at,
            "roots": [
                {
                    "path": r.path,
                    "exists": r.exists,
                    "is_dir": r.is_dir,
                    "readable": r.readable,
                    "readonly": r.readonly,
                    "error": r.error,
                    "nested_checked": r.nested_checked,
                    "nested_writable": list(r.nested_writable),
                }
                for r in self.roots
            ],
        }


def _probe_write(path: str) -> tuple[bool, str]:
    """Try to create a hidden probe file inside *path*.

    Returns (writable, cleanup_error). The probe file is removed immediately
    when creation succeeds; if unlinking fails the caller still treats the
    directory as writable (unsafe) and records the leftover.
    """
    probe = os.path.join(path, f"{PROBE_PREFIX}{uuid.uuid4().hex}")
    try:
        fd = os.open(probe, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    except OSError as exc:
        if exc.errno in WRITE_ERRNOS:
            return False, ""
        # ENOSPC/EIO/... are not proof of read-only: fail closed on the root.
        return False, f"写探测异常: {exc.strerror}"
    try:
        os.close(fd)
    except OSError:  # pragma: no cover - closing a fresh fd cannot realistically fail
        pass
    try:
        os.unlink(probe)
    except OSError as exc:  # pragma: no cover - needs an exotic filesystem
        log.error("guard: 探测文件无法清理，可能残留 %s: %s", probe, exc.strerror)
        return True, f"探测文件清理失败（可能残留）: {exc.strerror}"
    return True, ""


def _sample_subdirs(root: str, limit: int, max_depth: int) -> list[str]:
    """Return up to *limit* subdirectories of *root*, depth-first (max depth 3)."""
    found: list[str] = []
    queue: list[tuple[str, int]] = [(root, 0)]
    while queue and len(found) < limit:
        current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        try:
            with os.scandir(current) as it:
                dirs = sorted(
                    (entry for entry in it if entry.is_dir(follow_symlinks=False)),
                    key=lambda entry: entry.name,
                )
        except OSError:
            # Unreadable/inaccessible parents are skipped, never a failure.
            continue
        for entry in dirs:
            if len(found) >= limit:
                break
            found.append(entry.path)
            queue.append((entry.path, depth + 1))
    return found


def probe_readonly(path: str, sample_limit: int | None = None,
                   max_depth: int | None = None) -> RootCheck:
    """Probe the root itself and sampled nested subdirectories for writability."""
    if sample_limit is None:
        sample_limit = config.guard_sample_limit
    if max_depth is None:
        max_depth = config.guard_max_depth
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

    writable, detail = _probe_write(path)
    if writable:
        chk.error = "目录可写！必须以只读方式挂载"
        if detail:
            chk.error = f"{chk.error}（{detail}）"
        return chk
    if detail:
        chk.error = detail
        return chk

    # Root rejects writes: sample nested subdirectories, because a read-only
    # root may still contain a writable bind mount / ACL-enabled subtree.
    chk.readonly = True
    for sub in _sample_subdirs(path, sample_limit, max_depth) if sample_limit else []:
        nested_writable, nested_detail = _probe_write(sub)
        if nested_writable:
            chk.nested_writable.append(sub)
            chk.readonly = False
            chk.error = f"嵌套子目录可写！必须以只读方式挂载: {sub}"
            if nested_detail:
                chk.error = f"{chk.error}（{nested_detail}）"
            break
        chk.nested_checked += 1
    return chk


def run_guard() -> GuardReport:
    report = GuardReport(verified_at=_now_iso())
    for root in config.mount_roots:
        chk = probe_readonly(root)
        log.info(
            "guard root=%s exists=%s readable=%s readonly=%s nested=%s %s",
            chk.path, chk.exists, chk.readable, chk.readonly,
            chk.nested_checked, chk.error,
        )
        report.roots.append(chk)
    return report


# ---------------------------------------------------------------------------
# Global guard state + periodic recheck (P1-05)
# ---------------------------------------------------------------------------
_state_lock = threading.RLock()
_state: dict = {
    "report": GuardReport(),
    "verified_at": None,
    "unsafe": False,
    "reason": "",
}
_stop_event = threading.Event()
_thread: threading.Thread | None = None


def current_report() -> GuardReport:
    with _state_lock:
        return _state["report"]


def current_verified_at() -> str | None:
    with _state_lock:
        return _state["verified_at"]


def is_unsafe() -> bool:
    with _state_lock:
        return bool(_state["unsafe"])


def unsafe_reason() -> str:
    with _state_lock:
        return str(_state["reason"])


def reset_state() -> None:
    """Tests only: clear the in-process guard state."""
    with _state_lock:
        _state["report"] = GuardReport()
        _state["verified_at"] = None
        _state["unsafe"] = False
        _state["reason"] = ""


def _failure_reason(report: GuardReport) -> str:
    if not report.roots:
        return "MOUNT_ROOTS 未配置"
    bad = [r for r in report.roots if not (r.exists and r.is_dir and r.readable and r.readonly)]
    parts = []
    for r in bad:
        if r.nested_writable:
            parts.append(f"{r.path} 的嵌套子目录可写: {', '.join(r.nested_writable)}")
        else:
            parts.append(f"{r.path}: {r.error or '只读自检失败'}")
    if not parts:
        parts.append("只读自检未通过")
    return "；".join(parts)


def set_report(report: GuardReport, reason: str = "") -> None:
    with _state_lock:
        _state["report"] = report
        _state["verified_at"] = report.verified_at or _now_iso()
        _state["unsafe"] = not report.passed
        _state["reason"] = reason if not report.passed else ""


def apply_report(report: GuardReport, db=None) -> GuardReport:
    """Update global state and, on failure, write audit + notification."""
    was_unsafe = is_unsafe()
    reason = "" if report.passed else _failure_reason(report)
    set_report(report, reason)
    if not report.passed:
        log.error("只读自检失败：%s", reason)
        if db is not None:
            try:
                db.audit("system", "guard.failed", reason)
                db.notify(
                    "security",
                    "只读自检失败：已暂停扫描与导出",
                    f"{reason}。在恢复只读挂载并再次通过自检前，扫描/生成方案/导出均被拒绝。",
                )
            except Exception:  # pragma: no cover - keep guard alive
                log.exception("guard: 写入 audit/notification 失败")
    elif was_unsafe:
        log.warning("只读自检已恢复")
        if db is not None:
            try:
                db.audit("system", "guard.recovered", "只读自检重新通过")
            except Exception:  # pragma: no cover
                log.exception("guard: 写入 audit 失败")
    return report


def periodic_check(db=None) -> GuardReport:
    """Run one recheck (also used by tests to verify state transitions)."""
    report = run_guard()
    return apply_report(report, db)


def _periodic_loop(db, interval: int, on_report) -> None:
    log.info("只读自检周期复查已启动：每 %s 秒", interval)
    while not _stop_event.wait(interval):
        try:
            report = periodic_check(db)
            if on_report is not None:
                try:
                    on_report(report)
                except Exception:  # pragma: no cover
                    log.exception("guard: on_report 回调失败")
        except Exception:  # pragma: no cover - keep the thread alive
            log.exception("只读自检周期复查异常（保持上一次状态）")


def start_periodic(db, interval: int | None = None, on_report=None) -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop_event.clear()
    _thread = threading.Thread(
        target=_periodic_loop,
        args=(db, interval or config.guard_interval_seconds, on_report),
        daemon=True,
        name="dupe-guard",
    )
    _thread.start()


def stop_periodic() -> None:
    global _thread
    _stop_event.set()
    if _thread is not None:
        _thread.join(timeout=5)
        _thread = None


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
    set_report(report)
    return report
