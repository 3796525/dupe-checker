"""Startup / periodic guard: writable mounts and nested subdirs must block the service."""
import errno
import os
import threading
from pathlib import Path

import pytest

import app.guard as guard
from app.guard import GuardReport, RootCheck, probe_readonly


@pytest.fixture(autouse=True)
def _clean_guard_state():
    guard.reset_state()
    yield
    guard.reset_state()


def test_missing_root_fails(tmp_path):
    chk = probe_readonly(str(tmp_path / "nope"))
    assert chk.exists is False
    assert chk.readonly is False
    assert "不存在" in (chk.error or "")


def test_file_root_fails(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x")
    chk = probe_readonly(str(f))
    assert chk.is_dir is False
    assert "不是目录" in (chk.error or "")


def test_writable_root_is_reported(tmp_path):
    chk = probe_readonly(str(tmp_path))
    assert chk.exists and chk.is_dir and chk.readable
    assert chk.readonly is False
    assert "可写" in (chk.error or "")
    leftovers = [p for p in Path(tmp_path).iterdir() if p.name.startswith(".dupe_write_probe_")]
    assert leftovers == [], "probe file must be cleaned up"


def test_readonly_root_passes(monkeypatch, tmp_path):
    def deny(*args, **kwargs):
        raise PermissionError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(guard.os, "open", deny)
    chk = probe_readonly(str(tmp_path))
    assert chk.readonly is True
    assert not chk.error


def test_nested_writable_subdir_is_reported(monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "sub" / "deep").mkdir(parents=True)
    (root / "readonly_a").mkdir()

    def fake_probe(path):
        # Root looks read-only, one nested directory is writable.
        return (str(path) == str(root / "sub"), "")

    monkeypatch.setattr(guard, "_probe_write", fake_probe)
    chk = probe_readonly(str(root), sample_limit=20, max_depth=3)
    assert chk.readonly is False
    assert chk.nested_writable == [str(root / "sub")]
    assert "嵌套子目录可写" in (chk.error or "")
    assert chk.nested_checked >= 1


def test_all_readonly_nested_sampling_passes(monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir()
    monkeypatch.setattr(guard, "_probe_write", lambda path: (False, ""))
    chk = probe_readonly(str(root), sample_limit=20, max_depth=3)
    assert chk.readonly is True
    assert chk.nested_writable == []
    assert chk.nested_checked == 2
    report = GuardReport(verified_at="2026-01-01T00:00:00+0800", roots=[chk])
    assert report.passed is True


def test_nested_sampling_skips_unreadable_dirs(monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "locked").mkdir(parents=True)
    real_scandir = os.scandir

    def fake_scandir(path, *args, **kwargs):
        if str(path) == str(root / "locked"):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_scandir(path, *args, **kwargs)

    monkeypatch.setattr(guard, "_probe_write", lambda path: (False, ""))
    monkeypatch.setattr(guard.os, "scandir", fake_scandir)
    chk = probe_readonly(str(root), sample_limit=20, max_depth=3)
    assert chk.readable is True
    assert chk.readonly is True, "an unreadable nested dir is skipped, not a failure"
    assert chk.nested_checked == 1


def test_periodic_check_flips_state_and_notifies(monkeypatch, db, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setattr(guard.config, "mount_roots", [str(root)])

    writable = GuardReport(verified_at="t1", roots=[RootCheck(
        path=str(root), exists=True, is_dir=True, readable=True,
        readonly=False, error="目录可写！必须以只读方式挂载",
    )])
    monkeypatch.setattr(guard, "run_guard", lambda: writable)
    guard.periodic_check(db)
    assert guard.is_unsafe() is True
    assert "可写" in guard.unsafe_reason()
    assert guard.current_verified_at() == "t1"
    audits = db.query("SELECT action FROM audit_log WHERE action='guard.failed'")
    assert audits, "failure must be audited"
    notes = db.query("SELECT title FROM notifications ORDER BY id DESC LIMIT 1")
    assert notes and "只读自检" in notes[0]["title"]

    readonly = GuardReport(verified_at="t2", roots=[RootCheck(
        path=str(root), exists=True, is_dir=True, readable=True, readonly=True,
    )])
    monkeypatch.setattr(guard, "run_guard", lambda: readonly)
    guard.periodic_check(db)
    assert guard.is_unsafe() is False
    assert guard.unsafe_reason() == ""
    assert guard.current_verified_at() == "t2"
    assert guard.current_report().passed is True


def test_periodic_thread_start_and_stop(db):
    guard.start_periodic(db, interval=3600)
    try:
        assert any(t.name == "dupe-guard" and t.is_alive() for t in threading.enumerate())
    finally:
        guard.stop_periodic()
    assert not any(t.name == "dupe-guard" for t in threading.enumerate())


def test_run_guard_without_roots_reports_nothing(monkeypatch):
    monkeypatch.setattr(guard.config, "mount_roots", [])
    report = guard.run_guard()
    assert report.roots == []
    assert report.passed is False
