"""Startup guard: writable mounts must block the service."""
import errno
import os
from pathlib import Path

import app.guard as guard
from app.guard import probe_readonly


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


def test_run_guard_without_roots_reports_nothing(monkeypatch):
    monkeypatch.setattr(guard.config, "mount_roots", [])
    report = guard.run_guard()
    assert report.roots == []
    assert report.passed is False
