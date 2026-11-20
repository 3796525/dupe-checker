"""Scheduler trigger evaluation; default state must be 'never scan'."""
import datetime
import json

import app.scheduler as scheduler_mod
from app.db import now_iso
from app.scheduler import Scheduler


class FakeScanner:
    def __init__(self):
        self.started = []

    def is_running(self):
        return False

    def start(self, plan_id):
        self.started.append(plan_id)
        return 1


def _plan(db, trigger_type, trigger, enabled=1):
    db.execute(
        "INSERT INTO scan_plans(name, roots_json, include_globs, exclude_globs, trigger_type, "
        "trigger_json, rate_meta, rate_hash, window_json, enabled, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("p", "[1]", "", "", trigger_type, json.dumps(trigger), 2000, 50, "{}", enabled,
         now_iso(), now_iso()),
    )
    db.commit()
    return db.query_one("SELECT * FROM scan_plans ORDER BY id DESC LIMIT 1")


def test_disabled_and_manual_plans_never_run(db):
    scanner = FakeScanner()
    sched = Scheduler(db, scanner)
    _plan(db, "manual", {})
    _plan(db, "daily", {"time": "02:00"}, enabled=0)
    sched.tick(datetime.datetime(2026, 11, 20, 2, 0))
    assert scanner.started == []


def test_daily_plan_runs_once_per_day(db):
    scanner = FakeScanner()
    sched = Scheduler(db, scanner)
    plan = _plan(db, "daily", {"time": "02:00"})
    now = datetime.datetime(2026, 11, 20, 2, 0)
    sched.tick(now)
    assert scanner.started == [plan["id"]]
    scanner.started.clear()
    sched.tick(now.replace(minute=1))
    assert scanner.started == []


def test_weekly_plan_checks_weekday(db):
    scanner = FakeScanner()
    sched = Scheduler(db, scanner)
    plan = _plan(db, "weekly", {"time": "03:00", "day": 1})  # Monday
    sched.tick(datetime.datetime(2026, 11, 19, 3, 0))  # Thursday
    assert scanner.started == []
    sched.tick(datetime.datetime(2026, 11, 23, 3, 0))  # Monday
    assert scanner.started == [plan["id"]]


def test_interval_plan_respects_last_run(db):
    scanner = FakeScanner()
    sched = Scheduler(db, scanner)
    plan = _plan(db, "interval", {"minutes": 60})
    now = datetime.datetime(2026, 11, 20, 10, 0)
    sched.tick(now)
    assert scanner.started == [plan["id"]]
    scanner.started.clear()
    sched.tick(now + datetime.timedelta(minutes=30))
    assert scanner.started == []
    sched.tick(now + datetime.timedelta(minutes=61))
    assert scanner.started == [plan["id"]]


def test_notify_only_creates_notification_and_never_scans(db):
    scanner = FakeScanner()
    sched = Scheduler(db, scanner)
    _plan(db, "notify_only", {"time": "02:00"})
    sched.tick(datetime.datetime(2026, 11, 20, 2, 0))
    assert scanner.started == []
    notes = db.query("SELECT * FROM notifications")
    assert notes and "该扫描了" in notes[0]["title"]


def test_no_plans_means_no_scan(db):
    scanner = FakeScanner()
    Scheduler(db, scanner).tick(datetime.datetime(2026, 11, 20, 2, 0))
    assert scanner.started == []
    assert db.query("SELECT * FROM scan_runs") == []
