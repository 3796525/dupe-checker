"""In-process scheduler: evaluates scan plan triggers once a minute.

Deliberately simple: no cron daemon, no catch-up of missed runs (documented in
docs/03-技术方案.md). Default state is "do nothing" - nothing is scanned until
the user configures and enables a plan.
"""
from __future__ import annotations

import datetime
import json
import logging
import threading
import time

from .db import Database

log = logging.getLogger("dupe.scheduler")


class Scheduler:
    def __init__(self, db: Database, scanner) -> None:
        self.db = db
        self.scanner = scanner
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="dupe-sched")
        self._thread.start()

    def _loop(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:  # pragma: no cover - keep scheduler alive
                log.exception("scheduler tick failed")
            time.sleep(60)

    def tick(self, now: datetime.datetime | None = None) -> None:
        now = now or datetime.datetime.now()
        if self.scanner.is_running():
            return
        rows = self.db.query("SELECT * FROM scan_plans WHERE enabled=1")
        for plan in rows:
            if not self._is_due(plan, now):
                continue
            if plan["trigger_type"] == "notify_only":
                self.db.notify("reminder", "该扫描了", f"方案「{plan['name']}」提醒你手动发起扫描")
                self._mark_run(plan, now)
                continue
            try:
                self.scanner.start(int(plan["id"]))
                self._mark_run(plan, now)
                log.info("scheduled scan started plan=%s", plan["id"])
            except RuntimeError:
                return
            break

    def _is_due(self, plan, now: datetime.datetime) -> bool:
        last = self.db.get_setting(f"plan_last_run_{plan['id']}")
        trigger = json.loads(plan["trigger_json"] or "{}")
        ttype = plan["trigger_type"]
        if ttype == "manual":
            return False
        if ttype in ("daily", "weekly", "notify_only"):
            hhmm = trigger.get("time", "02:00")
            if now.strftime("%H:%M") != hhmm:
                return False
            if ttype == "weekly":
                day = int(trigger.get("day", 1))
                if now.isoweekday() != day:
                    return False
            if last:
                try:
                    last_dt = datetime.datetime.fromisoformat(last)
                except ValueError:
                    last_dt = None
                if last_dt and last_dt.date() == now.date():
                    return False
            return True
        if ttype == "interval":
            minutes = int(trigger.get("minutes", 1440))
            if not last:
                return True
            try:
                last_dt = datetime.datetime.fromisoformat(last)
            except ValueError:
                return True
            return (now - last_dt).total_seconds() >= minutes * 60
        return False

    def _mark_run(self, plan, now: datetime.datetime) -> None:
        self.db.set_setting(f"plan_last_run_{plan['id']}", now.isoformat(timespec="seconds"))
