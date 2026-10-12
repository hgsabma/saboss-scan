"""Background execution of scans and scheduled monitoring.

A scan takes 5-20 seconds (network timeouts), so it runs in a background
thread while the browser shows a progress page.

Trade-off: an in-process thread pool keeps deployment simple (one process, no
Redis). Queued scans are stored in the database, so nothing is lost on a
restart: recover_interrupted_scans() re-queues them at startup. When load
grows, this module is the single place to swap in a real job queue
(for example RQ or Celery with Redis). See docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from ..config import Settings
from ..db import Database
from ..ratelimit import RateLimiter
from .service import recover_interrupted_scans, run_scan, schedule_due_scans

logger = logging.getLogger("saboss.worker")


class ScanWorker:
    def __init__(self, database: Database, settings: Settings, limiter: RateLimiter):
        self.database = database
        self.settings = settings
        self.limiter = limiter
        self.inline = settings.scan_executor == "inline"
        self._pool = None if self.inline else ThreadPoolExecutor(settings.scan_workers, thread_name_prefix="scan")
        self._stop = threading.Event()
        self._scheduler: threading.Thread | None = None

    # -- scans
    def submit(self, scan_id: int) -> None:
        if self.inline:
            self._run(scan_id)
        else:
            self._pool.submit(self._run, scan_id)

    def _run(self, scan_id: int) -> None:
        db = self.database.session()
        try:
            run_scan(db, self.settings, scan_id)
        finally:
            db.close()

    # -- lifecycle
    def start(self) -> None:
        db = self.database.session()
        try:
            for scan_id in recover_interrupted_scans(db):
                self.submit(scan_id)
        finally:
            db.close()
        if self.settings.scheduler_enabled and not self.inline:
            self._scheduler = threading.Thread(target=self._schedule_loop, name="scan-scheduler", daemon=True)
            self._scheduler.start()

    def stop(self) -> None:
        self._stop.set()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    def run_scheduler_once(self) -> list[int]:
        db = self.database.session()
        try:
            scan_ids = schedule_due_scans(db, self.settings, self.limiter)
        finally:
            db.close()
        for scan_id in scan_ids:
            self.submit(scan_id)
        return scan_ids

    def _schedule_loop(self) -> None:
        while not self._stop.wait(self.settings.scheduler_poll_seconds):
            try:
                self.run_scheduler_once()
            except Exception:
                logger.exception("scheduler iteration failed")
