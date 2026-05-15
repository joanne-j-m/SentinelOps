"""
core/job_store.py
─────────────────
Thread-safe in-memory job store.

Design assumption: For a hackathon, in-memory is fine. Phase 5 can swap this
for Redis or a SQLite-backed store if the demo needs persistence across restarts.
"""

from __future__ import annotations
import threading
import time
from typing import Dict, Optional
from .state import SentinelState, JobStatus


class JobStore:
    def __init__(self) -> None:
        self._store: Dict[str, SentinelState] = {}
        self._lock = threading.Lock()

    def create(self, job_id: str, initial_state: SentinelState) -> None:
        with self._lock:
            self._store[job_id] = initial_state

    def get(self, job_id: str) -> Optional[SentinelState]:
        with self._lock:
            return self._store.get(job_id)

    def update(self, job_id: str, partial: dict) -> None:
        with self._lock:
            if job_id in self._store:
                self._store[job_id].update(partial)  # type: ignore[typeddict-item]

    def set_status(self, job_id: str, status: JobStatus) -> None:
        self.update(job_id, {"job_status": status})

    def all_jobs(self) -> Dict[str, SentinelState]:
        with self._lock:
            return dict(self._store)


# Singleton — imported everywhere
job_store = JobStore()
