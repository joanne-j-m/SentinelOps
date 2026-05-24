"""
core/job_store.py
─────────────────
Thread-safe in-memory job store.

Phase 7 fixes:
  - get() returns a deep copy to prevent race conditions between the
    background graph thread and the FastAPI polling thread.
  - all_jobs() returns deep copies for the same reason.
"""

from __future__ import annotations
import copy
import threading
from typing import Dict, Optional, Any
from .state import SentinelState, JobStatus


class JobStore:
    def __init__(self) -> None:
        self._store: Dict[str, SentinelState] = {}
        self._lock = threading.Lock()

    def create(self, job_id: str, initial_state: SentinelState) -> None:
        with self._lock:
            self._store[job_id] = copy.deepcopy(initial_state)

    def get(self, job_id: str) -> Optional[SentinelState]:
        """Return a deep copy so callers never mutate the canonical state."""
        with self._lock:
            state = self._store.get(job_id)
            return copy.deepcopy(state) if state is not None else None

    def update(self, job_id: str, partial: Dict[str, Any]) -> None:
        with self._lock:
            if job_id in self._store:
                self._store[job_id].update(partial)  # type: ignore[typeddict-item]

    def set_status(self, job_id: str, status: JobStatus) -> None:
        self.update(job_id, {"job_status": status})

    def all_jobs(self) -> Dict[str, SentinelState]:
        """Return deep copies of all jobs for safe iteration."""
        with self._lock:
            return {k: copy.deepcopy(v) for k, v in self._store.items()}


# Singleton — imported everywhere
job_store = JobStore()