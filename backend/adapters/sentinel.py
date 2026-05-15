"""
adapters/sentinel.py
─────────────────────
Implements the Adapter pattern required by the Omium P&E bench (run.py).

From the PDF blueprint:
    class SentinelAdapter(Adapter):
        def execute_task(self, problem_statement):
            task_id = start_agent_workflow(problem_statement)
            return poll_until_complete(task_id)

This module provides:
  - A base Adapter ABC (since run.py will import and call .execute_task())
  - SentinelAdapter that drives the LangGraph pipeline synchronously
  - Standalone helper functions usable from FastAPI background tasks

Design assumption: The P&E bench calls execute_task() synchronously and
expects a dict result. FastAPI uses start_agent_workflow() + poll_until_complete()
separately for async UX.
"""

from __future__ import annotations
import uuid
import time
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from backend.core.state import SentinelState, JobStatus
from backend.core.job_store import job_store
from backend.graph.pipeline import sentinel_graph


# ── Base class (matches Omium's expected interface) ────────────────────────
class Adapter(ABC):
    @abstractmethod
    def execute_task(self, problem_statement: str) -> Dict[str, Any]:
        ...


# ── Standalone helpers (used by FastAPI endpoints) ─────────────────────────
def start_agent_workflow(problem_statement: str) -> str:
    """
    Creates a job record, spins up the LangGraph pipeline in a background
    thread, and immediately returns the job_id so the caller can poll.
    """
    job_id = str(uuid.uuid4())

    initial_state: SentinelState = {
        "job_id":             job_id,
        "job_status":         JobStatus.PENDING,
        "problem_statement":  problem_statement,
        "loop_count":         0,
        "messages":           [],
        "trace_spans":        [],
    }
    job_store.create(job_id, initial_state)

    def _run():
        try:
            final_state = sentinel_graph.invoke(initial_state)
            # Merge final_state back into job_store
            job_store.update(job_id, final_state)
            job_store.set_status(job_id, JobStatus.COMPLETE)
        except Exception as exc:
            job_store.update(job_id, {
                "job_status": JobStatus.FAILED,
                "error": str(exc),
            })

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return job_id


def poll_until_complete(
    job_id: str,
    timeout_seconds: int = 120,
    poll_interval: float = 0.5,
) -> Dict[str, Any]:
    """
    Blocks until the job reaches COMPLETE or FAILED, then returns the full state.
    Used by SentinelAdapter.execute_task() for synchronous P&E bench calls.
    """
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        state = job_store.get(job_id)
        if state is None:
            raise ValueError(f"Job {job_id} not found in store.")
        status = state.get("job_status")
        if status in (JobStatus.COMPLETE, JobStatus.FAILED):
            return dict(state)
        time.sleep(poll_interval)

    raise TimeoutError(f"Job {job_id} did not complete within {timeout_seconds}s.")


# ── Concrete adapter (P&E bench entry point) ───────────────────────────────
class SentinelAdapter(Adapter):
    def execute_task(self, problem_statement: str) -> Dict[str, Any]:
        """
        Synchronous end-to-end execution.
        Matches the interface in the PDF blueprint exactly.
        """
        task_id = start_agent_workflow(problem_statement)
        return poll_until_complete(task_id)
