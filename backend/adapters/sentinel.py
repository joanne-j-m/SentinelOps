"""
adapters/sentinel.py
─────────────────────
Implements the Adapter pattern required by the Omium P&E bench (run.py).

Phase 7 fixes:
  - Background thread receives a deep copy of initial_state so graph
    execution never mutates the job_store's canonical copy mid-flight.
  - Input sanitization: problem_statement is length-capped and stripped
    of control characters before entering the pipeline.

This module provides:
  - A base Adapter ABC (since run.py will import and call .execute_task())
  - SentinelAdapter that drives the LangGraph pipeline synchronously
  - Standalone helper functions usable from FastAPI background tasks
"""

from __future__ import annotations
import copy
import re
import uuid
import time
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any

from backend.core.state import SentinelState, JobStatus
from backend.core.job_store import job_store
from backend.graph.pipeline import get_graph

# ── Input constraints ──────────────────────────────────────────────────────
MAX_PROBLEM_LENGTH = 5000   # characters — anything longer is likely abuse


def sanitize_input(problem_statement: str) -> str:
    """
    Sanitize user-controlled input before it enters the LLM pipeline.
    - Strip control characters (except newline/tab).
    - Truncate to MAX_PROBLEM_LENGTH.
    """
    # Remove ASCII control chars except \n (0x0A) and \t (0x09)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', problem_statement)
    return cleaned[:MAX_PROBLEM_LENGTH].strip()


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
    sanitized = sanitize_input(problem_statement)

    initial_state: SentinelState = {
        "job_id":             job_id,
        "job_status":         JobStatus.PENDING,
        "problem_statement":  sanitized,
        "loop_count":         0,
        "messages":           [],
        "trace_spans":        [],
    }
    job_store.create(job_id, initial_state)

    # Deep copy for the background thread — graph execution mutates in place,
    # and we don't want it touching the job_store's canonical copy.
    thread_state = copy.deepcopy(initial_state)

    def _run() -> None:
        try:
            graph = get_graph()
            final_state: Dict[str, Any] = graph.invoke(thread_state)  # type: ignore[union-attr]
            # Merge final_state back into job_store atomically
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