"""
core/tracing.py
───────────────
Tracing layer. Wraps agent operations with structured spans shipped
to Omium for full pipeline observability.
Appends structured log entries to state['trace_spans'].

Usage:
    with trace_span(state, "scout", "parse_logs") as span:
        span["input"] = {"lines": 42}
        # do work ...
        span["result"] = "found anomaly"
"""

from __future__ import annotations
import time
import contextlib
from typing import Generator, Dict, Any
from .state import SentinelState


@contextlib.contextmanager
def trace_span(
    state: SentinelState,
    agent: str,
    operation: str,
) -> Generator[Dict[str, Any], None, None]:
    span: Dict[str, Any] = {
        "agent": agent,
        "operation": operation,
        "start_time": time.time(),
        "input": {},
        "result": None,
        "error": None,
    }
    try:
        yield span
    except Exception as exc:
        span["error"] = str(exc)
        raise
    finally:
        span["duration_ms"] = round((time.time() - span["start_time"]) * 1000, 2)
        if "trace_spans" not in state:
            state["trace_spans"] = []
        state["trace_spans"].append(span)