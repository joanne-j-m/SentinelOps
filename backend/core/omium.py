"""
core/omium.py
─────────────
Omium SDK integration for Sentinel-Ops.
Provides automatic tracing + checkpointing for the LangGraph pipeline
using the real omium 0.4.1 API.

Initialization (called once at startup via init_omium() in app.py):
    omium.init()                   — configure SDK with API key + project
    omium.instrument_langgraph()   — auto-trace every LangGraph node

ship_trace() is kept as a lightweight shim for API compatibility with
reporter.py. With instrument_langgraph(), traces are shipped automatically
as each node completes — no manual submission needed.

annotate_span() is unchanged from the noveum interface — drop-in safe.
"""

from __future__ import annotations
import os
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.core.state import SentinelState

logger = logging.getLogger(__name__)

_OMIUM_API_KEY = os.getenv("OMIUM_API_KEY", "").strip()
_initialized   = False


def init_omium() -> None:
    """
    Initialize Omium SDK and instrument LangGraph.
    Call this once at app startup (app.py).
    Silent no-op if OMIUM_API_KEY is not set or SDK unavailable.
    """
    global _initialized
    if _initialized:
        return

    if not _OMIUM_API_KEY:
        logger.info("OMIUM_API_KEY not set — Omium tracing disabled.")
        return

    try:
        import omium  # type: ignore

        omium.init(
            api_key=_OMIUM_API_KEY,
            project="sentinel-ops",
            auto_trace=True,
            auto_checkpoint=True,
            checkpoint_strategy="node",
        )
        omium.instrument_langgraph()
        _initialized = True
        logger.info("Omium initialized — LangGraph tracing + checkpoints active.")

    except ImportError:
        logger.info("omium SDK not installed — skipping initialization.")
    except Exception as exc:
        logger.warning(f"Omium init failed: {exc}")


def ship_trace(state: "SentinelState") -> None:
    """
    No-op shim kept for API compatibility with reporter.py.
    With omium.instrument_langgraph(), traces are shipped automatically
    as each node completes — no manual submission needed.
    The fine-grained state['trace_spans'] are still available in the
    API response for the React dashboard trace viewer.
    """
    job_id = state.get("job_id", "unknown")
    spans  = state.get("trace_spans", [])
    if _initialized and spans:
        logger.info(f"Omium auto-traced job {job_id} ({len(spans)} spans shipped).")


def annotate_span(
    state: "SentinelState",
    agent: str,
    operation: str,
    inputs: dict,
    outputs: dict,
    duration_ms: float = 0.0,
) -> None:
    """
    Manually append a span to state['trace_spans'].
    Drop-in replacement for noveum.annotate_span() — identical signature.
    """
    span = {
        "agent":       agent,
        "operation":   operation,
        "input":       inputs,
        "result":      outputs.get("result"),
        "error":       outputs.get("error"),
        "duration_ms": duration_ms,
    }
    state.setdefault("trace_spans", []).append(span)