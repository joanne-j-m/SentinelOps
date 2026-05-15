"""
core/noveum.py
───────────────
Noveum trace integration. Wraps agent operations with real trace spans
when NOVEUM_API_KEY is set, falls back to the stub tracer otherwise.

The existing trace_span() context manager in tracing.py is preserved
and still populates state['trace_spans'] for the API response.
This module adds shipping those spans to Noveum's platform.

Usage (automatic — called by reporter after job completes):
    from backend.core.noveum import ship_trace
    ship_trace(state)

Design assumption: Noveum SDK may not be pip-installable in all envs.
We import it lazily and degrade gracefully if unavailable.
"""

from __future__ import annotations
import os
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.core.state import SentinelState

logger = logging.getLogger(__name__)


def ship_trace(state: "SentinelState") -> None:
    """
    Ship collected trace spans to Noveum.
    Silent no-op if NOVEUM_API_KEY is not set or SDK unavailable.
    """
    api_key = os.getenv("NOVEUM_API_KEY", "").strip()
    if not api_key:
        logger.info("NOVEUM_API_KEY not set — skipping trace export.")
        return

    spans     = state.get("trace_spans", [])
    job_id    = state.get("job_id", "unknown")
    fact_sheet = state.get("fact_sheet", {})

    if not spans:
        return

    try:
        # Lazy import — won't crash if noveum SDK not installed
        import noveum_trace  # type: ignore

        trace = noveum_trace.Trace(
            api_key=api_key,
            name=f"sentinel-ops-job-{job_id}",
            metadata={
                "job_id":   job_id,
                "severity": fact_sheet.get("severity", "UNKNOWN"),
                "status":   str(state.get("job_status", "")),
            },
        )

        for span in spans:
            trace.add_span(
                name=f"{span['agent']}.{span['operation']}",
                inputs=span.get("input", {}),
                outputs={"result": span.get("result"), "error": span.get("error")},
                duration_ms=span.get("duration_ms", 0),
            )

        trace.submit()
        logger.info(f"Noveum trace shipped for job {job_id} ({len(spans)} spans).")

    except ImportError:
        logger.info("noveum_trace SDK not installed — skipping trace export.")
    except Exception as exc:
        logger.warning(f"Noveum trace export failed for job {job_id}: {exc}")


def annotate_span(
    state: "SentinelState",
    agent: str,
    operation: str,
    inputs: dict,
    outputs: dict,
    duration_ms: float = 0.0,
) -> None:
    """
    Manually add a span to state['trace_spans'].
    Useful for wrapping non-context-manager code paths.
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
