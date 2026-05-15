"""
agents/supervisor.py
─────────────────────
The Supervisor Agent is the entry point of every graph run.

Phase 1 behaviour (stub):
  - Validates the problem statement
  - Stamps metadata onto state
  - Decides the first routing target (always Scout in Phase 1)

Phase 2 will replace the stub logic with an LLM call to Groq/Llama 3 that:
  - Classifies the alert type (auth anomaly, malware hash, network scan, etc.)
  - Extracts structured fields (IPs, hashes, timestamps)
  - Writes a decomposition plan to state['messages']
"""

from __future__ import annotations
import datetime
from backend.core.state import SentinelState, JobStatus, AgentMessage
from backend.core.tracing import trace_span


def supervisor_node(state: SentinelState) -> SentinelState:
    """
    LangGraph node function. Receives state, returns updated state dict.
    """
    with trace_span(state, "supervisor", "decompose_task") as span:
        problem = state.get("problem_statement", "")
        span["input"] = {"problem_length": len(problem)}

        if not problem.strip():
            state["job_status"] = JobStatus.FAILED
            state["error"] = "Empty problem statement received."
            return state

        # ── Phase 1: Stub decomposition ──────────────────────────────────
        # Phase 2: Replace this block with a Groq LLM call that extracts
        #          IPs, hashes, timestamps, and alert_type from the problem.
        msg: AgentMessage = {
            "role": "supervisor",
            "content": (
                f"[STUB] Task received: '{problem[:120]}...'\n"
                "Decomposition plan: forward to Scout for raw evidence gathering."
            ),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

        state.setdefault("messages", []).append(msg)
        state["job_status"] = JobStatus.RUNNING
        state.setdefault("loop_count", 0)

        span["result"] = "decomposed → routing to scout"

    return state
