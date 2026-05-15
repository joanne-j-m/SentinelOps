"""
agents/supervisor.py
─────────────────────
Phase 2: Real Groq/Llama 3 alert classification and decomposition.

The Supervisor now:
  1. Calls Llama 3 to classify the alert type
  2. Extracts a structured decomposition plan
  3. Sets alert_type on state for downstream agents to use
"""

from __future__ import annotations
import datetime
import json
from backend.core.state import SentinelState, JobStatus, AgentMessage
from backend.core.tracing import trace_span
from backend.core.llm import call_llm

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) supervisor.
Your job is to classify incoming security alerts and create a structured investigation plan.

Given an alert, respond ONLY with a JSON object (no markdown, no explanation) in this exact format:
{
  "alert_type": "<one of: brute_force | malware | network_scan | data_exfiltration | privilege_escalation | phishing | unknown>",
  "severity_estimate": "<one of: LOW | MEDIUM | HIGH | CRITICAL>",
  "key_indicators": ["<indicator 1>", "<indicator 2>"],
  "investigation_plan": "<1-2 sentence plan for the Scout agent>"
}"""


def supervisor_node(state: SentinelState) -> SentinelState:
    with trace_span(state, "supervisor", "decompose_task") as span:
        problem = state.get("problem_statement", "")
        span["input"] = {"problem_length": len(problem)}

        if not problem.strip():
            state["job_status"] = JobStatus.FAILED
            state["error"] = "Empty problem statement received."
            return state

        # ── Phase 2: Real LLM classification ─────────────────────────────
        try:
            raw = call_llm(
                system=SYSTEM_PROMPT,
                user=f"Classify this security alert:\n\n{problem}",
                temperature=0.1,
                max_tokens=512,
            )

            # Strip markdown fences if model adds them anyway
            clean = raw.strip().strip("```json").strip("```").strip()
            parsed = json.loads(clean)

            alert_type   = parsed.get("alert_type", "unknown")
            severity_est = parsed.get("severity_estimate", "MEDIUM")
            indicators   = parsed.get("key_indicators", [])
            plan         = parsed.get("investigation_plan", "Investigate all available evidence.")

            content = (
                f"Alert classified as: {alert_type.upper()} (estimated {severity_est}).\n"
                f"Key indicators: {', '.join(indicators) if indicators else 'none extracted'}.\n"
                f"Investigation plan: {plan}"
            )

            state["alert_type"] = alert_type  # type: ignore[typeddict-unknown-key]

        except Exception as exc:
            content = (
                f"LLM classification failed ({exc}). "
                "Proceeding with generic investigation."
            )
            state["alert_type"] = "unknown"  # type: ignore[typeddict-unknown-key]
            span["error"] = str(exc)

        msg: AgentMessage = {
            "role":      "supervisor",
            "content":   content,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }

        state.setdefault("messages", []).append(msg)
        state["job_status"] = JobStatus.RUNNING
        state.setdefault("loop_count", 0)
        span["result"] = f"alert_type={state.get('alert_type')}"

    return state
