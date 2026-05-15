"""
agents/scout.py
────────────────
Phase 2: Real IOC extraction from the problem statement using ioc_parser.
         Groq/Llama 3 analyses the raw text to surface log-like evidence.
"""

from __future__ import annotations
import datetime
from backend.core.state import SentinelState, JobStatus, AgentMessage, ThreatEvidence
from backend.core.tracing import trace_span
from backend.core.ioc_parser import extract_iocs, compute_anomaly_score
from backend.core.llm import call_llm

SYSTEM_PROMPT = """You are a security scout agent specialising in log analysis.
Given a security alert or log data, extract the raw evidence.

Respond ONLY with a JSON object:
{
  "raw_logs": ["<log line 1>", "<log line 2>"],
  "anomaly_reason": "<one sentence describing the anomaly pattern>"
}

If no log lines are present in the input, synthesise what the logs would look like
based on the described behaviour. Include at most 5 log lines."""


def scout_node(state: SentinelState) -> SentinelState:
    with trace_span(state, "scout", "gather_evidence") as span:
        problem    = state.get("problem_statement", "")
        loop_count = state.get("loop_count", 0)
        span["input"] = {"loop": loop_count, "problem_snippet": problem[:80]}

        # ── Step 1: Regex IOC extraction (always runs, no API needed) ─────
        iocs = extract_iocs(problem, include_private_ips=True)

        # ── Step 2: LLM log analysis ──────────────────────────────────────
        raw_logs      = []
        anomaly_reason = "Suspicious activity detected based on alert description."

        try:
            import json
            loop_context = (
                f"\n\nNote: This is investigation loop {loop_count + 1}. "
                "Look deeper for additional evidence patterns."
                if loop_count > 0 else ""
            )

            raw = call_llm(
                system=SYSTEM_PROMPT,
                user=f"Analyse this security alert and extract evidence:{loop_context}\n\n{problem}",
                temperature=0.2,
                max_tokens=512,
            )

            clean  = raw.strip().strip("```json").strip("```").strip()
            parsed = json.loads(clean)

            raw_logs       = parsed.get("raw_logs", [])
            anomaly_reason = parsed.get("anomaly_reason", anomaly_reason)

        except Exception as exc:
            span["error"] = str(exc)
            # Fallback: use the problem statement itself as the "log"
            raw_logs = [f"[RAW ALERT] {problem}"]

        # ── Step 3: Compute anomaly score from extracted IOCs + log volume ─
        anomaly_score = compute_anomaly_score(iocs, raw_logs)

        # Boost score slightly on re-loops (Scout found more context)
        if loop_count > 0:
            anomaly_score = min(anomaly_score + 0.10 * loop_count, 1.0)

        evidence: ThreatEvidence = {
            "raw_logs":       raw_logs,
            "matched_ips":    iocs["ips"],
            "matched_hashes": iocs["hashes"],
            "anomaly_score":  round(anomaly_score, 3),
            "anomaly_reason": anomaly_reason,
        }

        msg: AgentMessage = {
            "role": "scout",
            "content": (
                f"Evidence gathered (loop {loop_count}): "
                f"{len(iocs['ips'])} IP(s), {len(iocs['hashes'])} hash(es), "
                f"{len(iocs['cves'])} CVE(s) found. "
                f"Anomaly score: {anomaly_score:.2f}. "
                f"Reason: {anomaly_reason}"
            ),
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }

        state["evidence"] = evidence
        state.setdefault("messages", []).append(msg)
        span["result"] = (
            f"ips={iocs['ips']} score={anomaly_score} logs={len(raw_logs)}"
        )

    return state
