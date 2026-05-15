"""
agents/scout.py
────────────────
The Scout Agent gathers raw evidence from logs, files, or webhook payloads.

Phase 1 behaviour (stub):
  - Simulates finding a suspicious IP and log lines
  - Populates state['evidence'] with placeholder data
  - Marks anomaly_score so the Analyst can decide if looping is needed

Phase 2 will add:
  - Real log file parsing via watchdog / inotify
  - Regex-based IOC extraction (IP, hash, user-agent patterns)
  - Webhook payload deserialisation (Falco, Wazuh, custom SIEM alerts)
"""

from __future__ import annotations
import datetime
from backend.core.state import SentinelState, JobStatus, AgentMessage, ThreatEvidence
from backend.core.tracing import trace_span


def scout_node(state: SentinelState) -> SentinelState:
    with trace_span(state, "scout", "gather_evidence") as span:
        problem = state.get("problem_statement", "")
        loop_count = state.get("loop_count", 0)

        span["input"] = {"loop": loop_count, "problem_snippet": problem[:80]}

        # ── Phase 1: Stub evidence ───────────────────────────────────────
        # Phase 2: Replace with real log parsing, regex IOC extraction,
        #          and file/webhook payload analysis.
        evidence: ThreatEvidence = {
            "raw_logs": [
                "2024-06-10T03:14:22Z  WARN  Failed SSH login from 192.168.1.42 (attempt 7/10)",
                "2024-06-10T03:14:25Z  WARN  Failed SSH login from 192.168.1.42 (attempt 8/10)",
                "2024-06-10T03:14:28Z ERROR  Account 'root' locked after 10 failed attempts",
            ],
            "matched_ips":    ["192.168.1.42"],
            "matched_hashes": [],
            # Simulate lower confidence on second loop to trigger analyst loop
            "anomaly_score":  0.85 if loop_count == 0 else 0.95,
            "anomaly_reason": (
                "Repeated failed SSH login attempts followed by account lockout. "
                "Possible brute-force attack."
            ),
        }

        msg: AgentMessage = {
            "role": "scout",
            "content": (
                f"[STUB] Evidence gathered on loop {loop_count}. "
                f"Found {len(evidence['matched_ips'])} suspicious IP(s). "
                f"Anomaly score: {evidence['anomaly_score']}"
            ),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

        state["evidence"] = evidence
        state.setdefault("messages", []).append(msg)
        span["result"] = f"anomaly_score={evidence['anomaly_score']}"

    return state
