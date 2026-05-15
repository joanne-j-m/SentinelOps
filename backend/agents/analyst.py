"""
agents/analyst.py
──────────────────
The Analyst Agent contextualises raw evidence.

Phase 1 behaviour (stub):
  - Accepts Scout's evidence
  - Simulates a threat-intel lookup result
  - Sets confidence score; if confidence < 0.6 AND loop_count < 3, signals loop

Phase 2 will add:
  - Tavily web search for IP reputation / CVE lookups
  - ChromaDB vector store for internal playbook RAG
  - Groq/Llama 3 call to reason over combined evidence + search snippets
  - AbuseIPDB / Shodan API calls for IP enrichment

Routing contract:
  Returns state with state['context']['confidence'].
  The graph's edge function reads this to decide: → reporter OR → scout (loop).
"""

from __future__ import annotations
import datetime
from backend.core.state import SentinelState, JobStatus, AgentMessage, ThreatContext
from backend.core.tracing import trace_span

CONFIDENCE_THRESHOLD = 0.6
MAX_LOOPS = 3


def analyst_node(state: SentinelState) -> SentinelState:
    with trace_span(state, "analyst", "enrich_evidence") as span:
        evidence = state.get("evidence", {})
        loop_count = state.get("loop_count", 0)

        span["input"] = {
            "matched_ips": evidence.get("matched_ips", []),
            "anomaly_score": evidence.get("anomaly_score"),
            "loop": loop_count,
        }

        # ── Phase 1: Stub enrichment ─────────────────────────────────────
        # Phase 2: Replace with Tavily search, ChromaDB RAG, Groq LLM call.
        context: ThreatContext = {
            "cve_matches": [],   # Phase 2: real CVE lookups
            "threat_intel": [
                {
                    "ip": "192.168.1.42",
                    "reputation": "suspicious",
                    "source": "[STUB] internal threat-intel DB",
                    "notes": "Associated with credential-stuffing campaigns in Q1 2024.",
                }
            ],
            "search_snippets": [
                "[STUB] Threat intel: IP 192.168.1.42 observed in Shodan scans targeting port 22.",
            ],
            # Confidence rises after a loop (Scout gathered more data)
            "confidence": 0.45 if loop_count == 0 else 0.82,
        }

        needs_loop = (
            context["confidence"] < CONFIDENCE_THRESHOLD
            and loop_count < MAX_LOOPS
        )

        msg: AgentMessage = {
            "role": "analyst",
            "content": (
                f"[STUB] Enrichment complete. Confidence: {context['confidence']}. "
                + ("Requesting additional Scout investigation." if needs_loop
                   else "Sufficient confidence to compile report.")
            ),
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }

        state["context"] = context
        state.setdefault("messages", []).append(msg)

        if needs_loop:
            state["loop_count"] = loop_count + 1
            state["job_status"] = JobStatus.LOOPING

        span["result"] = f"confidence={context['confidence']} needs_loop={needs_loop}"

    return state
