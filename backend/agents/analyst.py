"""
agents/analyst.py
──────────────────
Phase 2: Real enrichment via Tavily search + Groq/Llama 3 reasoning.

The Analyst now:
  1. Searches Tavily for IP/CVE/hash threat intel (if API key set)
  2. Calls Llama 3 to reason over evidence + search snippets
  3. Produces a confidence score based on LLM assessment
  4. Triggers loop back to Scout if confidence is too low
"""

from __future__ import annotations
import datetime
import json
from backend.core.state import SentinelState, JobStatus, AgentMessage, ThreatContext
from backend.core.tracing import trace_span
from backend.core.llm import call_llm
from backend.core.search import search_threat_intel

CONFIDENCE_THRESHOLD = 0.6
MAX_LOOPS = 3

SYSTEM_PROMPT = """You are a senior threat intelligence analyst.
Given security evidence and threat intel snippets, assess the threat.

Respond ONLY with a JSON object:
{
  "threat_assessment": "<2-3 sentence analysis of what is happening>",
  "confidence": <float between 0.0 and 1.0>,
  "confidence_reason": "<why you are or aren't confident>",
  "cve_matches": [{"id": "CVE-XXXX-XXXX", "description": "..."}],
  "mitre_tactics": ["T1110", "..."],
  "needs_more_data": <true if confidence < 0.6 and more Scout investigation would help>
}

Confidence guide:
  0.0-0.3: Very little evidence, likely noise
  0.3-0.6: Some evidence but inconclusive, needs more data
  0.6-0.8: Reasonable evidence, likely a real threat
  0.8-1.0: Strong evidence, high confidence threat"""


def analyst_node(state: SentinelState) -> SentinelState:
    with trace_span(state, "analyst", "enrich_evidence") as span:
        evidence   = state.get("evidence", {})
        loop_count = state.get("loop_count", 0)

        span["input"] = {
            "matched_ips":   evidence.get("matched_ips", []),
            "anomaly_score": evidence.get("anomaly_score"),
            "loop":          loop_count,
        }

        # ── Step 1: Tavily threat intel search ────────────────────────────
        search_targets = (
            evidence.get("matched_ips", []) +
            evidence.get("matched_hashes", [])
        )
        snippets = search_threat_intel(search_targets, max_results=2) if search_targets else []

        # ── Step 2: LLM reasoning over evidence + search context ──────────
        evidence_summary = (
            f"Anomaly score: {evidence.get('anomaly_score', 0)}\n"
            f"Anomaly reason: {evidence.get('anomaly_reason', 'N/A')}\n"
            f"Suspicious IPs: {evidence.get('matched_ips', [])}\n"
            f"File hashes: {evidence.get('matched_hashes', [])}\n"
            f"Log sample:\n" +
            "\n".join(evidence.get("raw_logs", [])[:3])
        )

        search_context = (
            "\n\nThreat intel from search:\n" + "\n".join(snippets)
            if snippets else "\n\nNo external threat intel available."
        )

        confidence   = 0.5   # safe default
        assessment   = "Insufficient data for full analysis."
        cve_matches  = []
        mitre_tactics = []
        needs_more   = False

        try:
            raw = call_llm(
                system=SYSTEM_PROMPT,
                user=(
                    f"Analyse this security evidence (investigation loop {loop_count + 1}):\n\n"
                    f"{evidence_summary}{search_context}"
                ),
                temperature=0.1,
                max_tokens=768,
            )

            clean  = raw.strip().strip("```json").strip("```").strip()
            parsed = json.loads(clean)

            confidence    = float(parsed.get("confidence", 0.5))
            assessment    = parsed.get("threat_assessment", assessment)
            cve_matches   = parsed.get("cve_matches", [])
            mitre_tactics = parsed.get("mitre_tactics", [])
            needs_more    = parsed.get("needs_more_data", False)

        except Exception as exc:
            span["error"] = str(exc)
            # Fallback: use anomaly_score as confidence proxy
            confidence = min(evidence.get("anomaly_score", 0.5) * 0.9, 0.85)

        # ── Step 3: Decide loop or proceed ────────────────────────────────
        should_loop = (
            (confidence < CONFIDENCE_THRESHOLD or needs_more)
            and loop_count < MAX_LOOPS
        )

        context: ThreatContext = {
            "cve_matches":    cve_matches,
            "threat_intel":   [{"snippet": s} for s in snippets],
            "search_snippets": snippets,
            "confidence":     round(confidence, 3),
        }

        # Store mitre_tactics on context for reporter
        context["mitre_tactics"] = mitre_tactics  # type: ignore[typeddict-unknown-key]
        context["assessment"]    = assessment       # type: ignore[typeddict-unknown-key]

        msg: AgentMessage = {
            "role": "analyst",
            "content": (
                f"Enrichment complete (loop {loop_count}). "
                f"Confidence: {confidence:.0%}. "
                f"Assessment: {assessment[:100]}... "
                + ("→ Requesting more Scout data." if should_loop
                   else "→ Sufficient confidence, proceeding to report.")
            ),
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }

        state["context"] = context
        state.setdefault("messages", []).append(msg)

        if should_loop:
            state["loop_count"] = loop_count + 1
            state["job_status"] = JobStatus.LOOPING

        span["result"] = f"confidence={confidence:.2f} needs_loop={should_loop}"

    return state
