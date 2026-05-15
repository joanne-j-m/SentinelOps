"""
agents/reporter.py
───────────────────
Phase 5: Uses IP classifier to separate attacker vs victim IPs.
         Recommendations now only block attacker IPs.
         Uses call_llm_json for robust JSON handling.
"""

from __future__ import annotations
import datetime
from backend.core.state import SentinelState, JobStatus, AgentMessage, ThreatFactSheet
from backend.core.tracing import trace_span
from backend.core.llm import call_llm
from backend.core.notify import send_notifications
from backend.core.noveum import ship_trace
from backend.core.ip_classifier import classify_ips

SYSTEM_PROMPT = """You are a cybersecurity report writer.
Write a concise, professional executive summary for a Threat Fact Sheet.
Keep it to 3-4 sentences. Be direct, factual, and actionable.
Do not use bullet points. Do not repeat the raw log data."""


def _determine_severity(anomaly_score: float, confidence: float) -> str:
    combined = (anomaly_score + confidence) / 2
    if combined >= 0.85: return "CRITICAL"
    elif combined >= 0.70: return "HIGH"
    elif combined >= 0.50: return "MEDIUM"
    return "LOW"


def reporter_node(state: SentinelState) -> SentinelState:
    with trace_span(state, "reporter", "compile_fact_sheet") as span:
        evidence  = state.get("evidence", {})
        context   = state.get("context", {})
        problem   = state.get("problem_statement", "N/A")
        job_id    = state.get("job_id", "unknown")

        anomaly_score = evidence.get("anomaly_score", 0.0)
        confidence    = context.get("confidence", 0.0)
        severity      = _determine_severity(anomaly_score, confidence)

        # ── Phase 5: Classify IPs as attacker vs victim ───────────────────
        all_ips = evidence.get("matched_ips", [])
        attacker_ips, victim_ips = classify_ips(all_ips, problem)

        attacker_str = ", ".join(attacker_ips) if attacker_ips else "None detected"
        victim_str   = ", ".join(victim_ips)   if victim_ips   else "None detected"
        hashes       = ", ".join(evidence.get("matched_hashes", [])) or "None detected"
        snippets     = context.get("search_snippets", [])
        cves         = context.get("cve_matches", [])
        mitre_raw    = context.get("mitre_tactics", [])  # type: ignore[typeddict-item]
        assessment   = context.get("assessment", "")      # type: ignore[typeddict-item]

        # ── LLM executive summary ─────────────────────────────────────────
        exec_summary = assessment or "Threat analysis complete."
        try:
            exec_summary = call_llm(
                system=SYSTEM_PROMPT,
                user=(
                    f"Alert: {problem}\n"
                    f"Severity: {severity}\nConfidence: {confidence:.0%}\n"
                    f"Attacker IPs: {attacker_str}\n"
                    f"Victim hosts: {victim_str}\n"
                    f"Analyst assessment: {assessment}\n"
                    f"MITRE tactics: {', '.join(mitre_raw) if mitre_raw else 'unknown'}"
                ),
                temperature=0.3,
                max_tokens=300,
            )
        except Exception as exc:
            span["error"] = str(exc)

        # ── Build sections ────────────────────────────────────────────────
        intel_md = "\n".join(f"  - {s[:200]}" for s in snippets[:3]) or "  - No external intel gathered."
        cve_md   = "\n".join(
            f"  - **{c.get('id','?')}**: {c.get('description','')[:100]}"
            for c in cves[:3]
        ) or "  - No CVEs matched."
        mitre_md = "\n".join(f"- {t}" for t in mitre_raw) if mitre_raw else "- Unknown"
        logs_md  = "\n".join(evidence.get("raw_logs", ["No logs captured"])[:4])

        # ── Phase 5: Smart recommendations using classified IPs ───────────
        recommendations = []
        if attacker_ips:
            recommendations.append(f"Block attacker IP(s) {attacker_str} at perimeter firewall immediately.")
        if victim_ips:
            recommendations.append(f"Isolate and investigate victim host(s): {victim_str}.")
        recommendations += [
            "Reset credentials for all affected accounts.",
            "Enable enhanced logging on affected systems.",
            "Check for lateral movement within the subnet.",
            "Review and patch systems matching identified CVEs." if cves else "Keep all systems patched and updated.",
        ]

        markdown = f"""# 🛡️ Sentinel-Ops — Threat Fact Sheet
**Generated:** {datetime.datetime.now(datetime.UTC).isoformat()}
**Severity:** {severity}
**Confidence:** {confidence:.0%}

---

## Executive Summary
{exec_summary}

## Alert
> {problem}

## Evidence
- **Anomaly Score:** {anomaly_score:.2f}
- **Reason:** {evidence.get("anomaly_reason", "N/A")}
- **Attacker IPs:** {attacker_str}
- **Victim Hosts:** {victim_str}
- **File Hashes:** {hashes}

## Raw Log Sample
```
{logs_md}
```

## CVE Matches
{cve_md}

## Threat Intelligence
{intel_md}

## Recommendations
{chr(10).join(f"{i+1}. {r}" for i, r in enumerate(recommendations))}

## MITRE ATT&CK
{mitre_md}

---
*Generated by Sentinel-Ops v0.5 · Powered by Llama 3 via Groq*
"""

        fact_sheet: ThreatFactSheet = {
            "summary":         exec_summary,
            "severity":        severity,
            "recommendations": recommendations,
            "mitre_tactics":   mitre_raw,
            "raw_markdown":    markdown,
        }

        state["fact_sheet"] = fact_sheet
        state["job_status"] = JobStatus.COMPLETE

        msg: AgentMessage = {
            "role":      "reporter",
            "content":   f"Threat Fact Sheet compiled. Severity: {severity}. Confidence: {confidence:.0%}. Attacker IPs: {attacker_str}. Victim hosts: {victim_str}.",
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        state.setdefault("messages", []).append(msg)
        span["result"] = f"severity={severity} attackers={attacker_ips} victims={victim_ips}"

    send_notifications(fact_sheet, job_id)
    ship_trace(state)
    return state
