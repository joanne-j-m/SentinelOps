"""
core/state.py
─────────────
The SentinelState TypedDict is the shared memory that flows through every
node in the LangGraph graph. Every agent reads from it and writes back to it.

Design assumptions (Phase 1):
- All fields are Optional so stubs can leave them blank
- 'messages' is the LangGraph-standard conversation log
- 'job_status' drives the FastAPI polling response
- 'loop_count' prevents infinite retry loops
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any
from typing_extensions import TypedDict
from enum import Enum


class JobStatus(str, Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    LOOPING    = "looping"       # Analyst asked Scout for more data
    COMPLETE   = "complete"
    FAILED     = "failed"


class AgentMessage(TypedDict):
    role: str          # "supervisor" | "scout" | "analyst" | "reporter"
    content: str
    timestamp: str


class ThreatEvidence(TypedDict, total=False):
    """Raw evidence collected by the Scout."""
    raw_logs:       List[str]
    matched_ips:    List[str]
    matched_hashes: List[str]
    anomaly_score:  float
    anomaly_reason: str


class ThreatContext(TypedDict, total=False):
    """Enriched context added by the Analyst."""
    cve_matches:     List[Dict[str, str]]
    threat_intel:    List[Dict[str, str]]
    search_snippets: List[str]
    confidence:      float      # 0.0–1.0; if < 0.5 → loop back to Scout


class ThreatFactSheet(TypedDict, total=False):
    """Final output compiled by the Reporter."""
    summary:         str
    severity:        str        # LOW / MEDIUM / HIGH / CRITICAL
    recommendations: List[str]
    mitre_tactics:   List[str]
    raw_markdown:    str


class SentinelState(TypedDict, total=False):
    # ── Lifecycle ──────────────────────────────────────────────
    job_id:          str
    job_status:      JobStatus
    problem_statement: str      # The raw input / alert description
    loop_count:      int        # Safety valve: max 3 Scout→Analyst loops
    error:           Optional[str]

    # ── Agent communication log ────────────────────────────────
    messages:        List[AgentMessage]

    # ── Data layers (filled progressively) ────────────────────
    evidence:        ThreatEvidence
    context:         ThreatContext
    fact_sheet:      ThreatFactSheet

    # ── Tracing hooks (Phase 3) ────────────────────────────────
    trace_spans:     List[Dict[str, Any]]
