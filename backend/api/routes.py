"""
api/routes.py
──────────────
FastAPI route definitions for Sentinel-Ops.

Phase 7 fixes:
  - API key authentication via X-API-Key header on all mutating routes.
  - Input length validation (max 5000 chars) on problem_statement.
  - Alert queue uses collections.deque with maxlen for bounded memory.
  - Health endpoint remains unauthenticated (read-only status).
"""

from __future__ import annotations
import os
from collections import deque
from fastapi import APIRouter, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from backend.core.state import JobStatus
from backend.core.job_store import job_store
from backend.adapters.sentinel import start_agent_workflow

router = APIRouter()

# ── Max input length (also enforced in sentinel.py, but belt-and-suspenders) ─
MAX_PROBLEM_LENGTH = 5000

# ── API Key authentication ─────────────────────────────────────────────────
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _verify_api_key(
    api_key: Optional[str] = Security(_api_key_header),
) -> str:
    """
    Validate the API key from the X-API-Key header.
    If SENTINEL_API_KEY is not set in the environment, authentication is
    disabled (open access) — this preserves the hackathon workflow where
    you just want to run it locally without configuring keys.
    """
    expected = os.getenv("SENTINEL_API_KEY", "").strip()
    if not expected:
        return "dev"
    if not api_key or api_key != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Set X-API-Key header.",
        )
    return api_key


# ── Request / Response schemas ─────────────────────────────────────────────
class JobSubmitRequest(BaseModel):
    problem_statement: str = Field(
        ...,
        min_length=10,
        max_length=MAX_PROBLEM_LENGTH,
        examples=["Repeated failed SSH login attempts from 192.168.1.42. 10 attempts in 60s."],
    )


class JobStatusResponse(BaseModel):
    job_id:      str
    status:      str
    error:       Optional[str] = None
    messages:    List[Any]     = []
    fact_sheet:  Optional[Dict[str, Any]] = None
    trace_spans: List[Any]     = []


class WebhookAlertRequest(BaseModel):
    """Accepts Falco/Wazuh-style alert payloads."""
    source:   str = Field(examples=["falco"])
    severity: str = Field(examples=["WARNING"])
    rule:     str = Field(examples=["Terminal shell in container"])
    output:   str = Field(max_length=MAX_PROBLEM_LENGTH, examples=["A shell was spawned in a container..."])
    fields:   Dict[str, Any] = {}


# ── Bounded alert queue (monitor.py → frontend auto-fill) ─────────────────
_alert_queue: deque[str] = deque(maxlen=100)


# ── Routes ─────────────────────────────────────────────────────────────────
@router.get("/health")
async def health() -> Dict[str, Any]:
    from backend.core.llm import validate_keys, PRIMARY_MODEL, FALLBACK_MODEL
    keys   = validate_keys()
    jobs   = job_store.all_jobs()
    counts: Dict[str, int] = {}
    for j in jobs.values():
        s = str(j.get("job_status", "unknown"))
        counts[s] = counts.get(s, 0) + 1
    return {
        "status":  "ok",
        "service": "sentinel-ops",
        "version": "0.7.0",
        "models":  {"primary": PRIMARY_MODEL, "fallback": FALLBACK_MODEL},
        "keys":    keys,
        "jobs":    {"total": len(jobs), **counts},
    }


@router.post("/jobs", status_code=202)
async def submit_job(
    body: JobSubmitRequest,
    _key: str = Depends(_verify_api_key),
) -> Dict[str, Any]:
    """
    Submit a new threat hunting job.
    Returns immediately with a job_id; client polls GET /jobs/{job_id}.
    """
    job_id = start_agent_workflow(body.problem_statement)
    return {
        "job_id":  job_id,
        "status":  JobStatus.PENDING,
        "message": "Job accepted. Poll GET /jobs/{job_id} for status.",
    }


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job(job_id: str) -> JobStatusResponse:
    """Poll job status. Returns full state once COMPLETE or FAILED."""
    state = job_store.get(job_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    return JobStatusResponse(
        job_id      = job_id,
        status      = state.get("job_status", JobStatus.PENDING),
        error       = state.get("error"),
        messages    = state.get("messages", []),
        fact_sheet  = dict(state["fact_sheet"]) if state.get("fact_sheet") else None,
        trace_spans = state.get("trace_spans", []),
    )


@router.get("/jobs")
async def list_jobs() -> List[Dict[str, Any]]:
    """Debug endpoint: list all jobs and their statuses."""
    all_jobs = job_store.all_jobs()
    return [
        {"job_id": jid, "status": s.get("job_status")}
        for jid, s in all_jobs.items()
    ]


@router.post("/queue", status_code=202)
async def push_queue(
    body: JobSubmitRequest,
    _key: str = Depends(_verify_api_key),
) -> Dict[str, Any]:
    """monitor.py pushes detected alerts here. Frontend polls and auto-submits."""
    _alert_queue.append(body.problem_statement)
    return {"queued": True, "queue_depth": len(_alert_queue)}


@router.get("/queue")
async def pop_queue() -> Dict[str, Optional[str]]:
    """Frontend polls this every 2s. Returns next alert and removes it from queue."""
    try:
        return {"alert": _alert_queue.popleft()}
    except IndexError:
        return {"alert": None}


@router.post("/webhook/alert", status_code=202)
async def webhook_alert(
    body: WebhookAlertRequest,
    _key: str = Depends(_verify_api_key),
) -> Dict[str, Any]:
    """
    Receive structured SIEM/Falco alerts.
    Converts the alert to a problem_statement and submits a job.
    """
    problem = (
        f"[{body.source.upper()} ALERT — {body.severity}] "
        f"Rule: '{body.rule}'. Output: {body.output}"
    )
    job_id = start_agent_workflow(problem)
    return {
        "job_id":  job_id,
        "status":  JobStatus.PENDING,
        "source":  body.source,
        "message": "Webhook ingested and job started.",
    }