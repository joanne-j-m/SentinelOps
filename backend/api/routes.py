"""
api/routes.py
──────────────
FastAPI route definitions for Sentinel-Ops.

Endpoints:
  POST /jobs              → Submit a threat hunting job
  GET  /jobs/{job_id}     → Poll job status + result
  GET  /jobs              → List all jobs (debug)
  POST /webhook/alert     → Ingest a structured SIEM/Falco webhook (Phase 2)
  GET  /health            → Health check

Design assumption: Auth/rate-limiting not added in Phase 1 (hackathon speed).
Phase 5 will add API key middleware.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from backend.core.state import JobStatus
from backend.core.job_store import job_store
from backend.adapters.sentinel import start_agent_workflow

router = APIRouter()


# ── Request / Response schemas ─────────────────────────────────────────────
class JobSubmitRequest(BaseModel):
    problem_statement: str = Field(
        ...,
        min_length=10,
        example="Repeated failed SSH login attempts from 192.168.1.42. 10 attempts in 60s.",
    )


class JobStatusResponse(BaseModel):
    job_id:     str
    status:     str
    error:      Optional[str] = None
    messages:   list          = []
    fact_sheet: Optional[Dict[str, Any]] = None
    trace_spans: list         = []


class WebhookAlertRequest(BaseModel):
    """Stub for Phase 2: accepts Falco/Wazuh-style alert payloads."""
    source:    str = Field(example="falco")
    severity:  str = Field(example="WARNING")
    rule:      str = Field(example="Terminal shell in container")
    output:    str = Field(example="A shell was spawned in a container...")
    fields:    Dict[str, Any] = {}


# ── Routes ─────────────────────────────────────────────────────────────────
@router.get("/health")
async def health():
    from backend.core.llm import validate_keys, PRIMARY_MODEL, FALLBACK_MODEL
    from backend.core.job_store import job_store
    keys   = validate_keys()
    jobs   = job_store.all_jobs()
    counts = {}
    for j in jobs.values():
        s = str(j.get("job_status", "unknown"))
        counts[s] = counts.get(s, 0) + 1
    return {
        "status":  "ok",
        "service": "sentinel-ops",
        "version": "0.5.0",
        "models":  {"primary": PRIMARY_MODEL, "fallback": FALLBACK_MODEL},
        "keys":    keys,
        "jobs":    {"total": len(jobs), **counts},
    }


@router.post("/jobs", status_code=202)
async def submit_job(body: JobSubmitRequest):
    """
    Submit a new threat hunting job.
    Returns immediately with a job_id; client polls GET /jobs/{job_id}.
    The graph runs asynchronously in a background thread.
    """
    job_id = start_agent_workflow(body.problem_statement)
    return {
        "job_id": job_id,
        "status": JobStatus.PENDING,
        "message": "Job accepted. Poll GET /jobs/{job_id} for status.",
    }


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job(job_id: str):
    """
    Poll job status. Returns full state once COMPLETE or FAILED.
    """
    state = job_store.get(job_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    return JobStatusResponse(
        job_id      = job_id,
        status      = state.get("job_status", JobStatus.PENDING),
        error       = state.get("error"),
        messages    = state.get("messages", []),
        fact_sheet  = state.get("fact_sheet"),
        trace_spans = state.get("trace_spans", []),
    )


@router.get("/jobs")
async def list_jobs():
    """Debug endpoint: list all jobs and their statuses."""
    all_jobs = job_store.all_jobs()
    return [
        {"job_id": jid, "status": s.get("job_status")}
        for jid, s in all_jobs.items()
    ]


@router.post("/webhook/alert", status_code=202)
async def webhook_alert(body: WebhookAlertRequest):
    """
    Phase 2 stub: receive structured SIEM/Falco alerts.
    Currently converts the alert to a problem_statement and submits a job.
    """
    problem = (
        f"[{body.source.upper()} ALERT — {body.severity}] "
        f"Rule: '{body.rule}'. Output: {body.output}"
    )
    job_id = start_agent_workflow(problem)
    return {
        "job_id": job_id,
        "status": JobStatus.PENDING,
        "source": body.source,
        "message": "Webhook ingested and job started.",
    }
