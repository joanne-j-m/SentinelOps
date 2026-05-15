"""
tests/test_phase1.py
─────────────────────
Phase 1 test suite. Tests:
  1. State schema construction
  2. Individual agent nodes (unit tests)
  3. Full graph run via SentinelAdapter (integration test)
  4. Loop behaviour: analyst triggers scout re-run
  5. FastAPI endpoint smoke tests

Run with:
    cd sentinel-ops
    python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from backend.core.state import SentinelState, JobStatus
from backend.agents.supervisor import supervisor_node
from backend.agents.scout import scout_node
from backend.agents.analyst import analyst_node
from backend.agents.reporter import reporter_node
from backend.graph.pipeline import sentinel_graph, route_after_analyst
from backend.adapters.sentinel import SentinelAdapter, start_agent_workflow, poll_until_complete
from backend.core.job_store import job_store


# ── Fixtures ───────────────────────────────────────────────────────────────
@pytest.fixture
def base_state() -> SentinelState:
    return {
        "job_id":            "test-001",
        "job_status":        JobStatus.PENDING,
        "problem_statement": "SSH brute-force detected from 10.0.0.5, 9 failed logins.",
        "loop_count":        0,
        "messages":          [],
        "trace_spans":       [],
    }


# ── Unit: Supervisor ───────────────────────────────────────────────────────
def test_supervisor_sets_running_status(base_state):
    result = supervisor_node(base_state)
    assert result["job_status"] == JobStatus.RUNNING

def test_supervisor_fails_on_empty_problem(base_state):
    base_state["problem_statement"] = "   "
    result = supervisor_node(base_state)
    assert result["job_status"] == JobStatus.FAILED
    assert result["error"] is not None

def test_supervisor_adds_message(base_state):
    result = supervisor_node(base_state)
    assert len(result["messages"]) >= 1
    assert result["messages"][-1]["role"] == "supervisor"


# ── Unit: Scout ───────────────────────────────────────────────────────────
def test_scout_populates_evidence(base_state):
    result = scout_node(base_state)
    assert "evidence" in result
    assert len(result["evidence"]["matched_ips"]) > 0
    assert result["evidence"]["anomaly_score"] > 0

def test_scout_adds_message(base_state):
    result = scout_node(base_state)
    roles = [m["role"] for m in result["messages"]]
    assert "scout" in roles


# ── Unit: Analyst ─────────────────────────────────────────────────────────
def test_analyst_populates_context(base_state):
    base_state = scout_node(base_state)
    result = analyst_node(base_state)
    assert "context" in result
    assert "confidence" in result["context"]

def test_analyst_triggers_loop_on_low_confidence(base_state):
    """Verify the loop mechanism: when confidence < threshold, loop_count increments.
    With real LLM calls confidence varies, so we accept either path as long as it's consistent."""
    base_state = scout_node(base_state)
    result = analyst_node(base_state)
    confidence = result["context"]["confidence"]
    if confidence < 0.6:
        assert result["loop_count"] == 1
        assert result["job_status"] == JobStatus.LOOPING
    else:
        # High confidence is also valid behaviour from a real LLM
        assert result["loop_count"] == 0
        assert result["job_status"] != JobStatus.LOOPING

def test_analyst_no_loop_on_second_pass(base_state):
    """At MAX_LOOPS the graph must NOT loop regardless of confidence."""
    base_state["loop_count"] = 3       # At MAX_LOOPS ceiling
    base_state = scout_node(base_state)
    result = analyst_node(base_state)
    # Once loop_count >= MAX_LOOPS the analyst must not trigger another loop
    assert result["job_status"] != JobStatus.LOOPING


# ── Unit: Reporter ────────────────────────────────────────────────────────
def test_reporter_produces_fact_sheet(base_state):
    state = scout_node(base_state)
    state["loop_count"] = 1   # Skip loop so analyst gives high confidence
    state = analyst_node(state)
    result = reporter_node(state)
    assert "fact_sheet" in result
    assert result["fact_sheet"]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "raw_markdown" in result["fact_sheet"]

def test_reporter_marks_complete(base_state):
    state = scout_node(base_state)
    state["loop_count"] = 1
    state = analyst_node(state)
    result = reporter_node(state)
    assert result["job_status"] == JobStatus.COMPLETE


# ── Unit: Router ──────────────────────────────────────────────────────────
def test_route_loops_on_low_confidence():
    state: SentinelState = {
        "context": {"confidence": 0.3},
        "loop_count": 0,
        "job_status": JobStatus.RUNNING,
    }
    assert route_after_analyst(state) == "scout"

def test_route_proceeds_on_high_confidence():
    state: SentinelState = {
        "context": {"confidence": 0.9},
        "loop_count": 0,
        "job_status": JobStatus.RUNNING,
    }
    assert route_after_analyst(state) == "reporter"

def test_route_stops_looping_at_max():
    state: SentinelState = {
        "context": {"confidence": 0.3},
        "loop_count": 3,   # MAX_LOOPS reached
        "job_status": JobStatus.RUNNING,
    }
    assert route_after_analyst(state) == "reporter"


# ── Integration: Full graph run ───────────────────────────────────────────
def test_full_graph_run_completes():
    problem = "Suspicious outbound traffic from host 10.1.2.3 to known C2 IP 185.220.101.5"
    final_state = sentinel_graph.invoke({
        "job_id":            "integration-001",
        "job_status":        JobStatus.PENDING,
        "problem_statement": problem,
        "loop_count":        0,
        "messages":          [],
        "trace_spans":       [],
    })
    assert final_state["job_status"] == JobStatus.COMPLETE
    assert "fact_sheet" in final_state
    assert len(final_state["messages"]) >= 4   # supervisor + scout + analyst + reporter
    assert len(final_state["trace_spans"]) >= 4


# ── Integration: SentinelAdapter ─────────────────────────────────────────
def test_sentinel_adapter_execute_task():
    adapter = SentinelAdapter()
    result = adapter.execute_task(
        "Multiple failed login attempts on admin panel from IP 203.0.113.42"
    )
    assert result["job_status"] == JobStatus.COMPLETE
    assert result["fact_sheet"]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ── Integration: Job store + async polling ────────────────────────────────
def test_async_job_lifecycle():
    job_id = start_agent_workflow("Ransomware detected on host WIN-DC-01")
    result = poll_until_complete(job_id, timeout_seconds=180)
    assert result["job_status"] == JobStatus.COMPLETE
    assert result["job_id"] == job_id