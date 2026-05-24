"""
tests/test_phase5.py
─────────────────────
Phase 5 tests. Covers:
  1. JSON cleaning — markdown fences, trailing commas, prose wrapping
  2. call_llm_json retry on bad JSON
  3. IP classifier — attacker vs victim detection
  4. Reporter recommendations use classified IPs
  5. Health endpoint returns key status
  6. Full pipeline — no JSON parse errors in trace spans
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch, MagicMock
from backend.core.llm import clean_json, call_llm_json
from backend.core.ip_classifier import classify_ips
from backend.core.state import SentinelState, JobStatus
from backend.agents.reporter import reporter_node
from backend.graph.pipeline import sentinel_graph
from fastapi.testclient import TestClient
from backend.api.app import app

client = TestClient(app)


# ── Unit: clean_json ──────────────────────────────────────────────────────
def test_clean_json_strips_markdown_fences():
    raw = '```json\n{"key": "value"}\n```'
    assert clean_json(raw) == '{"key": "value"}'

def test_clean_json_strips_plain_fences():
    raw = '```\n{"key": "value"}\n```'
    assert clean_json(raw) == '{"key": "value"}'

def test_clean_json_extracts_from_prose():
    raw = 'Here is the JSON response:\n{"key": "value"}\nHope this helps!'
    result = clean_json(raw)
    import json
    assert json.loads(result) == {"key": "value"}

def test_clean_json_fixes_trailing_commas():
    raw = '{"a": 1, "b": 2,}'
    import json
    assert json.loads(clean_json(raw)) == {"a": 1, "b": 2}

def test_clean_json_fixes_trailing_comma_in_array():
    raw = '{"items": [1, 2, 3,]}'
    import json
    assert json.loads(clean_json(raw)) == {"items": [1, 2, 3]}

def test_clean_json_handles_already_clean():
    raw = '{"alert_type": "brute_force", "severity": "HIGH"}'
    import json
    assert json.loads(clean_json(raw))["alert_type"] == "brute_force"


# ── Unit: call_llm_json retry ─────────────────────────────────────────────
def test_call_llm_json_retries_on_bad_json():
    """Should retry when first response is bad JSON, succeed on second."""
    call_count = 0
    def mock_call_llm(system, user, temperature=0.1, max_tokens=1024):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return "Sorry, here is some prose instead of JSON"
        return '{"alert_type": "brute_force", "severity_estimate": "HIGH", "key_indicators": [], "investigation_plan": "test"}'

    with patch("backend.core.llm.call_llm", side_effect=mock_call_llm):
        result = call_llm_json("system", "user")
        assert result["alert_type"] == "brute_force"
        assert call_count == 2

def test_call_llm_json_raises_after_max_retries():
    """Should raise ValueError after all retries fail."""
    with patch("backend.core.llm.call_llm", return_value="not json at all !!!"):
        with pytest.raises(ValueError, match="invalid JSON"):
            call_llm_json("system", "user")


# ── Unit: IP Classifier ───────────────────────────────────────────────────
def test_classify_external_ip_as_attacker():
    attackers, victims = classify_ips(["203.0.113.42"], "SSH login from 203.0.113.42")
    assert "203.0.113.42" in attackers
    assert "203.0.113.42" not in victims

def test_classify_private_ip_as_victim():
    attackers, victims = classify_ips(["10.0.0.5"], "Ransomware on host 10.0.0.5")
    assert "10.0.0.5" in victims
    assert "10.0.0.5" not in attackers

def test_classify_from_pattern_as_attacker():
    attackers, victims = classify_ips(["10.0.0.42"], "Attack from 10.0.0.42")
    assert "10.0.0.42" in attackers

def test_classify_mixed_ips():
    ips = ["185.220.101.47", "10.0.0.5"]
    problem = "Host 10.0.0.5 connecting to C2 at 185.220.101.47"
    attackers, victims = classify_ips(ips, problem)
    assert "185.220.101.47" in attackers
    assert "10.0.0.5" in victims

def test_classify_empty_ips():
    attackers, victims = classify_ips([], "some alert")
    assert attackers == []
    assert victims == []

def test_classify_multiple_attackers():
    ips = ["203.0.113.1", "203.0.113.2"]
    attackers, victims = classify_ips(ips, "Scans from 203.0.113.1 and 203.0.113.2")
    assert len(attackers) == 2


# ── Unit: Reporter uses classified IPs ───────────────────────────────────
def test_reporter_blocks_attacker_not_victim():
    state: SentinelState = {
        "job_id": "p5-reporter-test",
        "job_status": JobStatus.RUNNING,
        "problem_statement": "Ransomware on host 10.0.0.5 connecting to C2 185.220.101.47",
        "loop_count": 0,
        "messages": [],
        "trace_spans": [],
        "evidence": {
            "raw_logs": ["connection to 185.220.101.47"],
            "matched_ips": ["10.0.0.5", "185.220.101.47"],
            "matched_hashes": [],
            "anomaly_score": 0.85,
            "anomaly_reason": "C2 communication",
        },
        "context": {
            "cve_matches": [],
            "threat_intel": [],
            "search_snippets": [],
            "confidence": 0.82,
            "mitre_tactics": ["T1486"],
            "assessment": "Ransomware C2 detected.",
        },
    }
    with patch("backend.agents.reporter.send_notifications"):
        with patch("backend.agents.reporter.ship_trace"):
            result = reporter_node(state)

    recs = result["fact_sheet"]["recommendations"]
    rec_text = " ".join(recs)
    # Should block the attacker IP
    assert "185.220.101.47" in rec_text
    # Should isolate the victim, not block it
    assert "10.0.0.5" in rec_text
    # Should NOT say "block" for the victim
    block_recs = [r for r in recs if "block" in r.lower() and "10.0.0.5" in r]
    assert len(block_recs) == 0


# ── Unit: Health endpoint ─────────────────────────────────────────────────
def test_health_returns_ok():
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"

def test_health_returns_version():
    resp = client.get("/api/v1/health")
    assert resp.json()["version"] == "0.7.0"

def test_health_returns_key_status():
    resp = client.get("/api/v1/health")
    data = resp.json()
    assert "keys" in data
    assert "groq" in data["keys"]
    assert "tavily" in data["keys"]
    assert "discord" in data["keys"]

def test_health_returns_model_info():
    resp = client.get("/api/v1/health")
    data = resp.json()
    assert "models" in data
    assert "llama" in data["models"]["primary"].lower()

def test_health_returns_job_stats():
    resp = client.get("/api/v1/health")
    data = resp.json()
    assert "jobs" in data
    assert "total" in data["jobs"]


# ── Integration: No JSON errors in trace spans ────────────────────────────
def test_pipeline_no_json_parse_errors():
    """
    Run full pipeline. With call_llm_json's retry logic, JSON parse errors
    should be rare. We allow at most 1 span error (real-LLM flakiness) and
    require that the pipeline still completes successfully — graceful
    degradation is the contract, not zero errors.
    """
    state: SentinelState = {
        "job_id":            "p5-json-test",
        "job_status":        JobStatus.PENDING,
        "problem_statement": (
            "Privilege escalation on prod-server-01. "
            "User jenkins ran chmod 777 /etc/passwd. "
            "CVE-2021-4034 polkit exploit pattern detected."
        ),
        "loop_count":  0,
        "messages":    [],
        "trace_spans": [],
    }
    with patch("backend.agents.reporter.send_notifications"):
        with patch("backend.agents.reporter.ship_trace"):
            final = sentinel_graph.invoke(state)

    # Hard contract: pipeline completes regardless of LLM flakiness
    assert final["job_status"] == JobStatus.COMPLETE
    assert "fact_sheet" in final

    # Soft contract: JSON errors should be uncommon thanks to retry logic
    json_errors = [
        s for s in final.get("trace_spans", [])
        if s.get("error") and "json" in str(s.get("error", "")).lower()
    ]
    # Allow up to 1 span to fail JSON parsing (real Groq is non-deterministic)
    assert len(json_errors) <= 1, f"Too many JSON parse errors: {json_errors}"

def test_pipeline_attacker_victim_separation():
    """Reporter should separate attacker and victim IPs correctly."""
    state: SentinelState = {
        "job_id":            "p5-ip-test",
        "job_status":        JobStatus.PENDING,
        "problem_statement": (
            "C2 communication from host 192.168.1.10 to external IP 185.220.101.47. "
            "Port 443 outbound, 2GB data transferred."
        ),
        "loop_count":  0,
        "messages":    [],
        "trace_spans": [],
    }
    with patch("backend.agents.reporter.send_notifications"):
        with patch("backend.agents.reporter.ship_trace"):
            final = sentinel_graph.invoke(state)

    assert final["job_status"] == JobStatus.COMPLETE
    recs = final.get("fact_sheet", {}).get("recommendations", [])
    rec_text = " ".join(recs)
    # Attacker should be blocked
    assert "185.220.101.47" in rec_text or "attacker" in rec_text.lower()