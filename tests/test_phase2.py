"""
tests/test_phase2.py
─────────────────────
Phase 2 tests. Covers:
  1. IOC parser — IPs, hashes, CVEs, domains
  2. Anomaly score computation
  3. Search fallback (no API key → empty results, no crash)
  4. Supervisor graceful degradation (no GROQ key → still continues)
  5. Scout real IOC extraction from problem statement
  6. Full pipeline still completes end-to-end (with or without API keys)

Note: LLM-dependent tests use graceful degradation — they pass even without
GROQ_API_KEY by verifying the fallback paths work correctly.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from backend.core.ioc_parser import extract_iocs, compute_anomaly_score
from backend.core.search import search_threat_intel
from backend.core.state import SentinelState, JobStatus
from backend.agents.supervisor import supervisor_node
from backend.agents.scout import scout_node
from backend.agents.analyst import analyst_node
from backend.agents.reporter import reporter_node
from backend.graph.pipeline import sentinel_graph


# ── Fixtures ───────────────────────────────────────────────────────────────
@pytest.fixture
def base_state() -> SentinelState:
    return {
        "job_id":            "p2-test-001",
        "job_status":        JobStatus.PENDING,
        "problem_statement": (
            "SSH brute-force detected from 203.0.113.42 and 198.51.100.7. "
            "Hash d41d8cd98f00b204e9800998ecf8427e found in /tmp/evil.sh. "
            "CVE-2023-38408 may be exploited."
        ),
        "loop_count":  0,
        "messages":    [],
        "trace_spans": [],
    }


# ── Unit: IOC Parser ──────────────────────────────────────────────────────
def test_ioc_extracts_ips():
    result = extract_iocs("Attack from 203.0.113.42 and 198.51.100.7")
    assert "203.0.113.42" in result["ips"]
    assert "198.51.100.7" in result["ips"]

def test_ioc_extracts_md5():
    result = extract_iocs("File hash: d41d8cd98f00b204e9800998ecf8427e")
    assert "d41d8cd98f00b204e9800998ecf8427e" in result["hashes"]

def test_ioc_extracts_sha256():
    sha = "a" * 64
    result = extract_iocs(f"SHA256: {sha}")
    assert sha in result["hashes"]

def test_ioc_extracts_cve():
    result = extract_iocs("Exploiting CVE-2023-38408 via openssh")
    assert "CVE-2023-38408" in result["cves"]

def test_ioc_extracts_domain():
    result = extract_iocs("C2 traffic to malicious.evil.com detected")
    assert any("evil.com" in d or "malicious.evil.com" in d for d in result["domains"])

def test_ioc_no_false_positives_on_clean_text():
    result = extract_iocs("Everything looks normal today. No issues found.")
    assert result["ips"] == []
    assert result["hashes"] == []
    assert result["cves"] == []

def test_ioc_deduplicates():
    result = extract_iocs("IP 1.2.3.4 and again 1.2.3.4 and 1.2.3.4")
    assert result["ips"].count("1.2.3.4") == 1


# ── Unit: Anomaly Score ───────────────────────────────────────────────────
def test_anomaly_score_zero_for_empty():
    iocs = {"ips": [], "hashes": [], "cves": [], "domains": []}
    assert compute_anomaly_score(iocs, []) == 0.0

def test_anomaly_score_increases_with_iocs():
    iocs_none = {"ips": [],            "hashes": [], "cves": [], "domains": []}
    iocs_some = {"ips": ["1.2.3.4"],   "hashes": [], "cves": [], "domains": []}
    iocs_more = {"ips": ["1.2.3.4"],   "hashes": ["ab" * 16], "cves": ["CVE-2023-1234"], "domains": []}
    assert compute_anomaly_score(iocs_none, []) < compute_anomaly_score(iocs_some, [])
    assert compute_anomaly_score(iocs_some, []) < compute_anomaly_score(iocs_more, [])

def test_anomaly_score_capped_at_1():
    iocs = {
        "ips":     ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
        "hashes":  ["a" * 32, "b" * 64],
        "cves":    ["CVE-2023-0001", "CVE-2023-0002"],
        "domains": ["evil.com", "bad.net"],
    }
    logs = ["line"] * 20
    assert compute_anomaly_score(iocs, logs) <= 1.0


# ── Unit: Search fallback ─────────────────────────────────────────────────
def test_search_returns_empty_without_key(monkeypatch):
    """Tavily search should return [] gracefully when no API key is set."""
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    result = search_threat_intel(["192.168.1.1", "CVE-2023-1234"])
    assert result == []

def test_search_returns_list_type():
    result = search_threat_intel([])
    assert isinstance(result, list)


# ── Unit: Scout real IOC extraction ──────────────────────────────────────
def test_scout_extracts_real_ips(base_state):
    result = scout_node(base_state)
    # Should find the IPs from the problem statement
    assert "203.0.113.42" in result["evidence"]["matched_ips"] or \
           "198.51.100.7" in result["evidence"]["matched_ips"]

def test_scout_extracts_hash(base_state):
    result = scout_node(base_state)
    assert "d41d8cd98f00b204e9800998ecf8427e" in result["evidence"]["matched_hashes"]

def test_scout_anomaly_score_nonzero(base_state):
    result = scout_node(base_state)
    assert result["evidence"]["anomaly_score"] > 0.0

def test_scout_score_increases_on_loop(base_state):
    result0 = scout_node(base_state)
    base_state["loop_count"] = 1
    result1 = scout_node(base_state)
    assert result1["evidence"]["anomaly_score"] >= result0["evidence"]["anomaly_score"]


# ── Unit: Supervisor graceful degradation ─────────────────────────────────
def test_supervisor_completes_without_groq_key(base_state, monkeypatch):
    """Supervisor should not crash even if GROQ_API_KEY is missing."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    # Reset cached client
    import backend.core.llm as llm_module
    llm_module._client = None
    result = supervisor_node(base_state)
    # Should still set status to RUNNING (graceful degradation)
    assert result["job_status"] == JobStatus.RUNNING
    assert len(result["messages"]) >= 1

def test_supervisor_empty_problem_fails(base_state):
    base_state["problem_statement"] = "   "
    result = supervisor_node(base_state)
    assert result["job_status"] == JobStatus.FAILED


# ── Integration: Full pipeline with real IOCs ─────────────────────────────
def test_full_pipeline_with_real_iocs():
    """
    End-to-end test with a realistic alert containing real IOCs.
    Works with or without GROQ_API_KEY (graceful degradation throughout).
    """
    state: SentinelState = {
        "job_id":            "p2-integration-001",
        "job_status":        JobStatus.PENDING,
        "problem_statement": (
            "Ransomware activity detected. Host 10.0.0.5 connecting to C2 at "
            "185.220.101.47. Suspicious file hash: "
            "3c4b2a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b. "
            "CVE-2023-44487 (HTTP/2 Rapid Reset) may be involved."
        ),
        "loop_count":  0,
        "messages":    [],
        "trace_spans": [],
    }
    final = sentinel_graph.invoke(state)

    assert final["job_status"] == JobStatus.COMPLETE
    assert "fact_sheet" in final
    assert final["fact_sheet"]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert len(final["messages"]) >= 4
    # Scout should have found the IP
    evidence = final.get("evidence", {})
    assert "185.220.101.47" in evidence.get("matched_ips", []) or \
           "10.0.0.5" in evidence.get("matched_ips", [])

def test_pipeline_with_cve_in_alert():
    state: SentinelState = {
        "job_id":            "p2-cve-test",
        "job_status":        JobStatus.PENDING,
        "problem_statement": "Log4Shell exploitation attempt detected. CVE-2021-44228 payload in User-Agent header from 45.33.32.156.",
        "loop_count":  0,
        "messages":    [],
        "trace_spans": [],
    }
    final = sentinel_graph.invoke(state)
    assert final["job_status"] == JobStatus.COMPLETE
    evidence = final.get("evidence", {})
    assert "45.33.32.156" in evidence.get("matched_ips", [])
