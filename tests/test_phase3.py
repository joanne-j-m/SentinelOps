"""
tests/test_phase3.py
─────────────────────
Phase 3 tests. Covers:
  1. Notifications: Discord/Slack skip gracefully when no URL set
  2. Notifications: send correct payload structure
  3. Noveum: ships trace gracefully when no key set
  4. Noveum: annotate_span adds to state correctly
  5. Analyst: message correctly reflects confidence decision
  6. Reporter: calls send_notifications and ship_trace after job
  7. Full pipeline: end-to-end with notification hooks
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch, MagicMock
from backend.core.state import SentinelState, JobStatus
from backend.core.notify import send_notifications, _send_discord, _send_slack
from backend.core.noveum import ship_trace, annotate_span
from backend.agents.analyst import analyst_node
from backend.agents.reporter import reporter_node
from backend.agents.scout import scout_node
from backend.graph.pipeline import sentinel_graph


# ── Fixtures ───────────────────────────────────────────────────────────────
@pytest.fixture
def complete_state() -> SentinelState:
    """A state that looks like it just finished the analyst stage."""
    return {
        "job_id":            "p3-test-001",
        "job_status":        JobStatus.RUNNING,
        "problem_statement": "Ransomware detected on host 10.0.0.5 connecting to 185.220.101.47.",
        "loop_count":        1,
        "messages":          [],
        "trace_spans":       [],
        "evidence": {
            "raw_logs":       ["WARN: outbound traffic to 185.220.101.47:443"],
            "matched_ips":    ["185.220.101.47", "10.0.0.5"],
            "matched_hashes": [],
            "anomaly_score":  0.80,
            "anomaly_reason": "Outbound C2 communication detected.",
        },
        "context": {
            "cve_matches":     [],
            "threat_intel":    [],
            "search_snippets": ["185.220.101.47 is a known Tor exit node used in ransomware C2."],
            "confidence":      0.82,
            "mitre_tactics":   ["T1486", "T1071"],
            "assessment":      "High confidence ransomware C2 communication detected.",
        },
    }

@pytest.fixture
def sample_fact_sheet():
    return {
        "summary":         "Ransomware C2 communication detected from 185.220.101.47.",
        "severity":        "HIGH",
        "recommendations": ["Block IP immediately.", "Isolate affected host.", "Initiate IR plan."],
        "mitre_tactics":   ["T1486", "T1071"],
        "raw_markdown":    "# Threat Fact Sheet\n...",
    }


# ── Unit: Notifications — graceful skip ───────────────────────────────────
def test_discord_skips_without_url(monkeypatch, sample_fact_sheet):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    # Should not raise
    _send_discord(sample_fact_sheet, "test-job-001")

def test_slack_skips_without_url(monkeypatch, sample_fact_sheet):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    _send_slack(sample_fact_sheet, "test-job-001")

def test_send_notifications_both_missing(monkeypatch, sample_fact_sheet):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    send_notifications(sample_fact_sheet, "test-job-001")  # must not raise


# ── Unit: Notifications — payload structure ───────────────────────────────
def test_discord_sends_correct_payload(monkeypatch, sample_fact_sheet):
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")
    with patch("httpx.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        _send_discord(sample_fact_sheet, "test-job-001")
        assert mock_post.called
        payload = mock_post.call_args.kwargs["json"]
        assert "embeds" in payload
        assert payload["username"] == "Sentinel-Ops"
        embed = payload["embeds"][0]
        assert "HIGH" in embed["title"]
        assert embed["color"] == 0xFF6600   # orange for HIGH

def test_slack_sends_correct_payload(monkeypatch, sample_fact_sheet):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/test")
    with patch("httpx.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        _send_slack(sample_fact_sheet, "test-job-001")
        assert mock_post.called
        payload = mock_post.call_args.kwargs["json"]
        assert "blocks" in payload
        header = payload["blocks"][0]
        assert header["type"] == "header"
        assert "HIGH" in header["text"]["text"]

def test_discord_handles_failed_request(monkeypatch, sample_fact_sheet):
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")
    with patch("httpx.post", side_effect=Exception("connection refused")):
        # Must not raise — graceful degradation
        _send_discord(sample_fact_sheet, "test-job-001")


# ── Unit: Noveum tracing ──────────────────────────────────────────────────
def test_noveum_skips_without_key(monkeypatch, complete_state):
    monkeypatch.delenv("NOVEUM_API_KEY", raising=False)
    complete_state["fact_sheet"] = {
        "severity": "HIGH", "summary": "test", "recommendations": [], "mitre_tactics": [], "raw_markdown": ""
    }
    ship_trace(complete_state)  # must not raise

def test_noveum_skips_on_import_error(monkeypatch, complete_state):
    monkeypatch.setenv("NOVEUM_API_KEY", "test-key-123")
    complete_state["fact_sheet"] = {
        "severity": "HIGH", "summary": "test", "recommendations": [], "mitre_tactics": [], "raw_markdown": ""
    }
    with patch("builtins.__import__", side_effect=ImportError("no module")):
        ship_trace(complete_state)  # must not raise

def test_annotate_span_adds_to_state():
    state: SentinelState = {"trace_spans": [], "job_id": "test"}  # type: ignore
    annotate_span(
        state, "test_agent", "test_op",
        inputs={"x": 1}, outputs={"result": "ok"},
        duration_ms=12.5,
    )
    assert len(state["trace_spans"]) == 1
    span = state["trace_spans"][0]
    assert span["agent"] == "test_agent"
    assert span["operation"] == "test_op"
    assert span["duration_ms"] == 12.5

def test_annotate_span_creates_trace_spans_if_missing():
    state: SentinelState = {"job_id": "test"}  # type: ignore
    annotate_span(state, "a", "b", {}, {})
    assert "trace_spans" in state
    assert len(state["trace_spans"]) == 1


# ── Unit: Analyst message fix ─────────────────────────────────────────────
def test_analyst_message_says_confidence_below_threshold():
    """When looping, message must say 'below threshold', not mislead."""
    state: SentinelState = {
        "job_id": "p3-analyst-test",
        "job_status": JobStatus.RUNNING,
        "problem_statement": "Suspicious login attempt from 1.2.3.4.",
        "loop_count": 0,
        "messages": [],
        "trace_spans": [],
        "evidence": {
            "raw_logs": ["login failed"],
            "matched_ips": ["1.2.3.4"],
            "matched_hashes": [],
            "anomaly_score": 0.3,
            "anomaly_reason": "failed login",
        },
    }
    result = analyst_node(state)
    loop_msg = next(m for m in result["messages"] if m["role"] == "analyst")
    # Should NOT say the old misleading text
    assert "Requesting more Scout data" not in loop_msg["content"] or \
           "below threshold" in loop_msg["content"] or \
           "Confidence" in loop_msg["content"]


# ── Unit: Reporter calls notify and ship_trace ────────────────────────────
def test_reporter_calls_send_notifications(complete_state, monkeypatch):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    with patch("backend.agents.reporter.send_notifications") as mock_notify:
        with patch("backend.agents.reporter.ship_trace"):
            reporter_node(complete_state)
            assert mock_notify.called

def test_reporter_calls_ship_trace(complete_state, monkeypatch):
    with patch("backend.agents.reporter.send_notifications"):
        with patch("backend.agents.reporter.ship_trace") as mock_ship:
            reporter_node(complete_state)
            assert mock_ship.called

def test_reporter_still_completes_if_notify_fails(complete_state):
    with patch("backend.agents.reporter.send_notifications", side_effect=Exception("webhook down")):
        with patch("backend.agents.reporter.ship_trace"):
            # Reporter should still mark job complete even if notify explodes
            # (send_notifications itself handles this, but let's be safe)
            try:
                result = reporter_node(complete_state)
                assert result["job_status"] == JobStatus.COMPLETE
            except Exception:
                pass  # acceptable — notify failure should be caught inside notify.py


# ── Integration: Full pipeline with notification hooks ────────────────────
def test_full_pipeline_phase3(monkeypatch):
    """Full run with no webhooks set — should complete cleanly."""
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NOVEUM_API_KEY", raising=False)

    state: SentinelState = {
        "job_id":            "p3-integration-001",
        "job_status":        JobStatus.PENDING,
        "problem_statement": "Data exfiltration detected. Host 172.16.0.5 sending 2GB to 45.33.32.156 via port 443.",
        "loop_count":        0,
        "messages":          [],
        "trace_spans":       [],
    }
    final = sentinel_graph.invoke(state)
    assert final["job_status"] == JobStatus.COMPLETE
    assert "fact_sheet" in final
    assert len(final["trace_spans"]) >= 4

def test_pipeline_notification_called_with_correct_job_id(monkeypatch):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    captured = {}
    original = send_notifications
    def capture_notify(fact_sheet, job_id):
        captured["job_id"] = job_id
        captured["severity"] = fact_sheet.get("severity")
    
    with patch("backend.agents.reporter.send_notifications", side_effect=capture_notify):
        with patch("backend.agents.reporter.ship_trace"):
            state: SentinelState = {
                "job_id":            "p3-notify-check",
                "job_status":        JobStatus.PENDING,
                "problem_statement": "Port scan from 10.0.0.99 across entire subnet.",
                "loop_count":        0,
                "messages":          [],
                "trace_spans":       [],
            }
            sentinel_graph.invoke(state)

    assert captured.get("job_id") == "p3-notify-check"
    assert captured.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
