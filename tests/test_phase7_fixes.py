"""
tests/test_phase7_fixes.py
───────────────────────────
Tests for all Phase 7 security, correctness, and maintainability fixes.

Run with:
    cd sentinel-ops
    python -m pytest tests/test_phase7_fixes.py -v
"""

from __future__ import annotations
import sys
import os
import json
import threading
import time
from typing import Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.api.app import app
from backend.core.state import SentinelState, JobStatus, ThreatContext
from backend.core.job_store import JobStore
from backend.core.llm import clean_json
from backend.adapters.sentinel import sanitize_input, MAX_PROBLEM_LENGTH

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════
# 1. API Key Authentication
# ═══════════════════════════════════════════════════════════════════════════

class TestAPIKeyAuth:
    """Mutating endpoints require X-API-Key when SENTINEL_API_KEY is set."""

    def test_submit_job_rejected_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        resp = client.post(
            "/api/v1/jobs",
            json={"problem_statement": "SSH brute force from 1.2.3.4, 10 failed logins"},
        )
        assert resp.status_code == 401

    def test_submit_job_rejected_with_wrong_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        resp = client.post(
            "/api/v1/jobs",
            json={"problem_statement": "SSH brute force from 1.2.3.4, 10 failed logins"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_submit_job_accepted_with_correct_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        with patch("backend.api.routes.start_agent_workflow", return_value="fake-id"):
            resp = client.post(
                "/api/v1/jobs",
                json={"problem_statement": "SSH brute force from 1.2.3.4, 10 failed logins"},
                headers={"X-API-Key": "test-secret-key-123"},
            )
        assert resp.status_code == 202

    def test_open_access_when_no_key_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
        with patch("backend.api.routes.start_agent_workflow", return_value="fake-id"):
            resp = client.post(
                "/api/v1/jobs",
                json={"problem_statement": "SSH brute force from 1.2.3.4, 10 failed logins"},
            )
        assert resp.status_code == 202

    def test_health_endpoint_never_requires_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_get_jobs_never_requires_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        resp = client.get("/api/v1/jobs")
        assert resp.status_code == 200

    def test_webhook_requires_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        resp = client.post(
            "/api/v1/webhook/alert",
            json={
                "source": "falco",
                "severity": "WARNING",
                "rule": "Shell in container",
                "output": "A shell was spawned",
            },
        )
        assert resp.status_code == 401

    def test_queue_push_requires_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_API_KEY", "test-secret-key-123")
        resp = client.post(
            "/api/v1/queue",
            json={"problem_statement": "SQL injection from 1.2.3.4 on /login endpoint"},
        )
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# 2. Input Sanitization
# ═══════════════════════════════════════════════════════════════════════════

class TestInputSanitization:
    """problem_statement is sanitized before entering the pipeline."""

    def test_control_characters_stripped(self) -> None:
        dirty = "Alert\x00 from \x07server\x1b[31m with \x0bweird chars"
        clean = sanitize_input(dirty)
        assert "\x00" not in clean
        assert "\x07" not in clean
        assert "\x1b" not in clean
        assert "\x0b" not in clean
        assert "Alert" in clean
        assert "server" in clean

    def test_newlines_and_tabs_preserved(self) -> None:
        text = "Line 1\nLine 2\tTabbed"
        clean = sanitize_input(text)
        assert "\n" in clean
        assert "\t" in clean

    def test_truncation_at_max_length(self) -> None:
        long_input = "A" * (MAX_PROBLEM_LENGTH + 500)
        clean = sanitize_input(long_input)
        assert len(clean) == MAX_PROBLEM_LENGTH

    def test_whitespace_stripped(self) -> None:
        text = "   some alert text   "
        clean = sanitize_input(text)
        assert clean == "some alert text"

    def test_pydantic_rejects_too_short(self) -> None:
        resp = client.post(
            "/api/v1/jobs",
            json={"problem_statement": "short"},
        )
        assert resp.status_code == 422

    def test_pydantic_rejects_too_long(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
        resp = client.post(
            "/api/v1/jobs",
            json={"problem_statement": "A" * (MAX_PROBLEM_LENGTH + 1)},
        )
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
# 3. Bounded Alert Queue
# ═══════════════════════════════════════════════════════════════════════════

class TestAlertQueue:
    """Alert queue is bounded and uses deque for O(1) popleft."""

    def test_queue_round_trip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
        client.post(
            "/api/v1/queue",
            json={"problem_statement": "Test alert from scanner for queue verification"},
        )
        resp = client.get("/api/v1/queue")
        assert resp.json()["alert"] is not None

    def test_empty_queue_returns_none(self) -> None:
        # Drain the queue first
        while client.get("/api/v1/queue").json()["alert"] is not None:
            pass
        resp = client.get("/api/v1/queue")
        assert resp.json()["alert"] is None


# ═══════════════════════════════════════════════════════════════════════════
# 4. Thread-safe Job Store
# ═══════════════════════════════════════════════════════════════════════════

class TestJobStoreSafety:
    """JobStore returns deep copies to prevent cross-thread mutation."""

    def test_get_returns_independent_copy(self) -> None:
        store = JobStore()
        state: SentinelState = {
            "job_id": "copy-test",
            "job_status": JobStatus.PENDING,
            "messages": [{"role": "test", "content": "hello", "timestamp": "now"}],
        }
        store.create("copy-test", state)

        copy1 = store.get("copy-test")
        assert copy1 is not None
        copy1.setdefault("messages", []).append(
            {"role": "test", "content": "mutated", "timestamp": "now"}
        )

        copy2 = store.get("copy-test")
        assert copy2 is not None
        assert len(copy2.get("messages", [])) == 1

    def test_create_stores_independent_copy(self) -> None:
        store = JobStore()
        msgs: List[Any] = []
        state: SentinelState = {
            "job_id": "create-test",
            "job_status": JobStatus.PENDING,
            "messages": msgs,
        }
        store.create("create-test", state)

        # Mutate the original
        msgs.append({"role": "test", "content": "after", "timestamp": "now"})

        stored = store.get("create-test")
        assert stored is not None
        assert len(stored.get("messages", [])) == 0

    def test_concurrent_updates_dont_corrupt(self) -> None:
        store = JobStore()
        store.create("conc-test", {
            "job_id": "conc-test",
            "job_status": JobStatus.PENDING,
            "loop_count": 0,
            "messages": [],
        })

        errors: List[Exception] = []

        def updater(n: int) -> None:
            try:
                for i in range(50):
                    store.update("conc-test", {"loop_count": n * 100 + i})
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=updater, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        result = store.get("conc-test")
        assert result is not None
        assert isinstance(result.get("loop_count"), int)


# ═══════════════════════════════════════════════════════════════════════════
# 5. Improved clean_json
# ═══════════════════════════════════════════════════════════════════════════

class TestCleanJsonBracketBalanced:
    """Bracket-balanced JSON extraction handles edge cases the greedy regex missed."""

    def test_basic_extraction(self) -> None:
        raw = '```json\n{"key": "value"}\n```'
        assert json.loads(clean_json(raw)) == {"key": "value"}

    def test_prose_around_json(self) -> None:
        raw = 'Here is the result:\n{"key": "value"}\nHope this helps!'
        assert json.loads(clean_json(raw)) == {"key": "value"}

    def test_two_json_objects_takes_first(self) -> None:
        raw = 'First: {"a": 1} and also second: {"b": 2}'
        result = json.loads(clean_json(raw))
        assert result == {"a": 1}

    def test_nested_braces(self) -> None:
        raw = '{"outer": {"inner": "value"}, "key": "test"}'
        result = json.loads(clean_json(raw))
        assert result["outer"]["inner"] == "value"

    def test_braces_inside_strings(self) -> None:
        raw = '{"msg": "use {placeholder} here", "ok": true}'
        result = json.loads(clean_json(raw))
        assert result["msg"] == "use {placeholder} here"

    def test_trailing_commas_fixed(self) -> None:
        raw = '{"a": 1, "b": 2,}'
        result = json.loads(clean_json(raw))
        assert result == {"a": 1, "b": 2}

    def test_trailing_comma_in_array(self) -> None:
        raw = '{"items": [1, 2, 3,]}'
        result = json.loads(clean_json(raw))
        assert result == {"items": [1, 2, 3]}

    def test_escaped_quotes_in_strings(self) -> None:
        raw = r'{"msg": "He said \"hello\""}'
        result = json.loads(clean_json(raw))
        assert "hello" in result["msg"]

    def test_no_json_returns_original(self) -> None:
        raw = "This is just plain text with no JSON at all"
        result = clean_json(raw)
        assert result == raw


# ═══════════════════════════════════════════════════════════════════════════
# 6. TypedDict Completeness
# ═══════════════════════════════════════════════════════════════════════════

class TestTypedDictCompleteness:
    """Verify that previously type-ignored fields are now properly declared."""

    def test_threat_context_has_mitre_tactics(self) -> None:
        ctx: ThreatContext = {
            "confidence": 0.8,
            "mitre_tactics": ["T1110"],
            "assessment": "Brute force detected.",
        }
        assert ctx["mitre_tactics"] == ["T1110"]
        assert ctx["assessment"] == "Brute force detected."

    def test_sentinel_state_has_alert_type(self) -> None:
        state: SentinelState = {
            "job_id": "type-test",
            "alert_type": "brute_force",
        }
        assert state["alert_type"] == "brute_force"


# ═══════════════════════════════════════════════════════════════════════════
# 7. Lazy Graph Initialization
# ═══════════════════════════════════════════════════════════════════════════

class TestLazyGraph:
    """Graph is initialized lazily, not at import time."""

    def test_get_graph_returns_callable(self) -> None:
        from backend.graph.pipeline import get_graph
        graph = get_graph()
        assert hasattr(graph, "invoke")

    def test_sentinel_graph_proxy_works(self) -> None:
        from backend.graph.pipeline import sentinel_graph
        assert hasattr(sentinel_graph, "invoke")

    def test_get_graph_is_idempotent(self) -> None:
        from backend.graph.pipeline import get_graph
        g1 = get_graph()
        g2 = get_graph()
        assert g1 is g2


# ═══════════════════════════════════════════════════════════════════════════
# 8. Reporter Notification Failure Isolation
# ═══════════════════════════════════════════════════════════════════════════

class TestReporterFailureIsolation:
    """Reporter completes even if notifications or tracing crash."""

    def test_reporter_completes_when_notify_throws(self) -> None:
        from backend.agents.reporter import reporter_node

        state: SentinelState = {
            "job_id": "notify-fail-test",
            "job_status": JobStatus.RUNNING,
            "problem_statement": "Test alert from 1.2.3.4",
            "loop_count": 0,
            "messages": [],
            "trace_spans": [],
            "evidence": {
                "raw_logs": ["test log"],
                "matched_ips": ["1.2.3.4"],
                "matched_hashes": [],
                "anomaly_score": 0.7,
                "anomaly_reason": "test",
            },
            "context": {
                "cve_matches": [],
                "threat_intel": [],
                "search_snippets": [],
                "confidence": 0.8,
                "mitre_tactics": ["T1110"],
                "assessment": "Test assessment.",
            },
        }

        with patch(
            "backend.agents.reporter.send_notifications",
            side_effect=Exception("Discord is down!"),
        ):
            with patch("backend.agents.reporter.ship_trace",
                        side_effect=Exception("Omium is down!")):
                result = reporter_node(state)

        assert result.get("job_status") == JobStatus.COMPLETE
        fact = result.get("fact_sheet")
        assert fact is not None
        assert fact.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ═══════════════════════════════════════════════════════════════════════════
# 9. CORS Configuration
# ═══════════════════════════════════════════════════════════════════════════

class TestCORSConfig:
    """CORS is locked down to specific origins."""

    def test_cors_allows_localhost_8000(self) -> None:
        resp = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:8000"

    def test_cors_blocks_arbitrary_origin(self) -> None:
        resp = client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://evil-site.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.headers.get("access-control-allow-origin") != "https://evil-site.com"


# ═══════════════════════════════════════════════════════════════════════════
# 10. Health Endpoint Version
# ═══════════════════════════════════════════════════════════════════════════

class TestVersionBump:
    def test_health_returns_updated_version(self) -> None:
        resp = client.get("/api/v1/health")
        assert resp.json()["version"] == "0.7.0"