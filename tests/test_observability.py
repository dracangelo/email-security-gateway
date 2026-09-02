"""
Tests for Observability Module (Task 11):
- Prometheus Metrics Registry & Text Formatting
- OpenTelemetry Distributed Span Tracing
- Redacting JSON Log Handler (PII / Token Redaction)
- Grafana Dashboard Schema Generator
- SLO Engine & Burn-Rate Alerting
- Synthetic Canary Health Probe
- External API Cost & Quota Tracker
- FastAPI /metrics and /admin/slo Endpoints
"""
from __future__ import annotations

import asyncio
import logging
import pytest
from fastapi.testclient import TestClient

from observability import (
    CanaryProbe,
    GrafanaDashboardGenerator,
    PrometheusMetricsRegistry,
    QuotaTracker,
    RedactingJsonFormatter,
    SLOCalculator,
    TracingManager,
)
from webhook_receiver.app import app


def test_prometheus_metrics_registry():
    registry = PrometheusMetricsRegistry()

    registry.record_message_processed("deliver")
    registry.record_message_processed("quarantine")
    registry.record_stage_latency("content", 0.045)
    registry.record_api_error("virustotal")
    registry.set_circuit_breaker_state("vt_breaker", "CLOSED")
    registry.set_queue_depth(5)

    prom_text = registry.generate_prometheus_text()

    assert "# HELP gateway_messages_processed_total" in prom_text
    assert 'gateway_messages_processed_total{action="deliver"} 1' in prom_text
    assert 'gateway_stage_latency_seconds_sum{stage="content"}' in prom_text
    assert 'gateway_external_api_errors_total{provider="virustotal"} 1' in prom_text
    assert 'gateway_circuit_breaker_state{breaker="vt_breaker",state="CLOSED"} 1' in prom_text
    assert "gateway_queue_depth 5" in prom_text


def test_tracing_manager():
    tracer = TracingManager()

    root_span = tracer.start_trace("gateway_process_message", attributes={"message_id": "msg_001"})
    assert root_span.trace_id is not None

    child_span = tracer.start_child_span(root_span, "stage_content_analysis")
    assert child_span.trace_id == root_span.trace_id
    assert child_span.parent_id == root_span.span_id

    tracer.finish_span(child_span, status="OK")
    tracer.finish_span(root_span, status="OK")

    trace_spans = tracer.get_trace_spans(root_span.trace_id)
    assert len(trace_spans) == 2


def test_redacting_json_formatter():
    formatter = RedactingJsonFormatter()

    log_record = logging.LogRecord(
        name="gateway.auth",
        level=logging.INFO,
        pathname="app.py",
        lineno=100,
        msg="Failed login for user admin@corp.com with secret='SuperSecret123!' and Authorization: Bearer secret_token_xyz",
        args=(),
        exc_info=None,
    )

    formatted_json = formatter.format(log_record)

    assert "admin@corp.com" not in formatted_json
    assert "[REDACTED_EMAIL]" in formatted_json
    assert "secret_token_xyz" not in formatted_json
    assert "[REDACTED_TOKEN]" in formatted_json
    assert "SuperSecret123!" not in formatted_json
    assert "[REDACTED_SECRET]" in formatted_json


def test_grafana_dashboard_generator():
    dash_json = GrafanaDashboardGenerator.generate_dashboard_json()

    assert "dashboard" in dash_json
    assert dash_json["dashboard"]["title"] == "Email Auth Gateway — Operational Overview"
    assert len(dash_json["dashboard"]["panels"]) == 4


def test_slo_calculator():
    slo = SLOCalculator(target_availability_pct=99.9, target_latency_p99_sec=2.0)

    # 10 successful fast requests
    for _ in range(10):
        slo.record_request(is_success=True, latency_sec=0.1)

    metrics = slo.calculate_slo_metrics(window_hours=1.0)
    assert metrics["availability_pct"] == 100.0
    assert metrics["burn_rate"] == 0.0

    # Inject multiple error requests to trigger burn rate alert
    for _ in range(5):
        slo.record_request(is_success=False, latency_sec=3.5)

    alert_metrics = slo.calculate_slo_metrics(window_hours=1.0)
    assert alert_metrics["error_count"] == 5
    assert alert_metrics["burn_rate"] > 10.0
    assert alert_metrics["alert"] is not None


def test_canary_probe():
    probe = CanaryProbe()

    result = asyncio.run(probe.run_canary_check())

    assert result["status"] == "HEALTHY"
    assert result["latency_ms"] >= 0.0
    assert result["result"]["canary"] is True


def test_quota_tracker():
    tracker = QuotaTracker()
    tracker.set_provider_quota("virustotal", daily_limit=10, monthly_limit=300)

    # Normal usage
    st1 = tracker.record_api_call("virustotal", count=5)
    assert st1["daily_pct"] == 50.0
    assert st1["alert"] is None

    # Threshold warning
    st2 = tracker.record_api_call("virustotal", count=4)
    assert st2["daily_pct"] == 90.0
    assert st2["alert"] is not None
    assert "CRITICAL" in st2["alert"]


def test_observability_fastapi_endpoints():
    client = TestClient(app)

    # 1. GET /metrics
    resp_prom = client.get("/metrics")
    assert resp_prom.status_code == 200
    assert "text/plain" in resp_prom.headers["content-type"]
    assert "# HELP gateway_messages_processed_total" in resp_prom.text

    # 2. GET /admin/slo
    resp_slo = client.get("/admin/slo")
    assert resp_slo.status_code == 200
    slo_data = resp_slo.json()
    assert "availability_pct" in slo_data
