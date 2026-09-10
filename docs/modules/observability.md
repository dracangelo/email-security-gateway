# Module: observability — Metrics, Tracing & SLOs

## Purpose

Provides structured observability: Prometheus metrics, OpenTelemetry distributed tracing, SLO (Service Level Objective) tracking, canary deployment monitoring, external API quota tracking, and a Grafana dashboard definition.

---

## Module Structure

| File | Responsibility |
|---|---|
| `metrics.py` | `PrometheusMetricsRegistry` — counters, histograms, gauges |
| `tracing.py` | `TracingManager` — OpenTelemetry span management |
| `slo.py` | `SLOCalculator` — error budget burn rate calculation |
| `logging_handler.py` | Structured JSON logging handler |
| `quota_tracker.py` | `QuotaTracker` — external API quota monitoring |
| `canary.py` | Canary deployment traffic comparison |
| `grafana_dashboard.py` | Grafana dashboard JSON definition generator |

---

## Prometheus Metrics (`metrics.py`)

Exposed at `GET /metrics` (Prometheus scrape endpoint).

### Counters

| Metric | Labels | Description |
|---|---|---|
| `email_gateway_messages_total` | `action`, `tenant_id` | Total messages processed, by routing action |
| `email_gateway_auth_checks_total` | `result`, `check` | Auth check outcomes (SPF/DKIM/DMARC pass/fail) |
| `email_gateway_webhook_requests_total` | `provider`, `status` | Inbound webhook requests by provider and HTTP status |
| `email_gateway_quarantine_operations_total` | `operation` | Quarantine store/release/reject operations |
| `email_gateway_relay_attempts_total` | `result` | SMTP relay attempts (success/failure) |

### Histograms

| Metric | Labels | Description |
|---|---|---|
| `email_gateway_message_processing_seconds` | `tenant_id` | End-to-end message processing latency |
| `email_gateway_external_call_duration_seconds` | `provider` | External API call duration (VirusTotal, RDAP, etc.) |
| `email_gateway_score_distribution` | `action` | Risk score distribution at decision time |

### Gauges

| Metric | Labels | Description |
|---|---|---|
| `email_gateway_quarantine_pending_items` | `tenant_id` | Current count of unreviewed quarantine items |
| `email_gateway_circuit_breaker_state` | `provider` | 0=closed, 1=open (alert when 1) |
| `email_gateway_redis_connected` | — | 1 if Redis is connected, 0 if in-memory fallback |

---

## OpenTelemetry Tracing (`tracing.py`)

`TracingManager` instruments message processing with distributed traces:

```
Span: process_message
  ├── Span: auth_checker.run_auth_checks
  │     ├── Span: spf.check_spf
  │     ├── Span: dkim.check_dkim
  │     └── Span: dmarc.evaluate
  ├── Span: content_analysis.analyze_content
  │     ├── Span: url_reputation.lookup (x N URLs)
  │     └── Span: domain_age.lookup
  ├── Span: attachment_analysis.analyze_attachments
  │     ├── Span: virustotal.hash_lookup
  │     └── Span: clamav.scan
  ├── Span: decision_engine.decide
  └── Span: delivery.deliver
```

Spans include attributes: `tenant_id`, `message_id`, `score`, `action`.

### Configuration

```bash
# Export to Jaeger (local dev)
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# Export to Datadog
OTEL_EXPORTER_OTLP_ENDPOINT=https://trace.agent.datadoghq.com
DD_API_KEY=...
```

---

## SLO Tracking (`slo.py`)

`SLOCalculator` tracks error budgets for defined SLOs:

| SLO | Target | Error Budget |
|---|---|---|
| **Message Processing Latency** | 99% of messages processed < 5s | 1% |
| **Quarantine Availability** | 99.9% of quarantine API calls succeed | 0.1% |
| **Relay Success Rate** | 99.5% of FORWARD/WARN messages relayed successfully | 0.5% |
| **False Positive Rate** | < 0.1% of messages incorrectly quarantined (measured by release rate) | — |

Burn rate alerts fire when the error budget is consumed faster than it can recover. Alert thresholds follow the Google SRE workbook multi-window approach.

---

## Quota Tracking (`quota_tracker.py`)

`QuotaTracker` monitors external API usage against rate limits:

| API | Default Limit | Alert Threshold |
|---|---|---|
| VirusTotal (free tier) | 500 requests/day | 80% (400/day) |
| VirusTotal (premium) | 20,000 requests/day | 80% |
| Google Safe Browsing | 10,000 requests/day | 80% |
| RDAP (`rdap.org`) | ~1,000 requests/hour | 70% |

Quota exhaustion downgrades to `NullReputationProvider` for the remainder of the window; alerts are fired via `QUARANTINE_NOTIFY_WEBHOOK_URL`.

---

## Structured Logging (`logging_handler.py`)

Configures Python's `logging` module to emit structured JSON:

```json
{
  "timestamp": "2026-09-10T12:34:56.789Z",
  "level": "INFO",
  "logger": "email_gateway",
  "message": "message processed",
  "message_id": "msg_abc123",
  "action": "quarantine",
  "score": 95,
  "tenant_id": "tenant_acme",
  "duration_ms": 342
}
```

All logs pass through `security.redact` before emission to prevent PII / credential leakage.

---

## Grafana Dashboard (`grafana_dashboard.py`)

Generates a Grafana dashboard JSON definition with:

- Message throughput and action breakdown (area chart)
- Risk score distribution (heatmap)
- Auth check pass/fail rates (time series)
- External API latency P50/P95/P99 (time series)
- Circuit breaker state (status panel)
- Quarantine queue depth (stat panel)
- Error budget burn rate (gauge)

Export:

```bash
python3 -m observability.grafana_dashboard > dashboard.json
# Import into Grafana: Dashboards → Import → Upload JSON
```
