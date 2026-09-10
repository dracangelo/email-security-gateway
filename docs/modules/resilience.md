# Module: resilience — Retry & Circuit Breaker

## Purpose

Wraps every external HTTP call (VirusTotal, RDAP, Google Safe Browsing, ClamAV) with exponential backoff retry and circuit breaker protection. Prevents transient failures from propagating into message failures and prevents hammering a provider that is already down.

---

## Module Structure

| File | Responsibility |
|---|---|
| `retry.py` | Exponential backoff with jitter retry decorator |
| `circuit_breaker.py` | Circuit breaker (closed → open → half-open state machine) |

---

## Retry (`retry.py`)

### Why Jitter Matters

Without jitter, a burst of messages all hitting the same transient failure will retry in lockstep — turning a brief blip into a thundering herd. Jitter randomizes the retry delay so retries spread out over time.

Delay formula:
```
delay = base * (2 ^ attempt_number) + uniform_random(0, base)
```

With `base=0.25s`:
- Attempt 1: 0.25s – 0.50s
- Attempt 2: 0.50s – 0.75s
- Attempt 3: 1.00s – 1.25s

### Configuration

| Setting | Default | Description |
|---|---|---|
| `EXTERNAL_CALL_MAX_ATTEMPTS` | `3` | Maximum number of attempts (including the first) |
| `EXTERNAL_CALL_BACKOFF_BASE_SECONDS` | `0.25` | Base for exponential backoff |
| `EXTERNAL_CALL_TIMEOUT_SECONDS` | `8.0` | Per-attempt timeout |

### Usage

```python
from resilience import with_retry

result = await with_retry(
    coro=some_external_api_call(url),
    max_attempts=3,
    base_delay=0.25,
)
```

Retryable exceptions: `httpx.TimeoutException`, `httpx.ConnectError`, `httpx.RemoteProtocolError`.

Non-retryable: `httpx.HTTPStatusError` with 4xx (client errors are not transient).

---

## Circuit Breaker (`circuit_breaker.py`)

### State Machine

```
            N consecutive failures
CLOSED ──────────────────────────→ OPEN
  ↑                                  │
  │         reset_timeout expires    │
  └──── HALF-OPEN ←─────────────────┘
            │
            │ next call succeeds
            └──→ CLOSED

            │ next call fails
            └──→ OPEN (immediately)
```

**CLOSED**: Normal operation. All calls pass through.

**OPEN**: All calls fail immediately without attempting the actual request. The circuit stays open for `CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS` (default 30s). This prevents hammering a provider that's already down and making every message wait out a full retry cycle.

**HALF-OPEN**: One test call is allowed through. If it succeeds, the circuit closes. If it fails, the circuit immediately reopens.

### Configuration

| Setting | Default | Description |
|---|---|---|
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `5` | Consecutive failures before opening |
| `CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS` | `30.0` | Seconds before attempting recovery |

### Per-Provider Instances

Each external dependency has its own circuit breaker instance — a VirusTotal outage does not open the ClamAV circuit breaker:

| Provider | Circuit Breaker Instance |
|---|---|
| VirusTotal URL reputation | `content_analysis.reputation.circuit_breaker` |
| VirusTotal file reputation | `attachment_analysis.reputation.circuit_breaker` |
| RDAP domain age | `content_analysis.reputation.rdap_circuit_breaker` |
| Google Safe Browsing | `content_analysis.reputation.gsb_circuit_breaker` |
| ClamAV | `attachment_analysis.reputation.clamav_circuit_breaker` |

### Usage

```python
from resilience import CircuitBreaker

breaker = CircuitBreaker(
    failure_threshold=5,
    reset_timeout=30.0,
    name="virustotal",
)

try:
    result = await breaker.call(virustotal_lookup(hash))
except CircuitBreakerOpenError:
    # Provider is down; use fallback (return unknown verdict)
    result = unknown_verdict
```

---

## Fail-Open vs Fail-Closed

The gateway deliberately **fails open** on all external dependency failures:

| Failure | Behavior |
|---|---|
| ClamAV unreachable | Scan skipped; heuristics and VT still apply |
| VirusTotal timeout / circuit open | Returns `unknown` verdict; other signals still apply |
| RDAP timeout | Domain age treated as `unknown`; other signals still apply |
| Redis unreachable | Falls back to in-memory store; mail is never dropped |

**Rationale**: The gateway is in the mail delivery path. Failing closed (dropping or quarantining all mail when a dependency is down) would be operationally catastrophic. The design accepts that some malware will slip through during a scanning outage, in exchange for zero false positives from infrastructure failures.

Monitor `ClamAVUnreachable`, `VirusTotalCircuitOpen`, and `StorageFallbackActivated` alerts to detect degraded operation early.
