"""
Prometheus Metrics Collector & Exporter.
Tracks gateway message throughput, latency percentiles, stage metrics, API errors, and circuit breaker states.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import time
from typing import Dict, List, Tuple


class PrometheusMetricsRegistry:
    def __init__(self):
        self.message_counter: Counter[str] = Counter()  # action -> count
        self.stage_latency_sum: defaultdict[str, float] = defaultdict(float)  # stage -> total_seconds
        self.stage_latency_count: Counter[str] = Counter()  # stage -> count
        self.api_error_counter: Counter[str] = Counter()  # provider -> error_count
        self.circuit_breaker_states: Dict[str, str] = {}  # breaker_name -> state ("CLOSED", "OPEN", "HALF_OPEN")
        self.queue_depth: int = 0

    def record_message_processed(self, action: str) -> None:
        self.message_counter[action] += 1

    def record_stage_latency(self, stage: str, duration_seconds: float) -> None:
        self.stage_latency_sum[stage] += duration_seconds
        self.stage_latency_count[stage] += 1

    def record_api_error(self, provider: str) -> None:
        self.api_error_counter[provider] += 1

    def set_circuit_breaker_state(self, breaker_name: str, state: str) -> None:
        self.circuit_breaker_states[breaker_name] = state.upper()

    def set_queue_depth(self, depth: int) -> None:
        self.queue_depth = depth

    def generate_prometheus_text(self) -> str:
        """Format current metrics into standard Prometheus text representation."""
        lines: List[str] = []

        # 1. Message Counter
        lines.append("# HELP gateway_messages_processed_total Total count of processed email messages by action.")
        lines.append("# TYPE gateway_messages_processed_total counter")
        for action, count in self.message_counter.items():
            lines.append(f'gateway_messages_processed_total{{action="{action}"}} {count}')
        if not self.message_counter:
            lines.append('gateway_messages_processed_total{action="total"} 0')

        # 2. Stage Latency
        lines.append("# HELP gateway_stage_latency_seconds_sum Total latency spent per processing stage in seconds.")
        lines.append("# TYPE gateway_stage_latency_seconds_sum counter")
        for stage, total_s in self.stage_latency_sum.items():
            lines.append(f'gateway_stage_latency_seconds_sum{{stage="{stage}"}} {total_s:.4f}')

        lines.append("# HELP gateway_stage_latency_seconds_count Total invocations per processing stage.")
        lines.append("# TYPE gateway_stage_latency_seconds_count counter")
        for stage, count in self.stage_latency_count.items():
            lines.append(f'gateway_stage_latency_seconds_count{{stage="{stage}"}} {count}')

        # 3. External API Errors
        lines.append("# HELP gateway_external_api_errors_total Total count of external provider API errors.")
        lines.append("# TYPE gateway_external_api_errors_total counter")
        for provider, count in self.api_error_counter.items():
            lines.append(f'gateway_external_api_errors_total{{provider="{provider}"}} {count}')

        # 4. Circuit Breaker States
        lines.append("# HELP gateway_circuit_breaker_state Current state of circuit breakers (1 = active state).")
        lines.append("# TYPE gateway_circuit_breaker_state gauge")
        for breaker, state in self.circuit_breaker_states.items():
            val = 1 if state == "CLOSED" else (2 if state == "HALF_OPEN" else 0)
            lines.append(f'gateway_circuit_breaker_state{{breaker="{breaker}",state="{state}"}} {val}')

        # 5. Queue Depth
        lines.append("# HELP gateway_queue_depth Current processing queue depth.")
        lines.append("# TYPE gateway_queue_depth gauge")
        lines.append(f"gateway_queue_depth {self.queue_depth}")

        return "\n".join(lines) + "\n"
