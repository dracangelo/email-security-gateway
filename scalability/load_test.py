"""
Load Testing Suite & Performance Benchmarking Harness.
Simulates high-volume inbound webhook/SMTP traffic and measures throughput, RPS, and P50/P90/P99 latency metrics.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class LoadTestReport:
    total_messages: int = 0
    successful: int = 0
    failed: int = 0
    total_duration_seconds: float = 0.0
    rps: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p90_ms: float = 0.0
    latency_p99_ms: float = 0.0
    target_met: bool = False
    latencies_ms: list[float] = field(default_factory=list)


class LoadTestRunner:
    """Benchmarking harness for executing high-volume message delivery load tests."""

    def __init__(self, target_p99_ms: float = 2000.0, target_msgs_per_min: float = 500.0):
        self.target_p99_ms = target_p99_ms
        self.target_msgs_per_min = target_msgs_per_min

    async def run_load_test(
        self,
        handler_func=None,
        process_func=None,
        total_messages: int = 50,
        concurrency: int = 5,
        target_p99_ms: float | None = None,
    ) -> dict | LoadTestReport:
        func = handler_func or process_func
        target_p99 = target_p99_ms or self.target_p99_ms
        sem = asyncio.Semaphore(concurrency)
        latencies: list[float] = []
        successful = 0
        failed = 0

        async def _send_single(index: int):
            nonlocal successful, failed
            async with sem:
                start = time.perf_counter()
                try:
                    res = func(index) if hasattr(func, "__code__") and func.__code__.co_argcount == 1 else func({"msg_id": f"load-test-{index}"})
                    if asyncio.iscoroutine(res):
                        await res
                    duration_ms = (time.perf_counter() - start) * 1000.0
                    latencies.append(duration_ms)
                    successful += 1
                except Exception:
                    failed += 1

        overall_start = time.perf_counter()
        tasks = [_send_single(i) for i in range(total_messages)]
        await asyncio.gather(*tasks, return_exceptions=True)
        total_duration = time.perf_counter() - overall_start

        if not latencies:
            latencies = [0.0]

        latencies.sort()
        n = len(latencies)
        p50 = latencies[int(n * 0.50)]
        p90 = latencies[int(n * 0.90)]
        p99 = latencies[min(int(n * 0.99), n - 1)]
        rps = total_messages / max(total_duration, 0.001)

        target_met = (p99 <= target_p99) and (failed == 0)

        # Return dict if called via process_func (tests/test_scalability.py expected dict)
        if process_func is not None:
            return {
                "total_messages": total_messages,
                "successful": successful,
                "failed": failed,
                "duration_sec": round(total_duration, 3),
                "rps": round(rps, 2),
                "p50_latency_ms": round(p50, 2),
                "p90_latency_ms": round(p90, 2),
                "p99_latency_ms": round(p99, 2),
                "sla_passed": target_met,
            }

        return LoadTestReport(
            total_messages=total_messages,
            successful=successful,
            failed=failed,
            total_duration_seconds=round(total_duration, 3),
            rps=round(rps, 2),
            latency_p50_ms=round(p50, 2),
            latency_p90_ms=round(p90, 2),
            latency_p99_ms=round(p99, 2),
            target_met=target_met,
            latencies_ms=latencies,
        )
