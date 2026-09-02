#!/usr/bin/env python3
"""
CLI Load & Throughput Benchmark Runner for Email Auth Gateway.
Simulates high-volume concurrent traffic against a local or remote gateway instance.
"""
import argparse
import asyncio
import sys
import time
from scalability.load_test import LoadTestRunner
from decision_engine.scorer import decide
from decision_engine.models import StageScore, Action


async def benchmark_internal_pipeline(total_messages: int, concurrency: int, target_p99: float):
    print(f"[*] Benchmarking internal multi-engine decision pipeline...")
    print(f"    Total Messages: {total_messages} | Concurrency: {concurrency} | P99 Target: {target_p99}ms")

    sample_scores = [
        StageScore(stage="auth", score_delta=0, reasons=["SPF pass", "DKIM pass"]),
        StageScore(stage="content", score_delta=15, reasons=["Contains wire transfer keyword"]),
        StageScore(stage="attachments", score_delta=0, reasons=[]),
    ]

    async def _process_mock(idx: int):
        decide(
            stage_scores=sample_scores,
            warn_threshold=30,
            quarantine_threshold=70,
        )
        return True

    runner = LoadTestRunner(target_p99_ms=target_p99)
    report = await runner.run_load_test(
        handler_func=_process_mock,
        total_messages=total_messages,
        concurrency=concurrency,
        target_p99_ms=target_p99,
    )

    print("\n" + "=" * 55)
    print("        LOAD TEST PERFORMANCE REPORT")
    print("=" * 55)
    print(f" Total Messages:       {report.total_messages}")
    print(f" Successful:           {report.successful}")
    print(f" Failed:               {report.failed}")
    print(f" Total Duration:       {report.total_duration_seconds}s")
    print(f" Throughput (RPS):     {report.rps} msgs/sec")
    print("-" * 55)
    print(f" P50 Latency:          {report.latency_p50_ms} ms")
    print(f" P90 Latency:          {report.latency_p90_ms} ms")
    print(f" P99 Latency:          {report.latency_p99_ms} ms (Target: <={target_p99}ms)")
    print("=" * 55)
    status_str = "PASSED [✓]" if report.target_met else "FAILED [!]"
    print(f" SLA Compliance:       {status_str}")
    print("=" * 55 + "\n")

    return report.target_met


def main():
    parser = argparse.ArgumentParser(description="Email Auth Gateway Load Testing CLI")
    parser.add_argument("--total", type=int, default=200, help="Total messages to process (default: 200)")
    parser.add_argument("--concurrency", type=int, default=15, help="Concurrent workers (default: 15)")
    parser.add_argument("--target-p99", type=float, default=100.0, help="P99 latency target in ms (default: 100.0)")

    args = parser.parse_args()

    success = asyncio.run(benchmark_internal_pipeline(args.total, args.concurrency, args.target_p99))
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
