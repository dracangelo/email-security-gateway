"""
Load and Performance Benchmark Test Suite.
Verifies throughput and latency SLAs under high-volume concurrency.
"""
import asyncio
import time
import pytest
from scalability.load_test import LoadTestRunner
from decision_engine.scorer import decide
from decision_engine.models import StageScore, Action
from content_analysis.keywords import scan_keywords


@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Automated benchmark tests enforcing latency & throughput SLAs."""

    @pytest.mark.anyio
    async def test_fast_path_decision_engine_sla(self):
        """SLA: Fast-path decision evaluation must achieve >= 200 RPS with P99 <= 50ms."""
        clean_scores = [
            StageScore(stage="auth", score_delta=0, reasons=["SPF pass", "DKIM pass", "DMARC pass"]),
            StageScore(stage="content", score_delta=0, reasons=[]),
            StageScore(stage="attachments", score_delta=0, reasons=[]),
        ]

        async def _evaluate_single(idx: int):
            decision = decide(
                stage_scores=clean_scores,
                warn_threshold=30,
                quarantine_threshold=70,
            )
            assert decision.action == Action.FORWARD
            return True

        runner = LoadTestRunner(target_p99_ms=50.0)
        report = await runner.run_load_test(
            handler_func=_evaluate_single,
            total_messages=300,
            concurrency=20,
            target_p99_ms=50.0,
        )

        assert report.successful == 300
        assert report.failed == 0
        assert report.rps >= 200.0, f"RPS was {report.rps}, expected >= 200.0"
        assert report.latency_p99_ms <= 50.0, f"P99 latency was {report.latency_p99_ms}ms, expected <= 50.0ms"
        assert report.target_met is True

    @pytest.mark.anyio
    async def test_content_keywords_pipeline_sla(self):
        """SLA: Keywords and pattern pipeline must achieve >= 50 RPS with P99 <= 150ms."""
        sample_body = """
        Dear Customer,
        Please review your updated wire transfer instructions and verify your password immediately.
        Access portal here: http://secure-update-banking-login.com/login.php
        Thank you,
        Support Team
        """

        async def _run_keywords(idx: int):
            matches, points = scan_keywords(sample_body)
            assert points > 0
            assert len(matches) > 0
            return True

        runner = LoadTestRunner(target_p99_ms=150.0)
        report = await runner.run_load_test(
            handler_func=_run_keywords,
            total_messages=150,
            concurrency=10,
            target_p99_ms=150.0,
        )

        assert report.successful == 150
        assert report.failed == 0
        assert report.latency_p50_ms <= 25.0
        assert report.latency_p99_ms <= 150.0
        assert report.target_met is True

    @pytest.mark.anyio
    async def test_high_concurrency_burst_zero_loss(self):
        """SLA: High-concurrency burst of 500 messages across 50 concurrent workers must have 0% loss."""
        processed = set()
        lock = asyncio.Lock()

        async def _burst_handler(idx: int):
            await asyncio.sleep(0.001)  # simulate micro I/O
            async with lock:
                processed.add(idx)
            return True

        runner = LoadTestRunner(target_p99_ms=200.0)
        report = await runner.run_load_test(
            handler_func=_burst_handler,
            total_messages=500,
            concurrency=50,
            target_p99_ms=200.0,
        )

        assert report.successful == 500
        assert report.failed == 0
        assert len(processed) == 500
        assert report.target_met is True
