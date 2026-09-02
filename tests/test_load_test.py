"""
Unit tests for load testing harness.
"""
import asyncio
import pytest
from scalability.load_test import LoadTestRunner


@pytest.mark.anyio
async def test_load_test_runner():
    runner = LoadTestRunner()

    async def mock_handler(payload):
        await asyncio.sleep(0.01)
        return True

    report = await runner.run_load_test(mock_handler, total_messages=10, concurrency=2, target_p99_ms=1000.0)
    assert report.total_messages == 10
    assert report.successful == 10
    assert report.failed == 0
    assert report.rps > 0
    assert report.latency_p50_ms > 0
    assert report.target_met is True
