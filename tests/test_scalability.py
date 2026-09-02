"""
Tests for Scalability & Performance Module (Task 12):
- Decoupled Async Message Queue, Worker Pool & DLQ
- Horizontal Worker Autoscaler
- Process-Wide Shared HTTP Connection Pool
- High-Performance Indexed Database Quarantine Store
- Concurrent Batch DNS & RDAP Resolver
- Automated Load Testing Suite & SLA Verification
- Cache Warm-Up Engine for Frequent Domains
"""
from __future__ import annotations

import asyncio
import pytest

from scalability import (
    AsyncMessageQueue,
    AsyncWorkerPool,
    BatchDNSResolver,
    CacheWarmupEngine,
    GlobalHTTPClientPool,
    IndexedDatabaseQuarantineStore,
    LoadTestRunner,
    WorkerAutoscaler,
)


def test_async_message_queue_and_worker_pool():
    queue = AsyncMessageQueue()
    processed = []

    async def handler_func(msg_val: str):
        if msg_val == "fail_me":
            raise ValueError("Intentional failure")
        processed.append(msg_val)

    pool = AsyncWorkerPool(queue=queue, handler_func=handler_func, concurrency=2)
    pool.start()

    async def run_queue_test():
        await queue.enqueue({"msg_val": "msg_1"}, max_retries=1)
        await queue.enqueue({"msg_val": "fail_me"}, max_retries=1)
        await queue.enqueue({"msg_val": "msg_2"}, max_retries=1)
        await asyncio.sleep(0.3)
        await pool.stop()

    asyncio.run(run_queue_test())

    assert "msg_1" in processed
    assert "msg_2" in processed
    assert len(queue.dlq) == 1
    assert queue.dlq[0].payload["msg_val"] == "fail_me"


def test_worker_autoscaler():
    queue = AsyncMessageQueue()
    pool = AsyncWorkerPool(queue=queue, handler_func=lambda x: None, concurrency=2)
    autoscaler = WorkerAutoscaler(worker_pool=pool, queue=queue, min_workers=2, max_workers=8, high_threshold=10)

    # Initial state
    assert autoscaler.evaluate_scale() == 2

    # Fill queue to trigger scale up
    async def fill_q():
        for i in range(15):
            await queue.enqueue({"msg": i})

    asyncio.run(fill_q())
    scaled_workers = autoscaler.evaluate_scale()
    assert scaled_workers > 2


def test_global_http_client_pool():
    client = GlobalHTTPClientPool.get_client(timeout_sec=5.0)
    assert client is not None
    assert not client.is_closed

    client_again = GlobalHTTPClientPool.get_client()
    assert client_again is client

    asyncio.run(GlobalHTTPClientPool.close_client())
    assert client.is_closed


def test_indexed_database_quarantine_store():
    store = IndexedDatabaseQuarantineStore(db_path=":memory:")

    q_id1 = store.save({
        "tenant_id": "tenant_1",
        "sender": "spammer@bad.com",
        "recipient": "victim@company.com",
        "action": "quarantine",
        "score": 85,
        "status": "pending",
    })
    q_id2 = store.save({
        "tenant_id": "tenant_1",
        "sender": "legit@good.com",
        "recipient": "victim@company.com",
        "action": "quarantine",
        "score": 30,
        "status": "released",
    })

    assert store.get(q_id1) is not None
    pending_records = store.query(tenant_id="tenant_1", status="pending")
    assert len(pending_records) == 1
    assert pending_records[0]["id"] == q_id1

    search_records = store.query(search_query="spammer")
    assert len(search_records) == 1


def test_batch_dns_resolver():
    resolver = BatchDNSResolver()

    domains = ["example.com", "google.com", "github.com"]
    results = asyncio.run(resolver.resolve_batch(domains))

    assert len(results) == 3
    assert results["example.com"]["resolved"] is True


def test_load_test_runner():
    runner = LoadTestRunner(target_p99_ms=1000.0, target_msgs_per_min=10.0)

    async def mock_processor(msg_id: int):
        await asyncio.sleep(0.005)

    res = asyncio.run(runner.run_load_test(process_func=mock_processor, total_messages=20, concurrency=5))

    assert res["total_messages"] == 20
    assert res["p99_latency_ms"] < 500.0
    assert res["sla_passed"] is True


def test_cache_warmup_engine():
    warmup = CacheWarmupEngine()
    warmup.add_frequent_domain("vendor-partner.com")

    count = asyncio.run(warmup.warm_cache())
    assert count == 1
    cached = warmup.get_cached_info("vendor-partner.com")
    assert cached is not None
    assert cached["warmed"] is True
