"""
Unit tests for message queue and worker pool.
"""
import asyncio
import pytest
from scalability.message_queue import AsyncMessageQueue, WorkerPool


@pytest.mark.anyio
async def test_message_queue_basic():
    queue = AsyncMessageQueue()
    task_id = await queue.enqueue({"msg": "hello"})
    assert queue.queue_depth() == 1

    task = await queue.dequeue()
    assert task.task_id == task_id
    assert task.payload["msg"] == "hello"
    queue.ack(task_id)
    assert queue.queue_depth() == 0


@pytest.mark.anyio
async def test_message_queue_dlq():
    queue = AsyncMessageQueue()
    task_id = await queue.enqueue({"msg": "fail"}, max_retries=1)
    task = await queue.dequeue()

    await queue.nack(task, error_reason="test error")
    assert len(queue.get_dlq_tasks()) == 1
    assert queue.get_dlq_tasks()[0].last_error == "test error"


@pytest.mark.anyio
async def test_worker_pool():
    queue = AsyncMessageQueue()
    pool = WorkerPool(queue, worker_count=2)
    processed = []

    async def sample_handler(payload):
        processed.append(payload["id"])

    pool.start(sample_handler)
    await queue.enqueue({"id": 1})
    await queue.enqueue({"id": 2})

    await asyncio.sleep(0.2)
    await pool.stop()

    assert 1 in processed
    assert 2 in processed
    assert pool.processed_count == 2
