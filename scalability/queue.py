"""
Asynchronous Message Queue & Worker Pool Engine.
Decouples inbound webhook receipt (202 Accepted) from background email analysis with retries, exponential backoff, and Dead Letter Queue (DLQ).
"""
from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from typing import Any, Callable, Dict, List, Optional


class QueueItem:
    def __init__(self, payload: Dict[str, Any], max_retries: int = 3):
        self.item_id = uuid.uuid4().hex
        self.payload = payload
        self.max_retries = max_retries
        self.retry_count = 0
        self.enqueued_at = time.time()
        self.last_error: Optional[str] = None


class AsyncMessageQueue:
    def __init__(self, max_size: int = 10000):
        self._queue: asyncio.Queue[QueueItem] = asyncio.Queue(maxsize=max_size)
        self.dlq: List[QueueItem] = []
        self.processed_count: int = 0

    async def enqueue(self, payload: Dict[str, Any], max_retries: int = 3) -> str:
        item = QueueItem(payload=payload, max_retries=max_retries)
        await self._queue.put(item)
        return item.item_id

    async def dequeue(self) -> QueueItem:
        return await self._queue.get()

    def mark_done(self) -> None:
        self._queue.task_done()
        self.processed_count += 1

    def move_to_dlq(self, item: QueueItem, error_msg: str) -> None:
        item.last_error = error_msg
        self.dlq.append(item)
        self._queue.task_done()

    def depth(self) -> int:
        return self._queue.qsize()


class AsyncWorkerPool:
    def __init__(self, queue: AsyncMessageQueue, handler_func: Callable[..., Any], concurrency: int = 4):
        self.queue = queue
        self.handler_func = handler_func
        self.concurrency = concurrency
        self.workers: List[asyncio.Task] = []
        self._running = False

    async def _worker_loop(self, worker_id: int):
        while self._running:
            try:
                item = await asyncio.wait_for(self.queue.dequeue(), timeout=0.1)
            except (asyncio.TimeoutError, TimeoutError):
                continue

            success = False
            while item.retry_count <= item.max_retries:
                try:
                    if inspect.iscoroutinefunction(self.handler_func):
                        await self.handler_func(**item.payload)
                    else:
                        self.handler_func(**item.payload)
                    success = True
                    break
                except Exception as exc:
                    item.retry_count += 1
                    item.last_error = str(exc)
                    if item.retry_count <= item.max_retries:
                        await asyncio.sleep(0.01 * (2 ** (item.retry_count - 1)))  # Exponential backoff

            if success:
                self.queue.mark_done()
            else:
                self.queue.move_to_dlq(item, f"Exceeded max retries: {item.last_error}")

    def start(self) -> None:
        self._running = True
        for i in range(self.concurrency):
            task = asyncio.create_task(self._worker_loop(worker_id=i))
            self.workers.append(task)

    async def stop(self) -> None:
        self._running = False
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
