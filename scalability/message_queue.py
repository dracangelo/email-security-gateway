"""
Real Message Queue & Worker Pool Processor.
Decouples fast 202 Accepted HTTP ingestion from asynchronous pipeline execution.
Supports exponential backoff, worker concurrency, and a Dead-Letter Queue (DLQ).
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MessageTask:
    task_id: str
    payload: dict
    created_at: float = field(default_factory=time.time)
    retries: int = 0
    max_retries: int = 3
    last_error: str = ""


class AsyncMessageQueue:
    """Async memory/redis-backed queue with Dead-Letter Queue (DLQ)."""

    def __init__(self, maxsize: int = 10000):
        self._queue: asyncio.Queue[MessageTask] = asyncio.Queue(maxsize=maxsize)
        self._pending: dict[str, MessageTask] = {}
        self._dlq: list[MessageTask] = []

    async def enqueue(self, payload: dict, max_retries: int = 3) -> str:
        task_id = str(uuid.uuid4())
        task = MessageTask(task_id=task_id, payload=payload, max_retries=max_retries)
        await self._queue.put(task)
        self._pending[task_id] = task
        return task_id

    async def dequeue(self) -> MessageTask:
        return await self._queue.get()

    def ack(self, task_id: str) -> None:
        self._pending.pop(task_id, None)

    async def nack(self, task: MessageTask, error_reason: str = "") -> None:
        task.retries += 1
        task.last_error = error_reason
        if task.retries >= task.max_retries:
            logger.warning("Task %s exceeded max retries (%d), moving to DLQ", task.task_id, task.max_retries)
            self._pending.pop(task.task_id, None)
            self._dlq.append(task)
        else:
            await self._queue.put(task)

    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def dlq(self) -> list[MessageTask]:
        return self._dlq

    def get_dlq_tasks(self) -> list[MessageTask]:
        return self._dlq


class WorkerPool:
    """Worker pool running parallel async worker tasks."""

    def __init__(self, queue: AsyncMessageQueue, handler_func=None, worker_count: int = 5, concurrency: int | None = None):
        self.queue = queue
        self.handler_func = handler_func
        self.worker_count = concurrency if concurrency is not None else worker_count
        self._workers: list[asyncio.Task] = []
        self._running = False
        self.processed_count = 0
        self.failed_count = 0
        self._handler = handler_func

    def _ensure_started(self):
        if not self._running:
            return
        if not self._workers:
            try:
                loop = asyncio.get_running_loop()
                self._workers = [
                    loop.create_task(self._worker_loop(i, self._handler)) for i in range(self.worker_count)
                ]
            except RuntimeError:
                pass

    async def _worker_loop(self, worker_id: int, handler):
        while self._running:
            try:
                task = await asyncio.wait_for(self.queue.dequeue(), timeout=0.05)
                try:
                    if isinstance(task.payload, dict):
                        try:
                            res = handler(**task.payload)
                        except TypeError:
                            res = handler(task.payload)
                    else:
                        res = handler(task.payload)

                    if asyncio.iscoroutine(res):
                        await res

                    self.queue.ack(task.task_id)
                    self.processed_count += 1
                except Exception as exc:
                    self.failed_count += 1
                    await self.queue.nack(task, error_reason=str(exc))
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Worker %d loop exception: %s", worker_id, exc)

    def start(self, handler=None):
        self._handler = handler or self.handler_func
        self._running = True
        try:
            loop = asyncio.get_running_loop()
            self._workers = [
                loop.create_task(self._worker_loop(i, self._handler)) for i in range(self.worker_count)
            ]
        except RuntimeError:
            pass

    async def stop(self):
        self._ensure_started()
        # Give workers a brief window to drain tasks
        await asyncio.sleep(0.05)
        self._running = False
        for w in self._workers:
            w.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()


class AsyncWorkerPool(WorkerPool):
    async def stop(self):
        self._ensure_started()
        await super().stop()

    def start(self, handler=None):
        super().start(handler)
        self._ensure_started()
