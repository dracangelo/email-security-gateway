"""
Horizontal Worker Autoscaling Module.
Monitors queue depth and processing load to dynamically adjust active worker concurrency.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AutoscalerConfig:
    min_workers: int = 2
    max_workers: int = 20
    target_queue_per_worker: int = 5
    scale_up_threshold: int = 15
    scale_down_threshold: int = 2


class WorkerAutoscaler:
    """Calculates desired worker pool concurrency based on real-time load metrics."""

    def __init__(
        self,
        worker_pool=None,
        queue=None,
        min_workers: int = 2,
        max_workers: int = 20,
        high_threshold: int = 10,
        config: AutoscalerConfig | None = None,
    ):
        self.worker_pool = worker_pool
        self.queue = queue
        self.config = config or AutoscalerConfig(
            min_workers=min_workers,
            max_workers=max_workers,
            scale_up_threshold=high_threshold,
        )

    def evaluate_scale(self) -> int:
        q_depth = self.queue.queue_depth() if self.queue else 0
        cur_workers = self.worker_pool.worker_count if self.worker_pool else self.config.min_workers
        return self.evaluate_desired_workers(q_depth, cur_workers)

    def evaluate_desired_workers(self, queue_depth: int, current_workers: int) -> int:
        if queue_depth > self.config.scale_up_threshold:
            desired = min(current_workers + 2, self.config.max_workers)
            return desired
        elif queue_depth < self.config.scale_down_threshold and current_workers > self.config.min_workers:
            desired = max(current_workers - 1, self.config.min_workers)
            return desired

        return current_workers
