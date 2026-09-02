"""
Unit tests for horizontal worker autoscaler.
"""
from scalability.autoscaler import AutoscalerConfig, WorkerAutoscaler


def test_autoscaler_scale_up():
    config = AutoscalerConfig(min_workers=2, max_workers=10, scale_up_threshold=10)
    scaler = WorkerAutoscaler(config)

    # High queue depth -> scale up
    desired = scaler.evaluate_desired_workers(queue_depth=20, current_workers=2)
    assert desired > 2


def test_autoscaler_scale_down():
    config = AutoscalerConfig(min_workers=2, max_workers=10, scale_down_threshold=2)
    scaler = WorkerAutoscaler(config)

    # Low queue depth -> scale down
    desired = scaler.evaluate_desired_workers(queue_depth=0, current_workers=5)
    assert desired < 5
