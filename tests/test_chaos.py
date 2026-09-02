"""
Unit tests for chaos testing & fault injection engine.
"""
from reliability.chaos_injector import ChaosInjector


def test_chaos_fault_simulation():
    chaos = ChaosInjector(enabled=True)

    def sample_pipeline_step():
        chaos.check_and_trigger("redis_down")
        return "success"

    res = chaos.verify_no_mail_loss("redis_down", sample_pipeline_step)
    assert res.injected is True
    assert res.handled_gracefully is True
    assert res.mail_preserved is True
