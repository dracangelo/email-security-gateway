"""
Unit tests for provider inbound failure behavior policy inspector.
"""
from reliability.inbound_failure_policy import InboundFailureInspector


def test_inbound_failure_policy_inspection():
    inspector = InboundFailureInspector()

    pol = inspector.get_provider_policy("sendgrid")
    assert pol.retry_duration_hours == 72
    assert pol.bounces_on_failure is False

    # Short outage -> no mail lost
    short_report = inspector.simulate_gateway_outage("sendgrid", outage_duration_hours=12.0)
    assert short_report.mail_lost is False
    assert short_report.retries_expected is True

    # Extended outage -> mail lost / bounces
    long_report = inspector.simulate_gateway_outage("sendgrid", outage_duration_hours=96.0)
    assert long_report.mail_lost is True
    assert long_report.retries_expected is False
