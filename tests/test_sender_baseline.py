"""
Unit tests for Historical Sender-Domain Baseline tracking.
"""
from auth_checker.sender_baseline import SenderBaselineStore, evaluate_sender_baseline


def test_sender_baseline_first_contact_and_ip_anomaly():
    store = SenderBaselineStore()

    # 1. First contact for new domain
    v1 = evaluate_sender_baseline("newdomain.com", "203.0.113.10", store=store)
    assert v1.is_first_contact is True
    assert v1.score_delta == 10
    assert v1.total_messages_seen == 1

    # 2. Subsequent contacts from same IP subnet
    for _ in range(10):
        evaluate_sender_baseline("newdomain.com", "203.0.113.12", store=store)

    v2 = evaluate_sender_baseline("newdomain.com", "203.0.113.15", store=store)
    assert v2.is_first_contact is False
    assert v2.is_ip_anomaly is False

    # 3. Contact from completely new subnet after baseline established
    v3 = evaluate_sender_baseline("newdomain.com", "198.51.100.99", store=store)
    assert v3.is_ip_anomaly is True
    assert v3.score_delta == 10
