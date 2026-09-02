"""
Unit tests for sender-recipient relationship graph and thread-hijacking BEC detector.
"""
from content_analysis.relationship_graph import RelationshipGraphStore, detect_thread_hijacking_and_relationship


def test_relationship_and_thread_hijack():
    store = RelationshipGraphStore()

    # Normal email first
    res1 = detect_thread_hijacking_and_relationship("vendor@supplier.com", "billing@company.com", store=store)
    assert res1.is_first_contact_pair is True
    assert res1.is_thread_hijack is False

    # Thread reply with financial change attempt
    res2 = detect_thread_hijacking_and_relationship(
        "vendor@supplier.com",
        "billing@company.com",
        in_reply_to="<msg-123@company.com>",
        body_text="Re: Invoice #104. Please note our new bank account details and IBAN for payment.",
        store=store,
    )
    assert res2.is_first_contact_pair is False
    assert res2.is_thread_hijack is True
    assert res2.score_delta >= 40
