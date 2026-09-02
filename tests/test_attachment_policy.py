"""
Unit tests for per-org attachment policy engine.
"""
from attachment_analysis.policy import OrgAttachmentPolicy, evaluate_attachment_policy


def test_attachment_policy_allowed():
    policy = OrgAttachmentPolicy()
    res = evaluate_attachment_policy("report.pdf", size_bytes=1024, has_macros=False, policy=policy)
    assert res.is_blocked is False


def test_attachment_policy_blocked_ext():
    policy = OrgAttachmentPolicy(blocked_extensions={".exe", ".bat", ".iso"})
    res = evaluate_attachment_policy("payload.iso", size_bytes=1024, policy=policy)
    assert res.is_blocked is True
    assert res.score_delta >= 50


def test_attachment_policy_macro_disallowed():
    policy = OrgAttachmentPolicy(allow_macros=False)
    res = evaluate_attachment_policy("financials.xlsm", size_bytes=2048, has_macros=True, policy=policy)
    assert res.is_blocked is True
    assert res.score_delta >= 50
