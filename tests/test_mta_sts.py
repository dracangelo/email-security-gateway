"""
Unit tests for MTA-STS checking, TLS downgrade verification, and TLS-RPT report generation.
"""
from auth_checker.mta_sts import (
    MTASTSPolicy,
    check_mta_sts,
    generate_tls_rpt,
    parse_mta_sts_policy,
)
from auth_checker.models import MTASTSResultCode
from auth_checker.pipeline import run_auth_checks


def test_parse_mta_sts_policy():
    policy_text = """
    version: STSv1
    mode: enforce
    max_age: 604800
    mx: mail.example.com
    mx: *.example.com
    """
    pol = parse_mta_sts_policy(policy_text)
    assert pol.version == "STSv1"
    assert pol.mode == "enforce"
    assert pol.max_age == 604800
    assert "mail.example.com" in pol.mx
    assert "*.example.com" in pol.mx


def test_check_mta_sts_enforce_pass():
    pol = MTASTSPolicy(mode="enforce")
    headers = "Received: from mail.example.com using TLSv1.3 with ESMTPS"
    res = check_mta_sts("example.com", headers_blob=headers, policy=pol)
    assert res.code == MTASTSResultCode.VALID
    assert res.tls_used is True
    assert res.mode == "enforce"


def test_check_mta_sts_enforce_fail():
    pol = MTASTSPolicy(mode="enforce")
    headers = "Received: from mail.example.com with SMTP"
    res = check_mta_sts("example.com", headers_blob=headers, policy=pol)
    assert res.code == MTASTSResultCode.ENFORCE_FAILED
    assert res.tls_used is False
    assert "cleartext transport" in res.explanation


def test_generate_tls_rpt():
    pol = MTASTSPolicy(mode="enforce")
    res = check_mta_sts("example.com", headers_blob="Received: cleartext", policy=pol)
    rpt = generate_tls_rpt("example.com", res)
    assert rpt["organization-name"] == "Email Auth Gateway"
    assert rpt["policies"][0]["summary"]["total-failure-session-count"] == 1


def test_run_auth_checks_with_mta_sts():
    msg = b"From: alice@example.com\r\nTo: bob@example.com\r\nReceived: using TLSv1.3\r\n\r\nTest body"
    verdict = run_auth_checks(msg, client_ip="127.0.0.1", envelope_from="alice@example.com")
    assert verdict.mta_sts is not None
    assert verdict.mta_sts.tls_used is True
