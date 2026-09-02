"""
Unit tests for ARC (Authenticated Received Chain) validation.
"""
from auth_checker.arc import ARCResultCode, check_arc


def test_arc_none():
    msg = b"From: alice@example.com\r\nTo: bob@example.com\r\n\r\nNo ARC headers"
    res = check_arc(msg)
    assert res.code == ARCResultCode.NONE
    assert res.instance_count == 0


def test_arc_header_parsing_pass():
    msg = (
        b"ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.com; s=arc;\r\n"
        b"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;\r\n"
        b"ARC-Authentication-Results: i=1; mx.google.com; spf=pass\r\n"
        b"From: alice@example.com\r\n\r\nTest body"
    )
    res = check_arc(msg)
    assert res.code == ARCResultCode.PASS
    assert res.instance_count == 1


def test_arc_header_parsing_fail():
    msg = (
        b"ARC-Seal: i=1; a=rsa-sha256; cv=fail; d=example.com; s=arc;\r\n"
        b"From: alice@example.com\r\n\r\nTest body"
    )
    res = check_arc(msg)
    assert res.code == ARCResultCode.FAIL
    assert res.instance_count == 1
