"""
Unit tests for FCrDNS (Forward-Confirmed Reverse DNS) consistency check.
"""
from unittest.mock import MagicMock
from auth_checker.fcrdns import FCrDNSResultCode, check_fcrdns


def test_fcrdns_loopback():
    res = check_fcrdns("127.0.0.1")
    assert res.code == FCrDNSResultCode.PASS
    assert res.is_confirmed is True


def test_fcrdns_confirmed_match():
    mock_resolver = MagicMock()
    mock_ptr = MagicMock()
    mock_ptr.target = "mail.example.com."

    mock_a = MagicMock()
    mock_a.__str__ = lambda self: "203.0.113.50"

    def mock_resolve(name, qtype, lifetime=5.0):
        if qtype == "PTR":
            return [mock_ptr]
        if qtype == "A":
            return [mock_a]
        raise Exception("NXDOMAIN")

    mock_resolver.resolve.side_effect = mock_resolve

    res = check_fcrdns("203.0.113.50", resolver=mock_resolver)
    assert res.code == FCrDNSResultCode.PASS
    assert res.is_confirmed is True
    assert res.ptr_hostname == "mail.example.com"


def test_fcrdns_mismatch():
    mock_resolver = MagicMock()
    mock_ptr = MagicMock()
    mock_ptr.target = "spoofed.attacker.com."

    mock_a = MagicMock()
    mock_a.__str__ = lambda self: "198.51.100.99"  # does not match client_ip

    def mock_resolve(name, qtype, lifetime=5.0):
        if qtype == "PTR":
            return [mock_ptr]
        if qtype == "A":
            return [mock_a]
        raise Exception("NXDOMAIN")

    mock_resolver.resolve.side_effect = mock_resolve

    res = check_fcrdns("203.0.113.50", resolver=mock_resolver)
    assert res.code == FCrDNSResultCode.FAIL
    assert res.is_confirmed is False
