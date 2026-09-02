"""
Unit tests for DNSSEC validation helpers.
"""
from unittest.mock import MagicMock
import dns.flags
from auth_checker.dnssec import create_dnssec_resolver, is_dnssec_authenticated, resolve_with_dnssec


def test_create_dnssec_resolver():
    resolver = create_dnssec_resolver()
    assert resolver is not None
    assert resolver.edns >= 0


def test_is_dnssec_authenticated():
    mock_answer = MagicMock()
    mock_answer.response.flags = dns.flags.AD | dns.flags.QR
    assert is_dnssec_authenticated(mock_answer) is True

    mock_answer_no_ad = MagicMock()
    mock_answer_no_ad.response.flags = dns.flags.QR
    assert is_dnssec_authenticated(mock_answer_no_ad) is False


def test_resolve_with_dnssec():
    mock_resolver = MagicMock()
    mock_rdata = MagicMock()
    mock_rdata.__str__ = lambda self: "v=spf1 -all"
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_rdata])
    mock_answer.response.flags = dns.flags.AD

    mock_resolver.resolve.return_value = mock_answer

    records, res = resolve_with_dnssec("example.com", "TXT", resolver=mock_resolver)
    assert len(records) == 1
    assert res.is_secure is True
