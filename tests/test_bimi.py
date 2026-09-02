"""
Unit tests for BIMI validation and VMC parsing.
"""
from unittest.mock import MagicMock
import dns.resolver
from auth_checker.bimi import BIMIResultCode, check_bimi


def test_bimi_no_record():
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
    res = check_bimi("example.com", resolver=mock_resolver)
    assert res.code == BIMIResultCode.NONE
    assert res.record_found is False


def test_bimi_valid_record():
    mock_resolver = MagicMock()
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;"]
    mock_answers = [mock_rdata]
    mock_resolver.resolve.return_value = mock_answers

    res = check_bimi("example.com", resolver=mock_resolver)
    assert res.code == BIMIResultCode.VALID
    assert res.record_found is True
    assert res.location_url == "https://example.com/logo.svg"
    assert res.authority_url == "https://example.com/vmc.pem"
    assert res.vmc_present is True
