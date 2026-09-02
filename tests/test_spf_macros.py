"""
Unit tests for SPF Macro expansion and exists: mechanisms.
"""
from unittest.mock import MagicMock
from auth_checker.spf import check_spf, expand_spf_macros


def test_expand_spf_macros():
    # Sender: alice@sub.example.com, Domain: example.com, IP: 1.2.3.4
    sender = "alice@sub.example.com"
    domain = "example.com"
    ip = "1.2.3.4"

    res = expand_spf_macros("%{s}", sender, domain, ip)
    assert res == "alice@sub.example.com"

    res_l = expand_spf_macros("%{l}", sender, domain, ip)
    assert res_l == "alice"

    res_o = expand_spf_macros("%{o}", sender, domain, ip)
    assert res_o == "sub.example.com"

    res_d = expand_spf_macros("%{d}", sender, domain, ip)
    assert res_d == "example.com"

    res_i = expand_spf_macros("%{i}", sender, domain, ip)
    assert res_i == "1.2.3.4"

    # Modifiers: reverse & count
    res_r = expand_spf_macros("%{ir}._spf.%{d}", sender, domain, ip)
    assert res_r == "4.3.2.1._spf.example.com"


def test_spf_exists_mechanism():
    mock_resolver = MagicMock()
    # Mock TXT for spf record
    mock_txt = MagicMock()
    mock_txt.strings = [b"v=spf1 exists:%{i}._spf.%{d} -all"]

    def mock_resolve(target, qtype, lifetime=5.0):
        if qtype == "TXT":
            return [mock_txt]
        if qtype == "A" and target == "1.2.3.4._spf.example.com":
            mock_a = MagicMock()
            mock_a.__str__ = lambda self: "127.0.0.2"
            return [mock_a]
        raise Exception("NXDOMAIN")

    mock_resolver.resolve.side_effect = mock_resolve

    spf_res = check_spf("example.com", "1.2.3.4", resolver=mock_resolver, sender="alice@example.com")
    assert spf_res.code.value == "pass"
