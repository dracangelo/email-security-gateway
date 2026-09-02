"""
Unit tests. All DNS is mocked (no real network calls) except the DKIM
round-trip, which generates a throwaway RSA key, signs a test message with
it, and injects the matching public key as a fake DNS answer -- exercising
the real dkimpy crypto path without needing an actual published record.

Run with:  python3 -m pytest tests/ -v
"""
from __future__ import annotations

import base64
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_checker.alignment import evaluate_dmarc
from auth_checker.dmarc import fetch_dmarc_policy, _org_domain
from auth_checker.models import DKIMResultCode, DMARCPolicy, DMARCResultCode, SPFResultCode
from auth_checker.spf import check_spf


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fake_resolver(txt_map: dict[str, list[bytes]], a_map: dict | None = None, mx_map: dict | None = None):
    """
    txt_map: {"example.com": [b"v=spf1 -all"]} -- each list entry becomes its
    own separate TXT record (so a two-item list simulates two published
    records at the same name, e.g. for the "multiple SPF records" test).
    Returns a MagicMock standing in for dns.resolver.Resolver.
    """
    a_map = a_map or {}
    mx_map = mx_map or {}

    def resolve(qname, rdtype, lifetime=None):
        qname = qname.rstrip(".")
        if rdtype == "TXT":
            if qname in txt_map:
                answers = []
                for record_bytes in txt_map[qname]:
                    rdata = MagicMock()
                    rdata.strings = [record_bytes]
                    answers.append(rdata)
                return answers
            raise dns.resolver.NXDOMAIN()
        if rdtype in ("A", "AAAA"):
            if qname in a_map:
                return [MagicMock(__str__=lambda self, ip=ip: ip) for ip in a_map[qname]]
            raise dns.resolver.NXDOMAIN()
        if rdtype == "MX":
            if qname in mx_map:
                out = []
                for host in mx_map[qname]:
                    m = MagicMock()
                    m.exchange = host
                    out.append(m)
                return out
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NXDOMAIN()

    resolver = MagicMock()
    resolver.resolve.side_effect = resolve
    return resolver


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

class TestSPF:
    def test_ip4_pass(self):
        resolver = _fake_resolver({"example.com": [b"v=spf1 ip4:203.0.113.0/24 -all"]})
        result = check_spf("example.com", "203.0.113.10", resolver)
        assert result.code == SPFResultCode.PASS

    def test_hardfail_outside_range(self):
        resolver = _fake_resolver({"example.com": [b"v=spf1 ip4:203.0.113.0/24 -all"]})
        result = check_spf("example.com", "198.51.100.5", resolver)
        assert result.code == SPFResultCode.FAIL

    def test_softfail(self):
        resolver = _fake_resolver({"example.com": [b"v=spf1 ip4:203.0.113.0/24 ~all"]})
        result = check_spf("example.com", "198.51.100.5", resolver)
        assert result.code == SPFResultCode.SOFTFAIL

    def test_no_record(self):
        resolver = _fake_resolver({})
        result = check_spf("example.com", "203.0.113.10", resolver)
        assert result.code == SPFResultCode.NONE

    def test_include_mechanism(self):
        resolver = _fake_resolver({
            "example.com": [b"v=spf1 include:_spf.mailer.com -all"],
            "_spf.mailer.com": [b"v=spf1 ip4:203.0.113.0/24 -all"],
        })
        result = check_spf("example.com", "203.0.113.10", resolver)
        assert result.code == SPFResultCode.PASS

    def test_multiple_spf_records_is_permerror(self):
        resolver = _fake_resolver({"example.com": [b"v=spf1 -all", b"v=spf1 +all"]})
        result = check_spf("example.com", "203.0.113.10", resolver)
        assert result.code == SPFResultCode.PERMERROR

    def test_too_many_includes_is_permerror(self):
        txt_map = {"example.com": [b"v=spf1 " + " ".join(f"include:s{i}.com" for i in range(15)).encode() + b" -all"]}
        for i in range(15):
            txt_map[f"s{i}.com"] = [b"v=spf1 -all"]
        resolver = _fake_resolver(txt_map)
        result = check_spf("example.com", "203.0.113.10", resolver)
        assert result.code == SPFResultCode.PERMERROR


# ---------------------------------------------------------------------------
# DMARC + alignment
# ---------------------------------------------------------------------------

class TestDMARCAlignment:
    def test_org_domain_heuristic(self):
        assert _org_domain("mail.example.com") == "example.com"
        assert _org_domain("example.com") == "example.com"

    def test_no_dmarc_record(self):
        resolver = _fake_resolver({})
        result = fetch_dmarc_policy("example.com", resolver)
        assert result.code == DMARCResultCode.NONE

    def test_relaxed_alignment_pass_via_spf(self):
        from auth_checker.models import SPFResult

        resolver = _fake_resolver({"_dmarc.example.com": [b"v=DMARC1; p=reject; aspf=r;"]})
        dmarc_record = fetch_dmarc_policy("example.com", resolver)

        spf_result = SPFResult(code=SPFResultCode.PASS, domain="mail.example.com", client_ip="203.0.113.10")
        from auth_checker.models import DKIMResult

        dkim_result = DKIMResult(code=DKIMResultCode.NONE)

        verdict = evaluate_dmarc("example.com", spf_result, dkim_result, dmarc_record)
        assert verdict.code == DMARCResultCode.PASS
        assert verdict.spf_aligned is True

    def test_strict_alignment_fails_on_subdomain(self):
        from auth_checker.models import DKIMResult, SPFResult

        resolver = _fake_resolver({"_dmarc.example.com": [b"v=DMARC1; p=reject; aspf=s;"]})
        dmarc_record = fetch_dmarc_policy("example.com", resolver)

        spf_result = SPFResult(code=SPFResultCode.PASS, domain="mail.example.com", client_ip="203.0.113.10")
        dkim_result = DKIMResult(code=DKIMResultCode.NONE)

        verdict = evaluate_dmarc("example.com", spf_result, dkim_result, dmarc_record)
        assert verdict.code == DMARCResultCode.FAIL  # mail.example.com != example.com under strict mode

    def test_missing_p_tag_is_permerror(self):
        resolver = _fake_resolver({"_dmarc.example.com": [b"v=DMARC1; pct=100;"]})
        result = fetch_dmarc_policy("example.com", resolver)
        assert result.code == DMARCResultCode.PERMERROR


# ---------------------------------------------------------------------------
# DKIM round-trip (real crypto, fake DNS)
# ---------------------------------------------------------------------------

class TestDKIMRoundTrip:
    def test_sign_and_verify_with_injected_key(self):
        pytest.importorskip("Crypto", reason="pycryptodome needed for DKIM sign() in this test")
        import dkim as dkimpy
        from auth_checker.dkim_check import check_dkim

        # Generate a throwaway keypair for the test only.
        from Crypto.PublicKey import RSA
        key = RSA.generate(1024)
        privkey_pem = key.export_key()
        pubkey_der_b64 = base64.b64encode(key.publickey().export_key(format="DER")).decode()

        message = (
            b"From: alerts@example.com\r\n"
            b"To: someone@recipient.com\r\n"
            b"Subject: test\r\n"
            b"\r\n"
            b"Hello world.\r\n"
        )

        signed = dkimpy.sign(
            message=message,
            selector=b"selector1",
            domain=b"example.com",
            privkey=privkey_pem,
            include_headers=[b"from", b"to", b"subject"],
        )
        signed_message = signed + message

        fake_txt_record = f"v=DKIM1; k=rsa; p={pubkey_der_b64}".encode()

        def fake_dnsfunc(name, timeout=5):
            return fake_txt_record.decode()

        result = check_dkim(signed_message, dnsfunc=fake_dnsfunc)
        assert result.code == DKIMResultCode.PASS
        assert result.signing_domain == "example.com"

    def test_no_signature_present(self):
        from auth_checker.dkim_check import check_dkim
        message = b"From: alerts@example.com\r\nTo: x@y.com\r\nSubject: hi\r\n\r\nBody\r\n"
        result = check_dkim(message)
        assert result.code == DKIMResultCode.NONE


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
