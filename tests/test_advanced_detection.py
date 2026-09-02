"""
Unit tests for Advanced Detection Capabilities:
- Allow-List / Block-List Policy Engine & Precedence Overrides
- SSRF-Safe URL Redirect Chain Resolution
- Office VBA Macro & PDF Structural Inspection
- DKIM Cryptographic Key/Algorithm Policies
- IP Reputation Lookups
"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from decision_engine import Action, AllowBlockEngine, StageScore, decide

from content_analysis.url_redirects import is_ssrf_safe_ip, is_ssrf_safe_host, resolve_url_redirect_chain
from attachment_analysis.document_analysis import inspect_document_attachment
from auth_checker.dkim_policy import evaluate_dkim_policy
from auth_checker.ip_reputation import check_connecting_ip_reputation


class TestAllowBlockEngine:
    def test_blocklist_email_precedence(self):
        engine = AllowBlockEngine(
            block_emails=["badguy@evil.com"],
            allow_domains=["evil.com"]
        )
        res = engine.evaluate(envelope_from="badguy@evil.com")
        assert res.is_blocked is True
        assert res.is_allowed is False
        assert "blocklist" in res.reason

    def test_allowlist_domain_matches(self):
        engine = AllowBlockEngine(allow_domains=["trusted.com"])
        res = engine.evaluate(envelope_from="user@trusted.com")
        assert res.is_allowed is True
        assert res.is_blocked is False

    def test_blocklist_cidr_ip_matches(self):
        engine = AllowBlockEngine(block_ips=["198.51.100.0/24"])
        res = engine.evaluate(client_ip="198.51.100.42")
        assert res.is_blocked is True

    def test_decide_override_blocked(self):
        engine = AllowBlockEngine(block_domains=["bad.com"])
        ab_res = engine.evaluate(envelope_from="spammer@bad.com")
        
        scores = [StageScore(stage="auth", score_delta=0, reasons=[])]
        decision = decide(scores, allow_block_result=ab_res)
        assert decision.action == Action.QUARANTINE
        assert "policy override" in decision.all_reasons[0]

    def test_decide_override_allowed_unless_malware(self):
        engine = AllowBlockEngine(allow_domains=["partner.com"])
        ab_res = engine.evaluate(envelope_from="friend@partner.com")

        # High heuristic score without malware -> Forward via policy override
        scores = [StageScore(stage="auth", score_delta=80, reasons=["high score"])]
        decision = decide(scores, allow_block_result=ab_res)
        assert decision.action == Action.FORWARD

        # Malware present (score >= 100) -> Override does NOT bypass
        malware_scores = [StageScore(stage="attachment", score_delta=100, reasons=["ClamAV hit"])]
        malware_decision = decide(malware_scores, allow_block_result=ab_res)
        assert malware_decision.action == Action.QUARANTINE


class TestSSRFRedirectResolver:
    def test_ssrf_forbidden_ips(self):
        assert is_ssrf_safe_ip("127.0.0.1") is False
        assert is_ssrf_safe_ip("10.0.1.5") is False
        assert is_ssrf_safe_ip("172.16.0.10") is False
        assert is_ssrf_safe_ip("192.168.1.1") is False
        assert is_ssrf_safe_ip("169.254.169.254") is False
        assert is_ssrf_safe_ip("8.8.8.8") is True

    def test_ssrf_forbidden_hosts(self):
        assert is_ssrf_safe_host("localhost") is False
        assert is_ssrf_safe_host("169.254.169.254") is False

    @pytest.mark.anyio
    async def test_redirect_resolver_ssrf_block(self):
        final_url, hops = await resolve_url_redirect_chain("http://127.0.0.1/admin")
        assert final_url == "http://127.0.0.1/admin"
        assert hops == []


class TestDocumentInspection:
    def test_office_zip_macro_detection(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("word/vbaProject.bin", b"VBA binary data dummy")
            zf.writestr("word/document.xml", b"<xml>AutoOpen</xml>")

        res = inspect_document_attachment("invoice.docm", buf.getvalue())
        assert res.has_macros is True
        assert any("VBA macro project" in r for r in res.reasons)

    def test_legacy_office_binary_macro_detection(self):
        data = b"Some header info ... vbaProject.bin ... AutoOpen script"
        res = inspect_document_attachment("report.doc", data)
        assert res.has_macros is True

    def test_pdf_javascript_and_autoaction_detection(self):
        pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /JS (app.alert('XSS')) /OpenAction 3 0 R >>\nendobj"
        res = inspect_document_attachment("document.pdf", pdf_data)
        assert res.has_pdf_javascript is True
        assert res.has_pdf_auto_action is True


class TestDKIMPolicyAndIPReputation:
    def test_deprecated_sha1_dkim(self):
        hdr = "DKIM-Signature: v=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; s=s1;"
        res = evaluate_dkim_policy(hdr)
        assert res.is_deprecated_alg is True
        assert res.score_delta == 20

    def test_connecting_ip_reputation_clean_local(self):
        res = check_connecting_ip_reputation("127.0.0.1")
        assert res.is_listed is False
