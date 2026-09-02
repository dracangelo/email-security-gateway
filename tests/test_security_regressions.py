"""
Security Regression Test Suite.
Maintains regression tests against known evasion, obfuscation, and bypass techniques.
"""
import pytest
from content_analysis.homoglyphs import strip_zero_width, detect_homoglyphs_and_idn
from content_analysis.html_evasion import detect_html_evasion
from content_analysis.rtl_detector import detect_rtl_override
from content_analysis.qr_detector import detect_qr_codes
from attachment_analysis.extensions import is_dangerous_extension, is_double_extension
from attachment_analysis.polyglot import detect_polyglot_file
from attachment_analysis.policy import evaluate_attachment_policy


@pytest.mark.security_regression
class TestSecurityRegressions:
    """Regression tests for phishing evasion and bypass techniques."""

    def test_zero_width_keyword_evasion(self):
        """Bypass: Attacker inserts zero-width spaces (\u200B) inside 'password' or 'urgent'."""
        obfuscated = "p\u200ba\u200ds\u200cs\u200dw\u200eo\u200br\u200cd"
        cleaned = strip_zero_width(obfuscated)
        assert cleaned == "password"

        findings = detect_homoglyphs_and_idn(obfuscated)
        assert any(f.has_zero_width for f in findings)

    def test_punycode_and_homoglyph_detection(self):
        """Bypass: Attacker registers punycode domain with Cyrillic lookalike."""
        punycode_domain = "xn--pple-43d.com"  # apple lookalike
        findings = detect_homoglyphs_and_idn(punycode_domain)
        assert any(f.is_punycode for f in findings)

    def test_rtl_override_filename_spoofing(self):
        """Bypass: Attacker uses Unicode Right-To-Left Override (U+202E) to disguise .exe as .pdf."""
        # invoice[U+202E]fdp.exe -> renders as invoiceexe.pdf
        spoofed_filename = "invoice\u202efdp.exe"
        finding = detect_rtl_override(text="", filename=spoofed_filename)
        assert finding.has_rtl_override is True
        assert finding.is_filename_spoof is True

    def test_double_extension_executable_masking(self):
        """Bypass: Attacker names malicious payload Q4_Report.pdf.exe or invoice.docx.vbs."""
        assert is_dangerous_extension("Q4_Financial_Report.pdf.exe") is True
        assert is_double_extension("Q4_Financial_Report.pdf.exe") is True

        policy_res = evaluate_attachment_policy("invoice.docx.vbs", size_bytes=1024)
        assert policy_res.is_blocked is True
        assert any(".vbs" in r.lower() for r in policy_res.reasons)

    def test_html_css_hidden_text_evasion(self):
        """Bypass: Phishing keywords hidden or padded with display:none text."""
        raw_html = """
        <p>Dear user,</p>
        <span style="display:none">This is normal business discussion.</span>
        <p>Your password expires today. <a href="http://evil.com/reset">Click here</a></p>
        """
        finding = detect_html_evasion(raw_html)
        assert finding.has_evasion is True
        assert "display:none" in finding.evasion_techniques
        assert "normal business discussion" in finding.hidden_text

    def test_polyglot_gif_php_detection(self):
        """Bypass: File containing GIF89a header and conflicting ZIP signature (GIF+ZIP polyglot)."""
        polyglot_payload = b"GIF89a\x01\x00\x01\x00PK\x03\x04\x00\x00\x00\x00malicious_embedded_archive"
        res = detect_polyglot_file(polyglot_payload)
        assert res.is_polyglot is True
        assert "GIF" in res.detected_formats
        assert "ZIP" in res.detected_formats

    def test_quishing_qr_code_detection_in_attachment(self):
        """Bypass: Phishing URL embedded inside an attached QR code image."""
        fake_qr_stream = b"GIF89a https://phishing-portal.com/login DATA"
        res = detect_qr_codes([fake_qr_stream])
        assert res.has_qr_code is True
        assert "https://phishing-portal.com/login" in res.decoded_urls
