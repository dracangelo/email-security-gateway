"""
Unit & Integration Tests for Enterprise Security Platform Features:
- PSL DMARC resolution
- Homoglyphs, IDNs, and zero-width obfuscation
- Display-name spoofing and Reply-To mismatch
- Magic bytes verification & recursive zip archive scanning
- NDR/Bounce loop prevention
- Tag-only mode RFC 5322 header tagging
- Admin API audit logging
"""
import io
import zipfile
import pytest
from unittest.mock import MagicMock

from auth_checker.dmarc import _org_domain
from content_analysis.homoglyphs import detect_homoglyphs_and_idn, strip_zero_width
from content_analysis.display_name import check_display_name_spoofing, check_reply_to_mismatch
from attachment_analysis.magic_bytes import verify_file_magic
from attachment_analysis.archives import inspect_and_extract_archive
from security.bounce_detector import is_bounce_or_ndr
from delivery.modify import apply_tag_only
from audit.logger import AuditLogger


class TestPSLDmarc:
    def test_psl_co_uk_domain(self):
        assert _org_domain("sub.example.co.uk") == "example.co.uk"

    def test_psl_github_io_domain(self):
        assert _org_domain("myblog.github.io") == "myblog.github.io"

    def test_psl_standard_com_domain(self):
        assert _org_domain("mail.sub.example.com") == "example.com"


class TestHomoglyphsAndZeroWidth:
    def test_zero_width_stripping(self):
        obfuscated = "p\u200ba\u200by\u200bp\u200ba\u200bl"
        assert strip_zero_width(obfuscated) == "paypal"

    def test_zero_width_detection(self):
        obfuscated = "act\u200bion required"
        findings = detect_homoglyphs_and_idn(obfuscated)
        assert len(findings) > 0
        assert findings[0].has_zero_width is True

    def test_punycode_detection(self):
        idn_domain = "xn--pypal-4ve.com"
        findings = detect_homoglyphs_and_idn(idn_domain)
        assert any(f.is_punycode for f in findings)


class TestDisplayNameAndReplyTo:
    def test_vip_display_name_spoofing(self):
        from_hdr = "Jane Doe CEO <attacker@evil-domain.com>"
        protected_vips = ["Jane Doe CEO", "John Smith CFO"]
        is_spoofed, reason = check_display_name_spoofing(from_hdr, protected_vips)
        assert is_spoofed is True
        assert "Jane Doe CEO" in reason

    def test_legitimate_display_name(self):
        from_hdr = "Support Team <support@company.com>"
        protected_vips = ["Jane Doe CEO"]
        is_spoofed, _ = check_display_name_spoofing(from_hdr, protected_vips)
        assert is_spoofed is False

    def test_reply_to_mismatch(self):
        from_hdr = "CEO <ceo@company.com>"
        reply_hdr = "CEO <ceo-mailbox@external-phish.com>"
        is_mismatch, reason = check_reply_to_mismatch(from_hdr, reply_hdr)
        assert is_mismatch is True
        assert "Reply-To domain mismatch" in reason


class TestAttachmentHardening:
    def test_executable_disguised_as_pdf(self):
        exe_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00"
        res = verify_file_magic("invoice.pdf", exe_data)
        assert res.is_extension_spoofed is True
        assert "Windows Executable" in res.detected_type

    def test_valid_pdf_magic(self):
        pdf_data = b"%PDF-1.4 header bytes..."
        res = verify_file_magic("invoice.pdf", pdf_data)
        assert res.is_extension_spoofed is False

    def test_zip_archive_extraction(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("nested_doc.pdf", b"hello pdf")
            zf.writestr("nested_script.exe", b"MZ fake exe")
        buf.seek(0)

        arc_res = inspect_and_extract_archive("archive.zip", buf.getvalue())
        assert arc_res.is_archive is True
        assert arc_res.is_encrypted is False
        assert len(arc_res.extracted_attachments) == 2
        filenames = [att.filename for att in arc_res.extracted_attachments]
        assert "nested_doc.pdf" in filenames
        assert "nested_script.exe" in filenames

    def test_encrypted_zip_detection(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(b"secret_password")
            zf.writestr("secret.txt", b"encrypted content", compress_type=zipfile.ZIP_DEFLATED)
            # Ensure flag_bits is marked as encrypted in zip header
            for zinfo in zf.filelist:
                zinfo.flag_bits |= 0x1
        buf.seek(0)

        arc_res = inspect_and_extract_archive("locked.zip", buf.getvalue())
        assert arc_res.is_archive is True
        assert arc_res.is_encrypted is True



class TestBounceDetector:
    def test_empty_envelope_from(self):
        is_b, reason = is_bounce_or_ndr("<>")
        assert is_b is True

    def test_mailer_daemon(self):
        is_b, reason = is_bounce_or_ndr("mailer-daemon@remote.server.com")
        assert is_b is True

    def test_auto_submitted_header(self):
        headers = "From: bot@site.com\r\nAuto-Submitted: auto-generated\r\n"
        is_b, reason = is_bounce_or_ndr("bot@site.com", headers)
        assert is_b is True

    def test_delivery_status_notification(self):
        headers = "Content-Type: multipart/report; report-type=delivery-status\r\n"
        is_b, reason = is_bounce_or_ndr("user@domain.com", headers)
        assert is_b is True


class TestTagOnlyMode:
    def test_tag_only_verdict_header(self):
        raw = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nBody text"
        tagged = apply_tag_only(raw, score=85, action="quarantine", reasons=["failed DMARC", "malicious link"])
        assert b"X-Gateway-Verdict: quarantine" in tagged
        assert b"X-Gateway-Score: 85" in tagged
        assert b"X-Gateway-Reasons: failed DMARC; malicious link" in tagged


import asyncio

def test_admin_audit_logging(tmp_path):
    log_file = tmp_path / "admin_audit.jsonl"
    logger = AuditLogger(str(log_file))

    asyncio.run(logger.record_admin_action(operator="secops_admin", action="release", target_id="quarantine_123", note="false positive"))
    entries = logger.read_all()

    assert len(entries) == 1
    assert entries[0]["event_type"] == "admin_action"
    assert entries[0]["operator"] == "secops_admin"
    assert entries[0]["target_id"] == "quarantine_123"

