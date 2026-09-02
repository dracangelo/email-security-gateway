import pytest
from attachment_analysis import extract_attachments
from attachment_analysis.archives import inspect_and_extract_archive
from attachment_analysis.document_analysis import inspect_document_attachment
from security.fuzzer import Fuzzer
from webhook_receiver.parsers import parse_sendgrid_payload


def test_fuzz_mime_and_attachment_parsers():
    seed_mime = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Fuzz Test\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Hello world\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/zip\r\n"
        b"Content-Disposition: attachment; filename=\"test.zip\"\r\n\r\n"
        b"PK\x03\x04\x0a\x00\x00\x00\x00\x00\x00\x00"
        b"--BOUNDARY--"
    )

    def _target(payload: bytes):
        # 1. Test attachment extraction
        attachments = extract_attachments(payload)
        for att in attachments:
            # 2. Test archive extraction on attachment content
            if att.filename.endswith(".zip"):
                inspect_and_extract_archive(att.filename, att.data)
            # 3. Test document structural parsing
            if att.filename.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")):
                inspect_document_attachment(att.filename, att.data)

    crashes = Fuzzer.fuzz_target(_target, seed_corpus=[seed_mime], iterations=50)
    assert len(crashes) == 0, f"Fuzzing detected {len(crashes)} uncaught parser crashes: {crashes[:2]}"


def test_fuzz_sendgrid_parser():
    def _target(payload: bytes):
        try:
            payload_str = payload.decode("utf-8", errors="ignore")
            form_data = {"email": payload_str, "from": "test@domain.com"}
            parse_sendgrid_payload(form_data)
        except Exception as e:
            if isinstance(e, (ValueError, KeyError, TypeError, AttributeError)):
                return
            raise e

    crashes = Fuzzer.fuzz_target(_target, seed_corpus=[b"email=hello&headers=123"], iterations=30)
    assert len(crashes) == 0
