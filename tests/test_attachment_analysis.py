import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attachment_analysis.extensions import is_dangerous_extension, is_double_extension
from attachment_analysis.extract import extract_attachments
from attachment_analysis.models import Attachment
from attachment_analysis.pipeline import analyze_attachments
from attachment_analysis.reputation import ClamAVScanner, FileReputationProvider


def _run(coro):
    return asyncio.run(coro)


def _build_message_with_attachment(filename: str, content: bytes, content_type: str = "application/octet-stream") -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "test"
    msg.set_content("see attached")
    maintype, subtype = content_type.split("/", 1)
    msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


class FakeFileReputationProvider(FileReputationProvider):
    def __init__(self, verdicts: dict[str, str]):
        self.verdicts = verdicts

    async def check_hash(self, sha256: str) -> tuple[str, str]:
        return self.verdicts.get(sha256, "unknown"), "fake_provider"


class TestExtensionHeuristics:
    def test_dangerous_extension_flagged(self):
        assert is_dangerous_extension("invoice.exe") is True

    def test_benign_extension_not_flagged(self):
        assert is_dangerous_extension("invoice.pdf") is False

    def test_double_extension_flagged(self):
        assert is_double_extension("invoice.pdf.exe") is True

    def test_single_dangerous_extension_not_double(self):
        assert is_double_extension("invoice.exe") is False

    def test_two_benign_extensions_not_double(self):
        assert is_double_extension("archive.tar.gz") is False

    def test_case_insensitive(self):
        assert is_dangerous_extension("INVOICE.EXE") is True


class TestExtraction:
    def test_extracts_single_attachment(self):
        raw = _build_message_with_attachment("invoice.pdf", b"%PDF-1.4 fake pdf content", "application/pdf")
        attachments = extract_attachments(raw)
        assert len(attachments) == 1
        assert attachments[0].filename == "invoice.pdf"
        assert b"fake pdf" in attachments[0].data

    def test_no_attachments_on_plain_message(self):
        raw = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: hi\r\n\r\nplain body, no multipart"
        assert extract_attachments(raw) == []

    def test_malformed_message_returns_empty_not_crash(self):
        assert extract_attachments(b"\xff\xfe not a valid email at all") == []


class TestAttachmentPipeline:
    def test_clean_pdf_scores_zero(self):
        att = Attachment(filename="report.pdf", content_type="application/pdf", data=b"clean pdf bytes")
        result = _run(analyze_attachments([att], file_reputation_provider=FakeFileReputationProvider({})))
        assert result.score_delta == 0
        assert result.findings[0].sha256  # was hashed

    def test_exe_extension_flagged(self):
        att = Attachment(filename="setup.exe", content_type="application/octet-stream", data=b"MZ fake exe")
        result = _run(analyze_attachments([att], file_reputation_provider=FakeFileReputationProvider({})))
        assert result.findings[0].is_dangerous_extension is True
        assert result.score_delta >= 25

    def test_double_extension_scores_higher_than_single(self):
        att1 = Attachment(filename="invoice.pdf.exe", content_type="application/octet-stream", data=b"payload-a")
        att2 = Attachment(filename="setup.exe", content_type="application/octet-stream", data=b"payload-b")
        r1 = _run(analyze_attachments([att1], file_reputation_provider=FakeFileReputationProvider({})))
        r2 = _run(analyze_attachments([att2], file_reputation_provider=FakeFileReputationProvider({})))
        assert r1.score_delta > r2.score_delta

    def test_malicious_hash_dominates_score(self):
        att = Attachment(filename="report.pdf", content_type="application/pdf", data=b"malware payload")
        import hashlib
        digest = hashlib.sha256(b"malware payload").hexdigest()
        result = _run(analyze_attachments([att], file_reputation_provider=FakeFileReputationProvider({digest: "malicious"})))
        assert result.score_delta >= 100
        assert result.findings[0].file_reputation == "malicious"

    def test_oversized_attachment_not_hashed_but_flagged(self):
        att = Attachment(filename="huge.zip", content_type="application/zip", data=b"x" * 1000)
        result = _run(analyze_attachments([att], max_attachment_size_bytes=500,
                                           file_reputation_provider=FakeFileReputationProvider({})))
        assert result.findings[0].is_oversized is True
        assert result.findings[0].sha256 == ""  # not hashed
        assert result.score_delta > 0

    def test_attachment_count_truncated_and_flagged(self):
        atts = [Attachment(filename=f"f{i}.txt", content_type="text/plain", data=b"x") for i in range(5)]
        result = _run(analyze_attachments(atts, max_attachments=2, file_reputation_provider=FakeFileReputationProvider({})))
        assert len(result.findings) == 2
        assert result.score_delta >= 10  # truncation penalty

    def test_no_attachments_scores_zero(self):
        result = _run(analyze_attachments([], file_reputation_provider=FakeFileReputationProvider({})))
        assert result.score_delta == 0
        assert result.findings == []


class TestClamAVScanner:
    def test_disabled_returns_not_scanned(self):
        scanner = ClamAVScanner(host="")  # no host configured
        result = _run(scanner.scan(b"any data"))
        assert result == "not_scanned"

    def test_connection_failure_fails_open_not_crash(self):
        # Points at a host/port nothing is listening on -- should degrade
        # to an "error:" result rather than raising and taking the whole
        # pipeline down with it.
        scanner = ClamAVScanner(host="127.0.0.1", port=1, timeout=1.0)
        result = _run(scanner.scan(b"any data"))
        assert result.startswith("error:")
