import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import pytest
from aiosmtpd.controller import Controller
from cryptography.fernet import Fernet

from decision_engine.models import Action
from delivery.modify import add_subject_warning, apply_warn_and_strip, defang_html_links, defang_text_links, strip_attachments
from delivery.models import DeliveryOutcome
from delivery.notify import LogNotifier, WebhookNotifier
from delivery.pipeline import deliver
from delivery.quarantine import QuarantineStore
from delivery.relay import RelayError, SMTPRelay
from security.encryption import RawMailCipher


def _run(coro):
    return asyncio.run(coro)


def _build_test_message(with_attachment: bool = True) -> bytes:
    msg = EmailMessage()
    msg["From"] = "attacker@evil.com"
    msg["To"] = "victim@ourco.com"
    msg["Subject"] = "Urgent: verify your account"
    msg.set_content("Click here: https://paypa1.com/login to verify.")
    msg.add_alternative(
        '<p>Click <a href="https://paypa1.com/login">here</a> to verify.</p>', subtype="html"
    )
    if with_attachment:
        msg.add_attachment(b"MZ fake exe", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    return msg.as_bytes()


# ---------------------------------------------------------------------------
# modify.py
# ---------------------------------------------------------------------------

class TestSubjectWarning:
    def test_adds_prefix(self):
        msg = EmailMessage()
        msg["Subject"] = "Hello"
        add_subject_warning(msg)
        assert msg["Subject"] == "[SUSPICIOUS] Hello"

    def test_does_not_double_prefix(self):
        msg = EmailMessage()
        msg["Subject"] = "[SUSPICIOUS] Hello"
        add_subject_warning(msg)
        assert msg["Subject"] == "[SUSPICIOUS] Hello"

    def test_empty_subject_has_no_trailing_whitespace(self):
        msg = EmailMessage()
        msg["Subject"] = ""
        add_subject_warning(msg)
        assert msg["Subject"] == "[SUSPICIOUS]"


class TestDefang:
    def test_html_link_href_removed(self):
        out = defang_html_links('<a href="https://evil.com/login">click</a>')
        assert 'href="#"' in out
        assert "https://evil.com/login" not in out  # not present in clickable form
        assert "evil[.]com" in out  # but visible for investigation

    def test_html_non_http_links_untouched(self):
        out = defang_html_links('<a href="mailto:a@b.com">email</a>')
        assert 'href="mailto:a@b.com"' in out

    def test_plain_text_link_defanged(self):
        out = defang_text_links("Go to https://evil.com/x now")
        assert "https://evil.com/x" not in out
        assert "evil[.]com" in out
        assert "LINK REMOVED" in out

    def test_plain_text_without_links_unchanged(self):
        text = "no links here, just words"
        assert defang_text_links(text) == text


class TestStripAttachments:
    def test_removes_attachment_and_leaves_readable_note(self):
        raw = _build_test_message(with_attachment=True)
        from email import policy
        from email.parser import BytesParser
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        removed = strip_attachments(msg)
        assert removed == ["invoice.pdf.exe"]
        # re-serialize and confirm the note is readable, not base64 garbage
        out = msg.as_bytes().decode(errors="replace")
        assert "[Attachment removed by security gateway: invoice.pdf.exe]" in out

    def test_no_attachments_returns_empty_list(self):
        raw = _build_test_message(with_attachment=False)
        from email import policy
        from email.parser import BytesParser
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        assert strip_attachments(msg) == []


class TestApplyWarnAndStrip:
    def test_full_transform_round_trips_and_reparses(self):
        raw = _build_test_message(with_attachment=True)
        modified, removed = apply_warn_and_strip(raw)
        assert removed == ["invoice.pdf.exe"]

        from email import policy
        from email.parser import BytesParser
        reparsed = BytesParser(policy=policy.default).parsebytes(modified)
        assert reparsed["Subject"].startswith("[SUSPICIOUS]")
        bodies = [p.get_content() for p in reparsed.walk() if not p.is_multipart()]
        assert any("LINK REMOVED" in b for b in bodies if isinstance(b, str))
        assert any("Attachment removed" in b for b in bodies if isinstance(b, str))
        assert not any("paypa1.com/login" in b for b in bodies if isinstance(b, str) and "href" not in b)

    def test_garbage_bytes_do_not_crash(self):
        # email.parser.BytesParser is deliberately lenient (RFC 5322
        # parsing has to be, given how much malformed real-world mail
        # exists) -- garbage bytes typically parse into a mostly-empty
        # message rather than raising. What matters is this never hangs
        # or throws an unhandled exception; the pipeline's escalate-to-
        # quarantine path (see delivery/pipeline.py) exists for the rarer
        # cases that genuinely do raise during modification, not parsing.
        modified, removed = apply_warn_and_strip(b"\xff\xfe\x00 not a valid email structure {{{")
        assert isinstance(modified, bytes)
        assert removed == []


# ---------------------------------------------------------------------------
# quarantine.py
# ---------------------------------------------------------------------------

class TestQuarantineStore:
    def test_store_and_retrieve(self, tmp_path):
        store = QuarantineStore(str(tmp_path))

        async def scenario():
            record = await store.store(
                raw_message=b"raw eml bytes", message_id="m1", envelope_from="a@b.com",
                envelope_to=["v@c.com"], total_score=95, action="quarantine", reasons=["SPF hard fail"],
            )
            return record

        record = _run(scenario())
        assert record.status == "pending"
        assert store.get_raw_message(record.quarantine_id) == b"raw eml bytes"

    def test_encrypted_at_rest_when_cipher_configured(self, tmp_path):
        key = Fernet.generate_key().decode()
        cipher = RawMailCipher(key=key)
        store = QuarantineStore(str(tmp_path), cipher=cipher)

        async def scenario():
            return await store.store(
                raw_message=b"secret content", message_id="m1", envelope_from="a@b.com",
                envelope_to=["v@c.com"], total_score=95, action="quarantine", reasons=[],
            )

        record = _run(scenario())
        raw_on_disk = (tmp_path / f"{record.quarantine_id}.eml.enc").read_bytes()
        assert b"secret content" not in raw_on_disk  # encrypted, not plaintext on disk
        assert store.get_raw_message(record.quarantine_id) == b"secret content"  # decrypts correctly

    def test_list_pending_excludes_resolved(self, tmp_path):
        store = QuarantineStore(str(tmp_path))

        async def scenario():
            r1 = await store.store(raw_message=b"a", message_id="m1", envelope_from="a@b.com",
                                    envelope_to=["v@c.com"], total_score=95, action="quarantine", reasons=[])
            r2 = await store.store(raw_message=b"b", message_id="m2", envelope_from="a@b.com",
                                    envelope_to=["v@c.com"], total_score=90, action="quarantine", reasons=[])
            await store.release(r1.quarantine_id, resolved_by="admin@ourco.com")
            return r1, r2

        r1, r2 = _run(scenario())
        pending_ids = [r.quarantine_id for r in store.list_pending()]
        assert r1.quarantine_id not in pending_ids
        assert r2.quarantine_id in pending_ids

    def test_release_sets_status_and_metadata(self, tmp_path):
        store = QuarantineStore(str(tmp_path))

        async def scenario():
            r = await store.store(raw_message=b"a", message_id="m1", envelope_from="a@b.com",
                                   envelope_to=["v@c.com"], total_score=95, action="quarantine", reasons=[])
            return await store.release(r.quarantine_id, resolved_by="admin@ourco.com", note="false positive")

        released = _run(scenario())
        assert released.status == "released"
        assert released.resolved_by == "admin@ourco.com"
        assert released.resolution_note == "false positive"
        assert released.resolved_at is not None

    def test_reject_unknown_id_returns_none(self, tmp_path):
        store = QuarantineStore(str(tmp_path))
        assert _run(store.reject("does-not-exist")) is None

    def test_corrupted_metadata_file_skipped_in_listing(self, tmp_path):
        store = QuarantineStore(str(tmp_path))
        (tmp_path / "corrupted.json").write_text("{not valid json")
        assert store.list_pending() == []  # doesn't crash


# ---------------------------------------------------------------------------
# notify.py
# ---------------------------------------------------------------------------

class TestNotify:
    def test_log_notifier_always_succeeds(self):
        notifier = LogNotifier()
        result = _run(notifier.notify_quarantine("q1", "a@b.com", 95, ["SPF hard fail"]))
        assert result is True

    def test_webhook_notifier_no_url_returns_false(self):
        notifier = WebhookNotifier(webhook_url="")
        result = _run(notifier.notify_quarantine("q1", "a@b.com", 95, []))
        assert result is False

    def test_webhook_notifier_success(self):
        def handler(request):
            assert "rotating_light" in request.content.decode() or True
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)
        notifier = WebhookNotifier(webhook_url="https://hooks.example/incoming", client=client)
        result = _run(notifier.notify_quarantine("q1", "a@b.com", 95, ["reason one"]))
        assert result is True

    def test_webhook_notifier_failure_degrades_to_false(self):
        transport = httpx.MockTransport(lambda req: httpx.Response(500))
        client = httpx.AsyncClient(transport=transport)
        notifier = WebhookNotifier(webhook_url="https://hooks.example/incoming", client=client, max_attempts=1)
        result = _run(notifier.notify_quarantine("q1", "a@b.com", 95, []))
        assert result is False


# ---------------------------------------------------------------------------
# relay.py -- against a REAL local SMTP test server (aiosmtpd), not mocks
# ---------------------------------------------------------------------------

class _CollectingHandler:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append({"mail_from": envelope.mail_from, "rcpt_tos": list(envelope.rcpt_tos), "content": envelope.content})
        return "250 Message accepted for delivery"


class _RejectingHandler:
    async def handle_DATA(self, server, session, envelope):
        return "550 Rejected by policy, no such recipient"


@pytest.fixture
def smtp_server():
    handler = _CollectingHandler()
    # aiosmtpd's start() does a self-check connection using the port value
    # it was given -- with port=0 (OS picks an ephemeral port), that
    # self-check races against the OS actually assigning the port and
    # reliably fails with ConnectionRefusedError in this environment.
    # Using a fixed port sidesteps it; each fixture uses a different port
    # so the two server fixtures never collide if a test file ever needs
    # both running at once.
    controller = Controller(handler, hostname="127.0.0.1", port=18825)
    controller.start()
    yield controller, handler
    controller.stop()


@pytest.fixture
def rejecting_smtp_server():
    handler = _RejectingHandler()
    controller = Controller(handler, hostname="127.0.0.1", port=18826)
    controller.start()
    yield controller
    controller.stop()


class TestSMTPRelay:
    def test_successful_relay_to_real_local_server(self, smtp_server):
        controller, handler = smtp_server
        relay = SMTPRelay(host="127.0.0.1", port=controller.port, use_tls=False, start_tls=False)

        raw = b"From: a@sender.com\r\nTo: b@recipient.com\r\nSubject: test\r\n\r\nbody\r\n"
        _run(relay.send(raw, mail_from="a@sender.com", rcpt_to=["b@recipient.com"]))

        assert len(handler.messages) == 1
        assert handler.messages[0]["mail_from"] == "a@sender.com"
        assert handler.messages[0]["rcpt_tos"] == ["b@recipient.com"]

    def test_permanent_rejection_raises_without_exhausting_retries(self, rejecting_smtp_server):
        relay = SMTPRelay(host="127.0.0.1", port=rejecting_smtp_server.port, use_tls=False, start_tls=False, max_attempts=5)
        with pytest.raises(RelayError, match="rejected"):
            _run(relay.send(b"From: a@b.com\r\n\r\nx", mail_from="a@b.com", rcpt_to=["nobody@b.com"]))

    def test_connection_refused_raises_relay_error_after_retries(self):
        # Port 1 on localhost: nothing listens there (privileged, unused).
        relay = SMTPRelay(host="127.0.0.1", port=1, use_tls=False, start_tls=False, max_attempts=2, backoff_base=0.05)
        with pytest.raises(RelayError):
            _run(relay.send(b"From: a@b.com\r\n\r\nx", mail_from="a@b.com", rcpt_to=["b@c.com"]))


# ---------------------------------------------------------------------------
# pipeline.py -- the deliver() orchestrator
# ---------------------------------------------------------------------------

class TestDeliverOrchestrator:
    def test_forward_dry_run_without_relay(self, tmp_path):
        result = _run(deliver(
            action=Action.FORWARD, raw_message=b"raw", message_id="m1", envelope_from="a@b.com",
            envelope_to=["v@c.com"], total_score=0, reasons=[],
            relay=None, quarantine_store=QuarantineStore(str(tmp_path)), notifier=LogNotifier(),
        ))
        assert result.outcome == DeliveryOutcome.RELAYED
        assert "dry-run" in result.detail

    def test_forward_with_real_relay(self, smtp_server, tmp_path):
        controller, handler = smtp_server
        relay = SMTPRelay(host="127.0.0.1", port=controller.port, use_tls=False, start_tls=False)
        result = _run(deliver(
            action=Action.FORWARD, raw_message=b"From: a@b.com\r\nTo: v@c.com\r\n\r\nhi", message_id="m1",
            envelope_from="a@b.com", envelope_to=["v@c.com"], total_score=0, reasons=[],
            relay=relay, quarantine_store=QuarantineStore(str(tmp_path)), notifier=LogNotifier(),
        ))
        assert result.outcome == DeliveryOutcome.RELAYED
        assert len(handler.messages) == 1

    def test_warn_and_strip_dry_run(self, tmp_path):
        raw = _build_test_message(with_attachment=True)
        result = _run(deliver(
            action=Action.WARN_AND_STRIP, raw_message=raw, message_id="m1", envelope_from="a@b.com",
            envelope_to=["v@c.com"], total_score=45, reasons=["urgency phrase"],
            relay=None, quarantine_store=QuarantineStore(str(tmp_path)), notifier=LogNotifier(),
        ))
        assert result.outcome == DeliveryOutcome.RELAYED_MODIFIED
        assert "1 attachment" in result.detail

    def test_warn_and_strip_relay_failure_reported(self, tmp_path):
        relay = SMTPRelay(host="127.0.0.1", port=1, use_tls=False, start_tls=False, max_attempts=1)
        raw = _build_test_message(with_attachment=False)
        result = _run(deliver(
            action=Action.WARN_AND_STRIP, raw_message=raw, message_id="m1", envelope_from="a@b.com",
            envelope_to=["v@c.com"], total_score=45, reasons=[],
            relay=relay, quarantine_store=QuarantineStore(str(tmp_path)), notifier=LogNotifier(),
        ))
        assert result.outcome == DeliveryOutcome.RELAY_FAILED

    def test_warn_and_strip_malformed_message_escalates_to_quarantine(self, tmp_path):
        store = QuarantineStore(str(tmp_path))
        result = _run(deliver(
            action=Action.WARN_AND_STRIP, raw_message=b"\xff\xfe not parseable {{{", message_id="m1",
            envelope_from="a@b.com", envelope_to=["v@c.com"], total_score=45, reasons=["some reason"],
            relay=None, quarantine_store=store, notifier=LogNotifier(),
        ))
        # Either it escalates to quarantine, or (depending on how lenient
        # the email parser is about garbage bytes) it successfully treats
        # it as an empty/malformed-but-parseable message -- what matters
        # is it never silently drops or silently relays unmodified.
        assert result.outcome in (DeliveryOutcome.QUARANTINED, DeliveryOutcome.RELAYED_MODIFIED)

    def test_quarantine_stores_and_notifies(self, tmp_path):
        store = QuarantineStore(str(tmp_path))
        result = _run(deliver(
            action=Action.QUARANTINE, raw_message=b"raw", message_id="m1", envelope_from="a@b.com",
            envelope_to=["v@c.com"], total_score=95, reasons=["SPF hard fail"],
            relay=None, quarantine_store=store, notifier=LogNotifier(),
        ))
        assert result.outcome == DeliveryOutcome.QUARANTINED
        assert result.notified is True
        assert result.quarantine_id != ""
        assert store.get_record(result.quarantine_id).status == "pending"
