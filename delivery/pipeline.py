"""Turns a decision_engine Action into something that actually happens to the message."""
from __future__ import annotations

import logging

from decision_engine.models import Action

from .modify import apply_tag_only, apply_warn_and_strip
from .models import DeliveryOutcome, DeliveryResult
from .notify import Notifier
from .quarantine import QuarantineStore
from .relay import RelayError, SMTPRelay

logger = logging.getLogger("email_gateway.delivery")


async def deliver(
    action: Action,
    raw_message: bytes,
    message_id: str,
    envelope_from: str,
    envelope_to: list[str],
    total_score: int,
    reasons: list[str],
    relay: SMTPRelay | None,
    quarantine_store: QuarantineStore,
    notifier: Notifier,
    tag_only: bool = False,
    soc_bcc: str | None = None,
) -> DeliveryResult:
    """
    tag_only=True overrides quarantine / modification to inject X-Gateway-Verdict headers
    and relay the message unmodified (or log dry-run) for initial deployment observation.
    """
    if tag_only and action != Action.FORWARD:
        tagged_msg = apply_tag_only(raw_message, total_score, action.value, reasons)
        if relay is None:
            return DeliveryResult(outcome=DeliveryOutcome.RELAYED, detail=f"tag-only dry-run: would relay tagged message (original action={action.value})")
        try:
            await relay.send(tagged_msg, mail_from=envelope_from, rcpt_to=envelope_to)
        except RelayError as exc:
            return DeliveryResult(outcome=DeliveryOutcome.RELAY_FAILED, detail=str(exc))
        return DeliveryResult(outcome=DeliveryOutcome.RELAYED, detail=f"tag-only: relayed tagged message (original action={action.value})")

    """
    relay=None disables actual relaying entirely (dry-run / decision-only
    mode -- useful for standing this up and watching its calls before
    trusting it to actually move mail). forward/warn_and_strip both
    degrade to "decided but not relayed" in that mode rather than
    raising, so you can run the full pipeline including quarantine
    (which never needed a relay to begin with) while relay is being
    configured separately.
    """
    if action == Action.QUARANTINE:
        record = await quarantine_store.store(
            raw_message=raw_message, message_id=message_id, envelope_from=envelope_from,
            envelope_to=envelope_to, total_score=total_score, action=action.value, reasons=reasons,
        )
        notified = await notifier.notify_quarantine(record.quarantine_id, envelope_from, total_score, reasons)
        return DeliveryResult(outcome=DeliveryOutcome.QUARANTINED, detail="held for review", quarantine_id=record.quarantine_id, notified=notified)

    if action == Action.WARN_AND_STRIP:
        try:
            modified, removed = apply_warn_and_strip(raw_message)
        except Exception as exc:
            # Couldn't safely modify the message (malformed MIME, etc.) --
            # escalate to quarantine rather than either relaying it
            # unmodified (defeats the point of warn_and_strip) or dropping
            # it silently (violates the "don't blind-drop" rule).
            logger.warning("message_id=%s failed to apply warn_and_strip (%s), escalating to quarantine", message_id, exc)
            record = await quarantine_store.store(
                raw_message=raw_message, message_id=message_id, envelope_from=envelope_from,
                envelope_to=envelope_to, total_score=total_score, action=action.value,
                reasons=reasons + [f"escalated: could not apply warn_and_strip ({exc})"],
            )
            notified = await notifier.notify_quarantine(record.quarantine_id, envelope_from, total_score, reasons)
            return DeliveryResult(outcome=DeliveryOutcome.QUARANTINED, detail="escalated from warn_and_strip: modification failed", quarantine_id=record.quarantine_id, notified=notified)

        if relay is None:
            return DeliveryResult(outcome=DeliveryOutcome.RELAYED_MODIFIED, detail=f"dry-run: would relay with {len(removed)} attachment(s) stripped")
        try:
            await relay.send(modified, mail_from=envelope_from, rcpt_to=envelope_to)
        except RelayError as exc:
            return DeliveryResult(outcome=DeliveryOutcome.RELAY_FAILED, detail=str(exc))
        return DeliveryResult(outcome=DeliveryOutcome.RELAYED_MODIFIED, detail=f"relayed with {len(removed)} attachment(s) stripped")

    # Action.FORWARD
    if soc_bcc and relay:
        try:
            await relay.send(raw_message, mail_from=envelope_from, rcpt_to=[soc_bcc])
        except Exception as exc:
            logger.warning("Failed to mirror message %s to SOC BCC address %s: %s", message_id, soc_bcc, exc)

    if relay is None:
        return DeliveryResult(outcome=DeliveryOutcome.RELAYED, detail="dry-run: would relay unmodified")
    try:
        await relay.send(raw_message, mail_from=envelope_from, rcpt_to=envelope_to)
    except RelayError as exc:
        return DeliveryResult(outcome=DeliveryOutcome.RELAY_FAILED, detail=str(exc))
    return DeliveryResult(outcome=DeliveryOutcome.RELAYED, detail="relayed unmodified")
