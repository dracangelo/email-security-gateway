"""
Sender-Recipient Relationship Graph and Thread-Hijacking BEC pattern detection.
Tracks pair history and detects vendor-email-compromise (BEC) payment change patterns in email reply threads.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

FINANCIAL_CHANGE_PATTERNS = [
    r"new bank (?:account|details|information)",
    r"changed (?:our )?bank (?:account|details)",
    r"updated (?:wire|payment) (?:instructions|details)",
    r"payment (?:to|via) (?:new|different) (?:account|iban|routing)",
    r"\b(?:iban|swift|routing number|sort code)\b",
]


@dataclass
class RelationshipFinding:
    is_first_contact_pair: bool = False
    is_thread_hijack: bool = False
    financial_change_detected: bool = False
    score_delta: int = 0
    explanation: str = ""


class RelationshipGraphStore:
    """Stores sender-recipient interaction history."""

    def __init__(self):
        self._pairs: dict[str, dict[str, float | int]] = {}

    def _pair_key(self, sender: str, recipient: str) -> str:
        return f"{sender.strip().lower()}->{recipient.strip().lower()}"

    def get_pair_history(self, sender: str, recipient: str) -> dict[str, float | int]:
        return self._pairs.get(self._pair_key(sender, recipient), {"count": 0, "first_seen": 0})

    def record_interaction(self, sender: str, recipient: str) -> None:
        key = self._pair_key(sender, recipient)
        now = time.time()
        if key not in self._pairs:
            self._pairs[key] = {"count": 1, "first_seen": now}
        else:
            self._pairs[key]["count"] += 1


global_relationship_store = RelationshipGraphStore()


def detect_thread_hijacking_and_relationship(
    sender: str,
    recipient: str,
    in_reply_to: str = "",
    references: str = "",
    body_text: str = "",
    store: RelationshipGraphStore | None = None,
) -> RelationshipFinding:
    """
    Evaluates sender-recipient pair history and detects thread-hijacking BEC patterns in reply threads.
    """
    if not sender or not recipient:
        return RelationshipFinding()

    store = store or global_relationship_store
    history = store.get_pair_history(sender, recipient)

    is_first_contact_pair = history["count"] == 0
    store.record_interaction(sender, recipient)

    is_reply_thread = bool(in_reply_to.strip() or references.strip() or "re:" in body_text.lower()[:30])

    financial_change = False
    if is_reply_thread and body_text:
        body_lower = body_text.lower()
        for pat in FINANCIAL_CHANGE_PATTERNS:
            if re.search(pat, body_lower):
                financial_change = True
                break

    is_thread_hijack = is_reply_thread and financial_change
    score_delta = 0
    reasons = []

    if is_thread_hijack:
        score_delta += 40
        reasons.append("Thread-hijacking BEC pattern: financial payment detail change in reply thread")
    elif is_first_contact_pair:
        score_delta += 10
        reasons.append(f"First-contact interaction between {sender} and {recipient}")

    return RelationshipFinding(
        is_first_contact_pair=is_first_contact_pair,
        is_thread_hijack=is_thread_hijack,
        financial_change_detected=financial_change,
        score_delta=score_delta,
        explanation="; ".join(reasons),
    )
