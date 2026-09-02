"""Result types for the delivery layer -- what actually happened to a message after a decision was made."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DeliveryOutcome(str, Enum):
    RELAYED = "relayed"                # forwarded on, unmodified
    RELAYED_MODIFIED = "relayed_modified"  # forwarded with warning/strip applied
    QUARANTINED = "quarantined"        # held, not delivered
    RELAY_FAILED = "relay_failed"      # tried to relay, SMTP call failed after retries


@dataclass
class DeliveryResult:
    outcome: DeliveryOutcome
    detail: str = ""
    quarantine_id: str = ""   # set when outcome == QUARANTINED, used for release/reject later
    notified: bool = False

    def as_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "detail": self.detail,
            "quarantine_id": self.quarantine_id,
            "notified": self.notified,
        }


@dataclass
class QuarantineRecord:
    quarantine_id: str
    message_id: str
    envelope_from: str
    envelope_to: list[str]
    total_score: int
    action: str
    reasons: list[str]
    quarantined_at: float
    status: str = "pending"  # "pending" | "released" | "rejected"
    resolved_at: float | None = None
    resolved_by: str = ""
    resolution_note: str = ""

    def as_dict(self) -> dict:
        return {
            "quarantine_id": self.quarantine_id,
            "message_id": self.message_id,
            "envelope_from": self.envelope_from,
            "envelope_to": self.envelope_to,
            "total_score": self.total_score,
            "action": self.action,
            "reasons": self.reasons,
            "quarantined_at": self.quarantined_at,
            "status": self.status,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "resolution_note": self.resolution_note,
        }

    @staticmethod
    def from_dict(d: dict) -> "QuarantineRecord":
        return QuarantineRecord(**d)
