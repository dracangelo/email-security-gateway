"""
Delivery Confirmation Tracking and Delivery Status Management.
Tracks delivery receipts, SMTP DSN codes, and handles SOC mirroring (BCC to SOC).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DeliveryReceipt:
    message_id: str
    recipient: str
    status: str  # "relayed", "quarantined", "bounced", "delivered_api"
    dsn_code: str = "2.0.0"
    timestamp: float = field(default_factory=time.time)
    detail: str = ""


class DeliveryTracker:
    def __init__(self):
        self._receipts: List[DeliveryReceipt] = []

    def record_receipt(self, message_id: str, recipient: str, status: str, dsn_code: str = "2.0.0", detail: str = "") -> DeliveryReceipt:
        receipt = DeliveryReceipt(
            message_id=message_id,
            recipient=recipient,
            status=status,
            dsn_code=dsn_code,
            detail=detail,
        )
        self._receipts.append(receipt)
        logger.info("Recorded delivery receipt for %s to %s: status=%s, dsn=%s", message_id, recipient, status, dsn_code)
        return receipt

    def get_receipts_for_message(self, message_id: str) -> List[DeliveryReceipt]:
        return [r for r in self._receipts if r.message_id == message_id]

    def get_stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in self._receipts:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts
