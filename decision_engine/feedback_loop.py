"""
Feedback loop engine.
Records analyst release/reject decisions and computes domain reputation adjustments and threshold feedback.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Dict, List


@dataclass
class FeedbackRecord:
    quarantine_id: str
    envelope_from: str
    domain: str
    action: str  # "release" (False Positive) or "reject" (True Positive)
    note: str = ""
    timestamp: float = field(default_factory=time.time)


class FeedbackLoopEngine:
    def __init__(self):
        self._records: List[FeedbackRecord] = []
        self._domain_scores: Dict[str, int] = {}  # domain -> net feedback score (-10 for release, +10 for reject)

    def record_feedback(self, quarantine_id: str, envelope_from: str, action: str, note: str = "") -> FeedbackRecord:
        domain = envelope_from.split("@")[-1].lower().strip() if "@" in envelope_from else envelope_from.lower().strip()
        record = FeedbackRecord(
            quarantine_id=quarantine_id,
            envelope_from=envelope_from,
            domain=domain,
            action=action.lower(),
            note=note,
        )
        self._records.append(record)

        if domain:
            current = self._domain_scores.get(domain, 0)
            if action.lower() == "release":
                # False positive: increase domain trust (reduce future score)
                self._domain_scores[domain] = max(current - 15, -40)
            elif action.lower() == "reject":
                # True positive: increase domain risk (boost future score)
                self._domain_scores[domain] = min(current + 15, 50)

        return record

    def get_domain_adjustment(self, domain: str) -> int:
        clean_domain = domain.lower().strip()
        return self._domain_scores.get(clean_domain, 0)

    def get_stats(self) -> dict:
        total = len(self._records)
        releases = sum(1 for r in self._records if r.action == "release")
        rejects = sum(1 for r in self._records if r.action == "reject")
        return {
            "total_feedback": total,
            "false_positives_released": releases,
            "true_positives_rejected": rejects,
            "false_positive_rate": (releases / total) if total > 0 else 0.0,
            "domains_tracked": len(self._domain_scores),
        }
