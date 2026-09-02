"""
Dashboard Analytics & Audit Search Engine.
Aggregates gateway telemetry, computes false-positive ratios, and provides full-text audit search.
"""
from __future__ import annotations

from collections import Counter
import time
from typing import Any, Dict, List, Optional

from delivery.quarantine import QuarantineRecord


class DashboardAnalyticsEngine:
    def __init__(self, quarantine_store: Any, tenant_manager: Any = None):
        self.quarantine_store = quarantine_store
        self.tenant_manager = tenant_manager

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Compute operational dashboard metrics and breakdown counters."""
        records: List[QuarantineRecord] = []
        if hasattr(self.quarantine_store, "list_pending"):
            records = self.quarantine_store.list_pending()

        total_quarantined = len(records)
        released_count = 0
        rejected_count = 0
        pending_count = 0

        sender_counter: Counter[str] = Counter()
        domain_counter: Counter[str] = Counter()
        action_counter: Counter[str] = Counter()

        for rec in records:
            status = getattr(rec, "status", "pending")
            action = getattr(rec, "action", "quarantine")
            action_counter[action] += 1

            if status == "released":
                released_count += 1
            elif status == "rejected":
                rejected_count += 1
            else:
                pending_count += 1

            from_addr = getattr(rec, "envelope_from", "")
            if from_addr:
                sender_counter[from_addr] += 1
                if "@" in from_addr:
                    domain = from_addr.split("@")[-1].lower()
                    domain_counter[domain] += 1

        total_resolved = released_count + rejected_count
        fp_rate = (released_count / total_resolved * 100.0) if total_resolved > 0 else 0.0

        return {
            "timestamp": time.time(),
            "summary": {
                "total_quarantined": total_quarantined,
                "pending_count": pending_count,
                "released_count": released_count,
                "rejected_count": rejected_count,
                "false_positive_rate_pct": round(fp_rate, 2),
            },
            "action_breakdown": dict(action_counter),
            "top_blocked_senders": dict(sender_counter.most_common(5)),
            "top_blocked_domains": dict(domain_counter.most_common(5)),
        }

    def search_audit_records(
        self,
        records: List[Dict[str, Any]],
        query: Optional[str] = None,
        event_type: Optional[str] = None,
        min_score: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Filter audit log records by full-text search query, event type, and score."""
        results = []
        q_lower = query.lower().strip() if query else None

        for rec in records:
            if event_type and rec.get("event_type") != event_type:
                continue

            if min_score is not None:
                score = rec.get("total_score") or rec.get("score") or 0
                if score < min_score:
                    continue

            if q_lower:
                rec_str = str(rec).lower()
                if q_lower not in rec_str:
                    continue

            results.append(rec)

        return results

    def get_realtime_threat_stream(self, records: List[Dict[str, Any]], min_score: int = 70) -> List[Dict[str, Any]]:
        """Extract high-severity threat events for real-time alert stream."""
        return self.search_audit_records(records, min_score=min_score)
