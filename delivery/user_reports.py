"""
User "Report Phish" Ingestion Module.
Processes end-user reported phishing submissions from Outlook/Gmail add-ins or report buttons,
extracts threat indicators, feeds back into the decision engine feedback loop, and triggers
security review / auto-zap workflows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import logging
import re
import time
from typing import Any, Dict, List, Optional

from decision_engine.feedback_loop import FeedbackLoopEngine
from delivery.auto_zap import RetroactiveZapEngine

logger = logging.getLogger(__name__)


@dataclass
class UserPhishReport:
    report_id: str
    reporter_email: str
    message_id: str
    sender: str
    subject: str
    body_snippet: str
    urls_extracted: List[str]
    reported_at: float = field(default_factory=time.time)
    action_taken: str = "quarantined_for_review"


class UserReportHandler:
    def __init__(
        self,
        feedback_loop: Optional[FeedbackLoopEngine] = None,
        zap_engine: Optional[RetroactiveZapEngine] = None,
    ):
        self.feedback_loop = feedback_loop or FeedbackLoopEngine()
        self.zap_engine = zap_engine
        self._reports: List[UserPhishReport] = []

    async def process_report(
        self,
        reporter_email: str,
        message_id: str,
        sender: str = "",
        subject: str = "",
        raw_message: bytes = b"",
        body: str = "",
        trigger_auto_zap: bool = True,
    ) -> Dict[str, Any]:
        """Process an incoming end-user report phish submission."""
        report_id = f"report_{hashlib.sha256(f'{reporter_email}:{message_id}:{time.time()}'.encode()).hexdigest()[:12]}"
        
        # Extract URLs
        extracted_urls = re.findall(r"https?://[^\s<>\"']+", body or raw_message.decode(errors="ignore"))
        
        report = UserPhishReport(
            report_id=report_id,
            reporter_email=reporter_email,
            message_id=message_id,
            sender=sender,
            subject=subject,
            body_snippet=body[:200] if body else "",
            urls_extracted=extracted_urls,
        )
        self._reports.append(report)

        # 1. Update Domain Reputation via Feedback Loop
        from_domain = sender.split("@")[-1] if "@" in sender else ""
        if from_domain:
            self.feedback_loop.record_feedback(
                quarantine_id=report_id,
                envelope_from=sender,
                action="reject",
                note=f"End-user phish report from {reporter_email}",
            )

        # 2. Retroactive Zap across org if enabled and zap_engine present
        zapped_count = 0
        if trigger_auto_zap and self.zap_engine:
            for url in extracted_urls:
                zapped = await self.zap_engine.trigger_zap_by_url(url, reason=f"User report by {reporter_email}")
                zapped_count += len(zapped)

        logger.info("Processed user phish report %s from %s for message %s (urls: %d, zapped: %d)",
                    report_id, reporter_email, message_id, len(extracted_urls), zapped_count)

        return {
            "report_id": report_id,
            "status": "processed",
            "urls_extracted": len(extracted_urls),
            "zapped_messages_count": zapped_count,
            "feedback_recorded": bool(from_domain),
        }

    def list_reports(self) -> List[Dict[str, Any]]:
        return [
            {
                "report_id": r.report_id,
                "reporter_email": r.reporter_email,
                "message_id": r.message_id,
                "sender": r.sender,
                "subject": r.subject,
                "urls_count": len(r.urls_extracted),
                "reported_at": r.reported_at,
            }
            for r in self._reports
        ]
