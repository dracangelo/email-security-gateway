"""
End-user Quarantine Digest Generator.
Compiles periodic summary emails for end-users containing quarantined items,
providing one-click release request capability with policy-based auto-approval vs analyst review.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import logging
import time
from typing import Any, Dict, List, Optional

from delivery.quarantine import QuarantineRecord, QuarantineStore

logger = logging.getLogger(__name__)


@dataclass
class QuarantineDigestEntry:
    quarantine_id: str
    envelope_from: str
    subject: str
    total_score: int
    reasons: List[str]
    quarantined_at: float
    release_token: str


class QuarantineDigestGenerator:
    def __init__(self, quarantine_store: QuarantineStore, secret_key: str = "digest_secret_key"):
        self.quarantine_store = quarantine_store
        self.secret_key = secret_key

    def generate_token(self, quarantine_id: str, recipient: str) -> str:
        """Generate HMAC token for secure single-click release request."""
        msg = f"{quarantine_id}:{recipient}"
        sig = hmac.new(self.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]
        return sig

    def verify_token(self, quarantine_id: str, recipient: str, token: str) -> bool:
        """Verify single-click release request HMAC token."""
        expected = self.generate_token(quarantine_id, recipient)
        return hmac.compare_digest(expected, token)

    def build_digest_for_recipient(self, recipient: str, portal_base_url: str = "https://gateway.example.com") -> Dict[str, Any]:
        """Fetch pending quarantine items for recipient and build HTML/Text digest."""
        all_pending = self.quarantine_store.list_pending()
        recipient_lower = recipient.lower()
        user_items: List[QuarantineDigestEntry] = []

        for item in all_pending:
            if recipient_lower in [to.lower() for to in item.envelope_to]:
                token = self.generate_token(item.quarantine_id, recipient_lower)
                user_items.append(
                    QuarantineDigestEntry(
                        quarantine_id=item.quarantine_id,
                        envelope_from=item.envelope_from,
                        subject=getattr(item, "subject", f"Quarantined Email ({item.quarantine_id})"),
                        total_score=item.total_score,
                        reasons=item.reasons,
                        quarantined_at=item.quarantined_at if hasattr(item, "quarantined_at") else getattr(item, "stored_at", time.time()),
                        release_token=token,
                    )
                )

        if not user_items:
            return {"recipient": recipient, "count": 0, "html": "", "text": ""}

        # Build HTML summary
        rows_html = ""
        for entry in user_items:
            release_link = f"{portal_base_url.rstrip('/')}/admin/quarantine/{entry.quarantine_id}/release_request?token={entry.release_token}&user={recipient_lower}"
            rows_html += f"""
            <tr style="border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 10px;"><strong>{entry.envelope_from}</strong></td>
                <td style="padding: 10px;">{entry.subject or '(No Subject)'}</td>
                <td style="padding: 10px; color: #d9534f;">Score: {entry.total_score}</td>
                <td style="padding: 10px;"><a href="{release_link}" style="background: #0275d8; color: #fff; padding: 6px 12px; text-decoration: none; border-radius: 4px;">Request Release</a></td>
            </tr>
            """

        html_body = f"""
        <html>
            <body style="font-family: sans-serif; padding: 20px;">
                <h2>📧 Email Security Quarantine Digest for {recipient}</h2>
                <p>The following messages were held in quarantine by your Email Auth Gateway. If you recognize a legitimate sender, click <strong>Request Release</strong>.</p>
                <table style="width: 100%; border-collapse: collapse; text-align: left;">
                    <thead>
                        <tr style="background: #f5f5f5;">
                            <th style="padding: 10px;">Sender</th>
                            <th style="padding: 10px;">Subject</th>
                            <th style="padding: 10px;">Risk Score</th>
                            <th style="padding: 10px;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </body>
        </html>
        """

        text_body = f"Quarantine Digest for {recipient}\n" + "\n".join(
            [f"- {e.envelope_from} | {e.subject} (Score: {e.total_score})" for e in user_items]
        )

        return {
            "recipient": recipient,
            "count": len(user_items),
            "html": html_body,
            "text": text_body,
            "entries": user_items,
        }
