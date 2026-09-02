"""
Outbound Mail Protection and Data Loss Prevention (DLP) Engine.
Scans outbound email for sensitive data leakage (SSNs, credit card numbers, API keys,
confidential markers) and compromised account spam/burst anomalies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
import time
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DLPScanResult:
    is_blocked: bool = False
    policy_violations: List[str] = field(default_factory=list)
    score_delta: int = 0
    anomalous_volume: bool = False


class DLPScanner:
    # Pattern definitions for PII, Financials, and Credentials
    PATTERNS = {
        "SSN Leak": r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
        "Credit Card Leak": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
        "API Secret Key": r"\b(?:sk_live|secret_key|api_key)_[0-9a-zA-Z]{24,}\b",
        "Confidential Tag": r"(?i)\b(strictly\s+confidential|internal\s+only|do\s+not\s+distribute)\b",
    }

    def __init__(self, max_outbound_burst_per_10m: int = 50):
        self.max_outbound_burst_per_10m = max_outbound_burst_per_10m
        # Sender volume tracking: sender -> list of timestamps
        self._sender_activity: Dict[str, List[float]] = {}
        self._compiled_patterns = {name: re.compile(pat) for name, pat in self.PATTERNS.items()}

    def inspect_outbound(
        self,
        sender: str,
        recipients: List[str],
        subject: str = "",
        text_body: str = "",
        attachment_names: List[str] | None = None,
    ) -> DLPScanResult:
        """Scan outbound email headers, body, and attachment names for DLP violations and anomalies."""
        now = time.time()
        violations = []
        score_delta = 0

        content = f"{subject}\n{text_body}\n" + " ".join(attachment_names or [])

        # 1. Pattern Matching
        for name, pattern in self._compiled_patterns.items():
            matches = pattern.findall(content)
            if matches:
                violations.append(f"DLP Violation ({name}): detected {len(matches)} match(es)")
                score_delta += 40 if "Leak" in name or "Key" in name else 20

        # 2. Account Compromise Anomaly Detection (Rate/Volume Burst)
        sender_lower = sender.lower()
        activity = self._sender_activity.get(sender_lower, [])
        # Filter activity in the last 600s (10 mins)
        recent_activity = [t for t in activity if now - t <= 600]
        recent_activity.append(now)
        self._sender_activity[sender_lower] = recent_activity

        anomalous = False
        if len(recent_activity) > self.max_outbound_burst_per_10m:
            anomalous = True
            violations.append(
                f"Compromised Account Anomaly: sender '{sender_lower}' sent {len(recent_activity)} outbound mails in last 10m (burst threshold: {self.max_outbound_burst_per_10m})"
            )
            score_delta += 50

        is_blocked = score_delta >= 40 or anomalous

        if violations:
            logger.warning("DLP outbound inspection flagged sender %s: %s", sender, violations)

        return DLPScanResult(
            is_blocked=is_blocked,
            policy_violations=violations,
            score_delta=score_delta,
            anomalous_volume=anomalous,
        )
