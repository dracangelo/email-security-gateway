"""
VIP/Executive protection policy layer.
Applies stricter scoring and lower quarantine thresholds for messages impersonating protected identities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class VIPPolicyResult:
    vip_detected: bool = False
    vip_name: str = ""
    score_boost: int = 0
    lowered_quarantine_threshold: Optional[int] = None
    reasons: List[str] = field(default_factory=list)


class VIPPolicyEngine:
    def __init__(self, default_score_boost: int = 25, default_quarantine_threshold: int = 45):
        self.default_score_boost = default_score_boost
        self.default_quarantine_threshold = default_quarantine_threshold

    def evaluate(
        self,
        from_header: str = "",
        vip_display_names: Optional[List[str]] = None,
        all_reasons: Optional[List[str]] = None,
    ) -> VIPPolicyResult:
        all_reasons = all_reasons or []
        vip_display_names = [v.lower().strip() for v in (vip_display_names or []) if v]

        if not vip_display_names and not from_header:
            return VIPPolicyResult()

        detected_vip = ""
        from_header_lower = from_header.lower()

        # Check if from_header contains VIP display name
        for vip in vip_display_names:
            if vip in from_header_lower:
                detected_vip = vip
                break

        # Also check existing reasons for VIP display name spoofing flag from content_analysis
        vip_reason_triggered = any("vip display name" in r.lower() or "display-name spoofing" in r.lower() for r in all_reasons)

        if detected_vip or vip_reason_triggered:
            vip_identifier = detected_vip if detected_vip else "protected identity"
            reasons = [f"VIP Policy Enforcement: detected impersonation of '{vip_identifier}'"]
            return VIPPolicyResult(
                vip_detected=True,
                vip_name=vip_identifier,
                score_boost=self.default_score_boost,
                lowered_quarantine_threshold=self.default_quarantine_threshold,
                reasons=reasons,
            )

        return VIPPolicyResult()
