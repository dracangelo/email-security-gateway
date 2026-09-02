"""Step 3: combine every stage's score_delta into one action."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Action(str, Enum):
    FORWARD = "forward"                # clean, deliver as-is
    WARN_AND_STRIP = "warn_and_strip"  # deliver with [WARNING] prefix, links/attachments stripped
    QUARANTINE = "quarantine"          # divert to admin review, do not deliver


@dataclass
class StageScore:
    stage: str            # "auth", "content", "attachments"
    score_delta: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class RoutingDecision:
    total_score: int
    action: Action
    stage_scores: list[StageScore]
    all_reasons: list[str] = field(default_factory=list)
    explainability: Optional[Dict[str, Any]] = None
    shadow_result: Optional[Dict[str, Any]] = None
    vip_info: Optional[Dict[str, Any]] = None
    campaign_info: Optional[Dict[str, Any]] = None

    def as_dict(self) -> dict:
        res = {
            "total_score": self.total_score,
            "action": self.action.value,
            "stages": [
                {"stage": s.stage, "score_delta": s.score_delta, "reasons": s.reasons} for s in self.stage_scores
            ],
            "reasons": self.all_reasons,
        }
        if self.explainability:
            res["explainability"] = self.explainability
        if self.shadow_result:
            res["shadow_result"] = self.shadow_result
        if self.vip_info:
            res["vip_info"] = self.vip_info
        if self.campaign_info:
            res["campaign_info"] = self.campaign_info
        return res
