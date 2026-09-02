"""
Shadow-mode / A-B testing framework for new scoring rules and threshold profiles.
Runs rules candidate side-by-side with primary scoring without affecting live delivery actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .models import Action, StageScore


@dataclass
class ShadowResult:
    shadow_rule_name: str
    shadow_score: int
    shadow_action: Action
    diverges_from_primary: bool
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "shadow_rule_name": self.shadow_rule_name,
            "shadow_score": self.shadow_score,
            "shadow_action": self.shadow_action.value,
            "diverges_from_primary": self.diverges_from_primary,
            "reasons": self.reasons,
        }


class ShadowModeEngine:
    def __init__(self, candidate_warn_threshold: int = 20, candidate_quarantine_threshold: int = 50, shadow_name: str = "experimental_strict"):
        self.candidate_warn_threshold = candidate_warn_threshold
        self.candidate_quarantine_threshold = candidate_quarantine_threshold
        self.shadow_name = shadow_name

    def evaluate(
        self,
        stage_scores: List[StageScore],
        primary_action: Action,
        primary_score: int,
    ) -> ShadowResult:
        # Candidate scoring calculation
        shadow_score = sum(s.score_delta for s in stage_scores)
        reasons = [r for s in stage_scores for r in s.reasons]

        if shadow_score >= self.candidate_quarantine_threshold:
            shadow_action = Action.QUARANTINE
        elif shadow_score >= self.candidate_warn_threshold:
            shadow_action = Action.WARN_AND_STRIP
        else:
            shadow_action = Action.FORWARD

        diverges = shadow_action != primary_action
        if diverges:
            reasons.append(f"Shadow divergence: primary action '{primary_action.value}' vs candidate '{shadow_action.value}'")

        return ShadowResult(
            shadow_rule_name=self.shadow_name,
            shadow_score=shadow_score,
            shadow_action=shadow_action,
            diverges_from_primary=diverges,
            reasons=reasons,
        )
