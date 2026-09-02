"""
Explainability generator for decision engine.
Generates human-readable, audit-ready summaries of routing decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import RoutingDecision


@dataclass
class DecisionExplainabilityReport:
    summary_verdict: str
    action: str
    total_score: int
    thresholds: Dict[str, int]
    stage_breakdown: Dict[str, dict]
    policy_overrides: List[str] = field(default_factory=list)
    top_risk_drivers: List[str] = field(default_factory=list)
    narrative: str = ""

    def as_dict(self) -> dict:
        return {
            "summary_verdict": self.summary_verdict,
            "action": self.action,
            "total_score": self.total_score,
            "thresholds": self.thresholds,
            "stage_breakdown": self.stage_breakdown,
            "policy_overrides": self.policy_overrides,
            "top_risk_drivers": self.top_risk_drivers,
            "narrative": self.narrative,
        }


class ExplainabilityGenerator:
    @staticmethod
    def generate(
        decision: RoutingDecision,
        warn_threshold: int = 30,
        quarantine_threshold: int = 70,
        tenant_id: str = "default",
    ) -> DecisionExplainabilityReport:
        stage_breakdown = {}
        top_risk_drivers = []
        policy_overrides = []

        for stage in decision.stage_scores:
            stage_breakdown[stage.stage] = {
                "score_delta": stage.score_delta,
                "reasons": stage.reasons,
            }
            if stage.score_delta > 0:
                for reason in stage.reasons:
                    top_risk_drivers.append(f"[{stage.stage.upper()}] {reason}")

        for reason in decision.all_reasons:
            if "override" in reason.lower() or "policy" in reason.lower():
                policy_overrides.append(reason)

        action_str = decision.action.value
        total_score = decision.total_score

        if policy_overrides:
            narrative = f"Message evaluated for tenant '{tenant_id}'. Decision forced to {action_str.upper()} via policy override: {'; '.join(policy_overrides)}."
        elif action_str == "quarantine":
            narrative = (
                f"Message score of {total_score} met or exceeded quarantine threshold ({quarantine_threshold}). "
                f"Primary risk drivers: {'; '.join(top_risk_drivers[:3]) if top_risk_drivers else 'accumulated threat signals'}."
            )
        elif action_str == "warn_and_strip":
            narrative = (
                f"Message score of {total_score} exceeded warning threshold ({warn_threshold}) but remained below quarantine ({quarantine_threshold}). "
                "Delivering with link defanging and warning banner."
            )
        else:
            narrative = f"Message score of {total_score} is clean (below warning threshold {warn_threshold}). Delivering as-is."

        return DecisionExplainabilityReport(
            summary_verdict=action_str.upper(),
            action=action_str,
            total_score=total_score,
            thresholds={"warn_threshold": warn_threshold, "quarantine_threshold": quarantine_threshold},
            stage_breakdown=stage_breakdown,
            policy_overrides=policy_overrides,
            top_risk_drivers=top_risk_drivers,
            narrative=narrative,
        )
