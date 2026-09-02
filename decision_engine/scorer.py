"""
Combines stage scores into one routing decision with enterprise decision engine policy layers:
- Per-tenant configurable weights & thresholds
- Precedence allow/block rules
- VIP/Executive protection scoring & lowered quarantine thresholds
- Feedback-loop domain trust adjustments
- Campaign clustering high-velocity boost
- Shadow-mode A-B rule testing
- Audit explainability report generation
"""
from __future__ import annotations

from typing import Optional

from .allow_block import AllowBlockResult
from .campaign_clustering import CampaignClusterResult
from .explainability import ExplainabilityGenerator
from .models import Action, RoutingDecision, StageScore
from .shadow_mode import ShadowModeEngine, ShadowResult
from .tenant_config import TenantConfig
from .vip_policy import VIPPolicyResult

DEFAULT_WARN_THRESHOLD = 30
DEFAULT_QUARANTINE_THRESHOLD = 70


def decide(
    stage_scores: list[StageScore],
    warn_threshold: int = DEFAULT_WARN_THRESHOLD,
    quarantine_threshold: int = DEFAULT_QUARANTINE_THRESHOLD,
    allow_block_result: AllowBlockResult | None = None,
    tenant_config: TenantConfig | None = None,
    vip_result: VIPPolicyResult | None = None,
    campaign_result: CampaignClusterResult | None = None,
    feedback_adjustment: int = 0,
    shadow_engine: ShadowModeEngine | None = None,
    tenant_id: str = "default",
) -> RoutingDecision:
    effective_warn = tenant_config.warn_threshold if tenant_config else warn_threshold
    effective_quarantine = tenant_config.quarantine_threshold if tenant_config else quarantine_threshold

    if effective_quarantine <= effective_warn:
        raise ValueError("quarantine_threshold must be greater than warn_threshold")

    # VIP Policy overrides/adjustments
    if vip_result and vip_result.vip_detected:
        if vip_result.lowered_quarantine_threshold is not None:
            effective_quarantine = max(effective_warn + 1, min(effective_quarantine, vip_result.lowered_quarantine_threshold))

    # Apply stage weights if provided by tenant_config
    weighted_stage_scores: list[StageScore] = []
    stage_weights = tenant_config.stage_weights if tenant_config else {}

    for s in stage_scores:
        weight = stage_weights.get(s.stage, 1.0)
        weighted_delta = int(s.score_delta * weight)
        weighted_stage_scores.append(StageScore(stage=s.stage, score_delta=weighted_delta, reasons=s.reasons))

    total = sum(s.score_delta for s in weighted_stage_scores)
    all_reasons = [reason for s in weighted_stage_scores for reason in s.reasons]

    # Feedback adjustment
    if feedback_adjustment != 0:
        total += feedback_adjustment
        adj_type = "increased" if feedback_adjustment > 0 else "reduced"
        all_reasons.append(f"Feedback loop adjustment: domain reputation {adj_type} risk score by {abs(feedback_adjustment)}")

    # VIP boost
    if vip_result and vip_result.vip_detected:
        total += vip_result.score_boost
        all_reasons.extend(vip_result.reasons)

    # Campaign cluster boost
    if campaign_result and campaign_result.is_campaign:
        total += campaign_result.score_boost
        all_reasons.extend(campaign_result.reasons)

    # Precedence Overrides
    if allow_block_result and allow_block_result.is_blocked:
        all_reasons.insert(0, f"policy override: {allow_block_result.reason}")
        decision = RoutingDecision(
            total_score=max(total, effective_quarantine),
            action=Action.QUARANTINE,
            stage_scores=weighted_stage_scores,
            all_reasons=all_reasons,
        )
    elif allow_block_result and allow_block_result.is_allowed:
        # Malware override: if any single score is >= 100 (e.g. ClamAV/VT malware), do not bypass
        has_malware = any(s.score_delta >= 100 for s in weighted_stage_scores)
        if not has_malware:
            all_reasons.insert(0, f"policy override: {allow_block_result.reason}")
            decision = RoutingDecision(
                total_score=0,
                action=Action.FORWARD,
                stage_scores=weighted_stage_scores,
                all_reasons=all_reasons,
            )
        else:
            if total >= effective_quarantine:
                action = Action.QUARANTINE
            elif total >= effective_warn:
                action = Action.WARN_AND_STRIP
            else:
                action = Action.FORWARD
            decision = RoutingDecision(total_score=total, action=action, stage_scores=weighted_stage_scores, all_reasons=all_reasons)
    else:
        if total >= effective_quarantine:
            action = Action.QUARANTINE
        elif total >= effective_warn:
            action = Action.WARN_AND_STRIP
        else:
            action = Action.FORWARD
        decision = RoutingDecision(total_score=total, action=action, stage_scores=weighted_stage_scores, all_reasons=all_reasons)

    # Attach explainability report
    explainability_report = ExplainabilityGenerator.generate(
        decision=decision,
        warn_threshold=effective_warn,
        quarantine_threshold=effective_quarantine,
        tenant_id=tenant_id,
    )
    decision.explainability = explainability_report.as_dict()

    # Attach Shadow mode evaluation if requested
    if shadow_engine:
        shadow_res = shadow_engine.evaluate(
            stage_scores=weighted_stage_scores,
            primary_action=decision.action,
            primary_score=decision.total_score,
        )
        decision.shadow_result = shadow_res.as_dict()

    if vip_result and vip_result.vip_detected:
        decision.vip_info = {
            "vip_name": vip_result.vip_name,
            "score_boost": vip_result.score_boost,
            "lowered_quarantine_threshold": vip_result.lowered_quarantine_threshold,
        }

    if campaign_result and campaign_result.cluster_id:
        decision.campaign_info = {
            "cluster_id": campaign_result.cluster_id,
            "cluster_size": campaign_result.cluster_size,
            "is_campaign": campaign_result.is_campaign,
        }

    return decision
