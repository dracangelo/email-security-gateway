"""
Tests for advanced Decision Engine & Scoring features (Task 5):
- Per-tenant configurable weights & thresholds
- VIP protection policy
- Feedback loop from admin release/reject
- Campaign clustering & fuzzy hashing
- Shadow mode A-B testing
- Per-decision explainability reports
- Time-of-Click link protection & redirect verification
"""
from __future__ import annotations

import base64
import pytest

from decision_engine import (
    Action,
    AllowBlockResult,
    CampaignClusterEngine,
    DecisionExplainabilityReport,
    ExplainabilityGenerator,
    FeedbackLoopEngine,
    RoutingDecision,
    ShadowModeEngine,
    StageScore,
    TenantConfig,
    TenantConfigStore,
    VIPPolicyEngine,
    decide,
)
from time_of_click import TimeOfClickService, rewrite_urls_in_html, rewrite_urls_in_text


def test_tenant_config_and_weights():
    store = TenantConfigStore()
    config = TenantConfig(
        tenant_id="acme_corp",
        warn_threshold=20,
        quarantine_threshold=50,
        stage_weights={"auth": 1.0, "content": 2.0, "attachments": 1.0},
    )
    store.set_config(config)

    retrieved = store.get_config("acme_corp")
    assert retrieved.warn_threshold == 20
    assert retrieved.quarantine_threshold == 50

    # Content score of 15 weighted by 2.0 becomes 30 -> meets warn threshold (20)
    stages = [StageScore(stage="content", score_delta=15, reasons=["suspicious keyword"])]
    decision = decide(stage_scores=stages, tenant_config=retrieved)
    assert decision.action == Action.WARN_AND_STRIP
    assert decision.total_score == 30


def test_vip_policy_engine():
    vip_engine = VIPPolicyEngine(default_score_boost=30, default_quarantine_threshold=40)
    res = vip_engine.evaluate(from_header="Chief Executive Officer <ceo@gmail.com>", vip_display_names=["Chief Executive Officer"])

    assert res.vip_detected is True
    assert res.score_boost == 30
    assert res.lowered_quarantine_threshold == 40

    stages = [StageScore(stage="content", score_delta=15, reasons=["display-name spoofing"])]
    decision = decide(stage_scores=stages, vip_result=res)

    assert decision.action == Action.QUARANTINE
    assert decision.total_score == 45  # 15 + 30
    assert decision.vip_info["vip_name"] == "chief executive officer"


def test_feedback_loop_engine():
    feedback = FeedbackLoopEngine()
    feedback.record_feedback(quarantine_id="q123", envelope_from="vendor@trusted.com", action="release", note="false positive")

    adj = feedback.get_domain_adjustment("trusted.com")
    assert adj == -15

    stages = [StageScore(stage="content", score_delta=35, reasons=["keyword trigger"])]
    decision = decide(stage_scores=stages, feedback_adjustment=adj, warn_threshold=30)
    # Score 35 - 15 = 20 -> below warn_threshold (30) -> FORWARD
    assert decision.action == Action.FORWARD
    assert decision.total_score == 20

    stats = feedback.get_stats()
    assert stats["false_positives_released"] == 1


def test_campaign_clustering_simhash():
    cluster_engine = CampaignClusterEngine(campaign_threshold=2, default_score_boost=25)

    res1 = cluster_engine.evaluate_and_register(text_body="Urgent wire transfer required for invoice #12345", subject="Payment Request")
    assert res1.is_campaign is False

    # Second near-identical email should trigger campaign alert
    res2 = cluster_engine.evaluate_and_register(text_body="Urgent wire transfer required for invoice #12346", subject="Payment Request")
    assert res2.is_campaign is True
    assert res2.score_boost == 25

    decision = decide(stage_scores=[StageScore(stage="content", score_delta=15)], campaign_result=res2, warn_threshold=30)
    assert decision.total_score == 40
    assert decision.action == Action.WARN_AND_STRIP
    assert decision.campaign_info["is_campaign"] is True


def test_shadow_mode_engine():
    shadow = ShadowModeEngine(candidate_warn_threshold=15, candidate_quarantine_threshold=40, shadow_name="strict_test")
    stages = [StageScore(stage="auth", score_delta=20)]

    decision = decide(stage_scores=stages, warn_threshold=30, quarantine_threshold=70, shadow_engine=shadow)
    assert decision.action == Action.FORWARD  # Primary (score 20 < 30)
    assert decision.shadow_result["shadow_action"] == Action.WARN_AND_STRIP.value
    assert decision.shadow_result["diverges_from_primary"] is True


def test_explainability_generator():
    stages = [
        StageScore(stage="auth", score_delta=20, reasons=["DKIM signature invalid"]),
        StageScore(stage="content", score_delta=60, reasons=["Urgency keywords", "Known phishing link"]),
    ]
    decision = decide(stage_scores=stages, warn_threshold=30, quarantine_threshold=70, tenant_id="tenant_x")

    assert decision.explainability is not None
    assert decision.explainability["summary_verdict"] == "QUARANTINE"
    assert "70" in decision.explainability["narrative"]
    assert len(decision.explainability["top_risk_drivers"]) == 3


def test_time_of_click_rewriter_and_service():
    secret = "super_secret_toc_key"
    base_url = "https://gateway.example.com"

    html = '<p>Click <a href="https://phishing.com/login">here</a> to reset password.</p>'
    rewritten_html, count = rewrite_urls_in_html(html, base_url, secret)
    assert count == 1
    assert "https://gateway.example.com/toc/redirect?url=" in rewritten_html

    # Extract query params
    import urllib.parse
    parsed = urllib.parse.urlparse(rewritten_html.split('href="')[1].split('"')[0])
    query = urllib.parse.parse_qs(parsed.query)

    encoded_url = query["url"][0]
    sig = query["sig"][0]

    service = TimeOfClickService(secret_key=secret)
    is_valid, target_url = service.decode_and_verify(encoded_url, sig)

    assert is_valid is True
    assert target_url == "https://phishing.com/login"

    # Tampered signature test
    is_valid_tampered, _ = service.decode_and_verify(encoded_url, "invalid_signature")
    assert is_valid_tampered is False


@pytest.mark.anyio
async def test_toc_service_click_evaluation():
    class DummyReputationProvider:
        async def check_url(self, url: str):
            class Verdict:
                is_malicious = "malicious" in url
                threat_type = "phishing" if is_malicious else ""
            return Verdict()

    service = TimeOfClickService(secret_key="secret", reputation_provider=DummyReputationProvider())

    safe, reason = await service.evaluate_click("https://safe.com/welcome")
    assert safe is True

    unsafe, reason_unsafe = await service.evaluate_click("https://malicious.com/phish")
    assert unsafe is False
    assert "malicious" in reason_unsafe
