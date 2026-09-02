import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from decision_engine.models import Action, StageScore
from decision_engine.scorer import decide


class TestDecisionEngine:
    def test_low_score_forwards(self):
        decision = decide([StageScore(stage="auth", score_delta=0, reasons=[])])
        assert decision.action == Action.FORWARD

    def test_medium_score_warns(self):
        decision = decide([StageScore(stage="auth", score_delta=45, reasons=["SPF softfail"])])
        assert decision.action == Action.WARN_AND_STRIP

    def test_high_score_quarantines(self):
        decision = decide([StageScore(stage="content", score_delta=100, reasons=["malicious URL"])])
        assert decision.action == Action.QUARANTINE

    def test_scores_sum_across_stages(self):
        decision = decide([
            StageScore(stage="auth", score_delta=20, reasons=["DKIM none"]),
            StageScore(stage="content", score_delta=15, reasons=["urgency phrase"]),
        ])
        assert decision.total_score == 35
        assert decision.action == Action.WARN_AND_STRIP

    def test_boundary_exactly_at_quarantine_threshold(self):
        decision = decide([StageScore(stage="auth", score_delta=70, reasons=[])])
        assert decision.action == Action.QUARANTINE  # >= threshold, not just >

    def test_boundary_exactly_at_warn_threshold(self):
        decision = decide([StageScore(stage="auth", score_delta=30, reasons=[])])
        assert decision.action == Action.WARN_AND_STRIP

    def test_reasons_flattened_from_all_stages(self):
        decision = decide([
            StageScore(stage="auth", score_delta=30, reasons=["SPF hard fail"]),
            StageScore(stage="content", score_delta=10, reasons=["urgency phrase"]),
        ])
        assert "SPF hard fail" in decision.all_reasons
        assert "urgency phrase" in decision.all_reasons

    def test_invalid_threshold_configuration_rejected(self):
        with pytest.raises(ValueError):
            decide([StageScore(stage="auth", score_delta=0, reasons=[])], warn_threshold=80, quarantine_threshold=70)
