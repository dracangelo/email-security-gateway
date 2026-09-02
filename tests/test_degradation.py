"""
Unit tests for degradation matrix module.
"""
from reliability.degradation_matrix import DegradationMatrix


def test_degradation_matrix_evaluation():
    matrix = DegradationMatrix()

    # Full capabilities
    report_full = matrix.evaluate_degraded_pipeline([])
    assert report_full.degradation_level == "FULL"
    assert report_full.safe_to_operate is True

    # Partial degradation
    report_deg = matrix.evaluate_degraded_pipeline(["virustotal", "rdap"])
    assert report_deg.degradation_level == "DEGRADED"
    assert len(report_deg.disabled_capabilities) == 2
    assert report_deg.safe_to_operate is True
