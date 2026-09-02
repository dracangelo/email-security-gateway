"""
Unit tests for QR code phishing (quishing) detection.
"""
from content_analysis.qr_detector import detect_qr_codes


def test_qr_detector_empty():
    res = detect_qr_codes([])
    assert res.has_qr_code is False


def test_qr_detector_fallback_raw_string():
    sample_qr_img = b"PNG header data ... https://phishing-target.com/login ... end PNG data"
    res = detect_qr_codes([sample_qr_img])
    assert res.has_qr_code is True
    assert "https://phishing-target.com/login" in res.decoded_urls
