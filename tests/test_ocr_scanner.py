"""
Unit tests for embedded image OCR scanner.
"""
from content_analysis.ocr_scanner import scan_image_ocr


def test_ocr_scanner_empty():
    res = scan_image_ocr([])
    assert res.has_text is False


def test_ocr_scanner_fallback():
    sample_img = b"GIF89a Urgent action required verify your bank account details now"
    res = scan_image_ocr([sample_img])
    assert res.has_text is True
    assert len(res.extracted_text) > 0
