"""
Unit tests for polyglot file detection.
"""
from attachment_analysis.polyglot import detect_polyglot_file


def test_polyglot_normal():
    data = b"GIF89a normal image header content"
    res = detect_polyglot_file(data)
    assert res.is_polyglot is False


def test_polyglot_gif_zip():
    # File containing both GIF signature and ZIP signature
    polyglot_data = b"GIF89a ... " + (b"A" * 50) + b"PK\x03\x04 ... zip payload"
    res = detect_polyglot_file(polyglot_data)
    assert res.is_polyglot is True
    assert "GIF" in res.detected_formats
    assert "ZIP" in res.detected_formats
    assert res.explanation != ""
