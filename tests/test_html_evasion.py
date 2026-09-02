"""
Unit tests for HTML CSS evasion handling.
"""
from content_analysis.html_evasion import detect_html_evasion


def test_html_evasion_none():
    html = "<div><p>Hello world, this is a clean email.</p></div>"
    res = detect_html_evasion(html)
    assert res.has_evasion is False


def test_html_evasion_display_none():
    html = '<div><span style="display:none">secret spam phrase</span>Visible content</div>'
    res = detect_html_evasion(html)
    assert res.has_evasion is True
    assert "secret spam phrase" in res.hidden_text
    assert "Visible content" in res.visible_text
    assert "display:none" in res.evasion_techniques


def test_html_evasion_font_size_zero():
    html = '<p style="font-size:0px">hidden text</p><p>visible text</p>'
    res = detect_html_evasion(html)
    assert res.has_evasion is True
    assert "font-size:0" in res.evasion_techniques
