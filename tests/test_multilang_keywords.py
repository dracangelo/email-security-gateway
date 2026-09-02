"""
Unit tests for multi-language keyword scanner and language detector.
"""
from content_analysis.multilang_keywords import detect_language, scan_multilang_keywords


def test_detect_language():
    assert detect_language("Bitte überweisung der rechnung und überprüfen") == "de"
    assert detect_language("Paiement urgent de votre facture et virement") == "fr"
    assert detect_language("Pago urgente de su factura y transferencia") == "es"
    assert detect_language("Regular english message text") == "en"


def test_scan_multilang_keywords_german():
    text = "Bitte führen Sie eine dringende zahlung durch."
    matches, score = scan_multilang_keywords(text)
    assert len(matches) > 0
    assert matches[0].phrase == "dringende zahlung"
    assert score > 0
