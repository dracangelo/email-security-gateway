"""
Unit tests for multi-language keyword scanner and language detector.
"""
from content_analysis.multilang_keywords import detect_language, scan_multilang_keywords


def test_detect_language():
    assert detect_language("Bitte überweisung der rechnung und überprüfen") == "de"
    assert detect_language("Paiement urgent de votre facture et virement") == "fr"
    assert detect_language("Pago urgente de su factura y transferencia") == "es"
    assert detect_language("Pagamento urgente della fattura e bonifico") == "it"
    assert detect_language("Pagamento urgente da fatura e transferencia") == "pt"
    assert detect_language("Dringende betaling van de factuur voor de rekening") == "nl"
    assert detect_language("至急の振込のお願いとお知らせ") == "ja"
    assert detect_language("Срочная оплата счета за услуги") == "ru"
    assert detect_language("请立即完成紧急付款和账单核对") == "zh"
    assert detect_language("Regular english message text") == "en"


def test_scan_multilang_keywords_german():
    text = "Bitte führen Sie eine dringende zahlung durch."
    matches, score = scan_multilang_keywords(text)
    assert len(matches) > 0
    assert matches[0].phrase == "dringende zahlung"
    assert score > 0


def test_scan_multilang_keywords_japanese():
    text = "至急の支払いをお願いします。アカウントの停止を防ぐためです。"
    matches, score = scan_multilang_keywords(text)
    assert len(matches) >= 2
    phrases = [m.phrase for m in matches]
    assert "至急の支払い" in phrases
    assert "アカウントの停止" in phrases
    assert score >= 40


def test_scan_multilang_keywords_chinese():
    text = "由于逾期账单未结清，您的账号已被冻结，请立即转账。"
    matches, score = scan_multilang_keywords(text)
    assert len(matches) >= 2
    phrases = [m.phrase for m in matches]
    assert "逾期账单" in phrases
    assert "账号已被冻结" in phrases
    assert score >= 40


def test_scan_multilang_keywords_italian():
    text = "Sollecito per pagamento urgente e bonifico in sospeso."
    matches, score = scan_multilang_keywords(text)
    assert len(matches) >= 2
    phrases = [m.phrase for m in matches]
    assert "pagamento urgente" in phrases
    assert "bonifico in sospeso" in phrases
    assert score >= 30


def test_scan_multilang_diacritics_resilience():
    # Test that 'überweisung ausstehend' matches even without umlaut ('uberweisung ausstehend')
    text = "Der status zeigt uberweisung ausstehend und konto bestaetigen bitte."
    matches, score = scan_multilang_keywords(text)
    assert len(matches) >= 1
    assert score > 0
