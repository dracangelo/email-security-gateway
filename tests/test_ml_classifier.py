"""
Unit tests for NLP / ML phishing intent classifier.
"""
from content_analysis.ml_classifier import predict_phishing_probability


def test_ml_classifier_benign():
    text = "Hi Team, attached is the minutes from today's sync meeting."
    res = predict_phishing_probability(text)
    assert res.is_phishing is False
    assert res.phishing_probability < 0.50


def test_ml_classifier_phishing():
    text = "URGENT ACTION REQUIRED: Verify your bank account immediately to avoid account suspension. Click here to login and update your credentials."
    res = predict_phishing_probability(text, url_count=1, is_first_contact=True)
    assert res.is_phishing is True
    assert res.phishing_probability >= 0.70
    assert res.score_delta > 0
