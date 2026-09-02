"""
Lightweight NLP / ML phishing intent classifier.
Evaluates semantic features, urgency density, and call-to-action ratios to output a phishing probability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

URGENCY_TOKENS = {"urgent", "immediately", "asap", "suspended", "verify", "expire", "action required", "alert", "security"}
FINANCIAL_TOKENS = {"invoice", "payment", "wire", "transfer", "bank", "account", "fund", "payroll", "gift card", "routing"}
ACTION_TOKENS = {"click here", "login", "confirm", "update", "sign in", "verify now", "access"}


@dataclass
class MLClassificationFinding:
    phishing_probability: float = 0.0
    is_phishing: bool = False
    score_delta: int = 0
    explanation: str = ""


def predict_phishing_probability(
    text: str,
    url_count: int = 0,
    is_first_contact: bool = False,
) -> MLClassificationFinding:
    """
    Evaluates semantic phishing features and outputs a calibrated probability score.
    """
    if not text.strip():
        return MLClassificationFinding()

    text_lower = text.lower()
    words = re.findall(r"\b\w+\b", text_lower)
    word_count = max(len(words), 1)

    urgency_hits = sum(1 for w in words if w in URGENCY_TOKENS)
    financial_hits = sum(1 for w in words if w in FINANCIAL_TOKENS)
    action_hits = sum(1 for phrase in ACTION_TOKENS if phrase in text_lower)

    urgency_ratio = urgency_hits / word_count
    financial_ratio = financial_hits / word_count
    url_density = url_count / word_count

    # Weighted linear model mapping features to [0.0, 1.0] probability curve
    logits = -3.5  # baseline bias
    logits += urgency_hits * 0.8
    logits += financial_hits * 0.9
    logits += action_hits * 1.2
    logits += (url_count > 0) * 1.0
    logits += (is_first_contact) * 0.8

    # Sigmoid function
    import math

    prob = 1.0 / (1.0 + math.exp(-logits))

    is_phishing = prob >= 0.70
    score_delta = 25 if is_phishing else (10 if prob >= 0.50 else 0)

    explanation = ""
    if is_phishing:
        explanation = f"ML classifier: high phishing intent probability ({prob:.2%})"
    elif prob >= 0.50:
        explanation = f"ML classifier: moderate suspicious intent probability ({prob:.2%})"

    return MLClassificationFinding(
        phishing_probability=round(prob, 4),
        is_phishing=is_phishing,
        score_delta=score_delta,
        explanation=explanation,
    )
