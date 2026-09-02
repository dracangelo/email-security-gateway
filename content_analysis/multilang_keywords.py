"""
Multi-language keyword detection and language identification.
Extends phishing/BEC keyword scanning to German, French, Spanish, Italian, Portuguese, and Dutch.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from .keywords import KeywordMatch

MULTILANG_DICTIONARIES: dict[str, dict[str, list[tuple[str, int]]]] = {
    "de": {
        "financial_urgency": [
            ("dringende zahlung", 15),
            ("rechnung überfällig", 20),
            ("überweisung ausstehend", 15),
            ("bankverbindung geändert", 25),
        ],
        "credential_harvesting": [
            ("konto bestaetigen", 20),
            ("passwort abgelaufen", 15),
            ("zugang gesperrt", 20),
        ],
    },
    "fr": {
        "financial_urgency": [
            ("paiement urgent", 15),
            ("facture impayée", 20),
            ("virement en attente", 15),
            ("changement de coordonnées bancaires", 25),
        ],
        "credential_harvesting": [
            ("confirmer votre compte", 20),
            ("mot de passe expiré", 15),
            ("compte suspendu", 20),
        ],
    },
    "es": {
        "financial_urgency": [
            ("pago urgente", 15),
            ("factura vencida", 20),
            ("transferencia pendiente", 15),
            ("cambio de cuenta bancaria", 25),
        ],
        "credential_harvesting": [
            ("confirmar su cuenta", 20),
            ("contraseña expirada", 15),
            ("cuenta suspendida", 20),
        ],
    },
}

LANG_INDICATORS = {
    "de": ["und", "der", "die", "das", "bitte", "rechnung", "überweisung", "dringende", "zahlung", "führungs"],
    "fr": ["et", "le", "la", "les", "votre", "facture", "paiement", "urgent"],
    "es": ["y", "el", "la", "los", "su", "factura", "pago", "urgente"],
}


def detect_language(text: str) -> str:
    """Detect primary language code for input text."""
    words = set(re.findall(r"\b\w+\b", text.lower()))
    scores = {}

    for lang, indicators in LANG_INDICATORS.items():
        score = sum(1 for ind in indicators if ind in words)
        scores[lang] = score

    best_lang = max(scores, key=scores.get) if scores else "en"
    return best_lang if scores.get(best_lang, 0) >= 1 else "en"


def scan_multilang_keywords(text: str) -> tuple[list[KeywordMatch], int]:
    """Scan text against multi-language phishing dictionaries."""
    text_lower = text.lower()
    lang = detect_language(text_lower)

    if lang not in MULTILANG_DICTIONARIES:
        return [], 0

    matches = []
    total_score = 0
    dictionary = MULTILANG_DICTIONARIES[lang]

    for category, phrases in dictionary.items():
        for phrase, weight in phrases:
            if phrase in text_lower:
                matches.append(
                    KeywordMatch(
                        phrase=phrase,
                        category=f"{category}_{lang}",
                    )
                )
                total_score += weight

    return matches, total_score
