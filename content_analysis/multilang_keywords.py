"""
Multi-language keyword detection, character set classification, and language identification.
Extends phishing/BEC keyword scanning to German, French, Spanish, Italian, Portuguese, Dutch,
Japanese, Russian, Chinese, and English with Unicode NFKC normalization and diacritic folding.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .keywords import KeywordMatch

MULTILANG_DICTIONARIES: dict[str, dict[str, list[tuple[str, int]]]] = {
    "de": {
        "financial_urgency": [
            ("dringende zahlung", 15),
            ("rechnung überfällig", 20),
            ("rechnung uberfallig", 20),
            ("überweisung ausstehend", 15),
            ("uberweisung ausstehend", 15),
            ("bankverbindung geändert", 25),
            ("bankverbindung geandert", 25),
            ("sofortige bezahlung", 20),
            ("letzte mahnung", 20),
        ],
        "credential_harvesting": [
            ("konto bestaetigen", 20),
            ("konto bestätigen", 20),
            ("passwort abgelaufen", 15),
            ("zugang gesperrt", 20),
            ("sicherheitsüberprüfung", 20),
            ("sicherheitsprufung", 20),
            ("ihr konto wurde eingeschränkt", 25),
        ],
        "executive_urgency": [
            ("bitte diskret behandeln", 20),
            ("gutscheinkarten kaufen", 25),
            ("sind sie am arbeitsplatz", 15),
        ],
    },
    "fr": {
        "financial_urgency": [
            ("paiement urgent", 15),
            ("facture impayée", 20),
            ("facture impayee", 20),
            ("virement en attente", 15),
            ("changement de coordonnées bancaires", 25),
            ("changement de coordonnees bancaires", 25),
            ("règlement immédiat", 20),
            ("relance de paiement", 15),
        ],
        "credential_harvesting": [
            ("confirmer votre compte", 20),
            ("mot de passe expiré", 15),
            ("mot de passe expire", 15),
            ("compte suspendu", 20),
            ("vérification d'identité", 20),
            ("action requise immédiatement", 20),
        ],
        "executive_urgency": [
            ("demande confidentielle", 20),
            ("acheter des cartes cadeaux", 25),
            ("êtes-vous disponible", 15),
        ],
    },
    "es": {
        "financial_urgency": [
            ("pago urgente", 15),
            ("factura vencida", 20),
            ("transferencia pendiente", 15),
            ("cambio de cuenta bancaria", 25),
            ("aviso de cobro", 15),
            ("pago inmediato", 20),
        ],
        "credential_harvesting": [
            ("confirmar su cuenta", 20),
            ("contraseña expirada", 15),
            ("contrasena expirada", 15),
            ("cuenta suspendida", 20),
            ("verificación de seguridad", 20),
            ("verificacion de seguridad", 20),
            ("acceso bloqueado", 20),
        ],
        "executive_urgency": [
            ("solicitud confidencial", 20),
            ("comprar tarjetas de regalo", 25),
            ("está disponible en este momento", 15),
        ],
    },
    "it": {
        "financial_urgency": [
            ("pagamento urgente", 15),
            ("fattura scaduta", 20),
            ("bonifico in sospeso", 15),
            ("modifica coordinate bancarie", 25),
            ("sollecito di pagamento", 15),
        ],
        "credential_harvesting": [
            ("conferma il tuo account", 20),
            ("password scaduta", 15),
            ("account sospeso", 20),
            ("accesso bloccato", 20),
            ("verifica di sicurezza", 20),
        ],
        "executive_urgency": [
            ("richiesta confidenziale", 20),
            ("acquistare carte regalo", 25),
            ("sei disponibile adesso", 15),
        ],
    },
    "pt": {
        "financial_urgency": [
            ("pagamento urgente", 15),
            ("fatura vencida", 20),
            ("transferência pendente", 15),
            ("transferencia pendente", 15),
            ("alteração de dados bancários", 25),
            ("alteracao de dados bancarios", 25),
            ("comprovante de transferência", 15),
        ],
        "credential_harvesting": [
            ("confirmar sua conta", 20),
            ("senha expirada", 15),
            ("conta bloqueada", 20),
            ("verificação de segurança", 20),
            ("atualização cadastral obrigatória", 25),
        ],
        "executive_urgency": [
            ("pedido confidencial", 20),
            ("comprar cartões presente", 25),
            ("você está disponível agora", 15),
        ],
    },
    "nl": {
        "financial_urgency": [
            ("dringende betaling", 15),
            ("factuur achterstallig", 20),
            ("openstaande rekening", 15),
            ("wijziging bankgegevens", 25),
            ("onmiddellijke betaling", 20),
        ],
        "credential_harvesting": [
            ("bevestig uw account", 20),
            ("wachtwoord verlopen", 15),
            ("account geblokkeerd", 20),
            ("beveiligingswaarschuwing", 20),
            ("toegang opgeschort", 20),
        ],
        "executive_urgency": [
            ("vertrouwelijk verzoek", 20),
            ("cadeaubonnen kopen", 25),
            ("bent u momenteel beschikbaar", 15),
        ],
    },
    "ja": {
        "financial_urgency": [
            ("至急の支払い", 20),
            ("請求書の未払い", 20),
            ("振込のお願い", 15),
            ("振込先変更", 25),
            ("送金手続き", 15),
        ],
        "credential_harvesting": [
            ("アカウントの停止", 25),
            ("パスワードの有効期限", 20),
            ("本人確認の手続き", 20),
            ("ログイン制限", 20),
            ("セキュリティ警告", 20),
        ],
        "executive_urgency": [
            ("至急対応願います", 20),
            ("ギフトカード購入", 25),
            ("社外秘", 15),
        ],
    },
    "ru": {
        "financial_urgency": [
            ("срочная оплата", 20),
            ("просроченный счет", 20),
            ("изменение банковских реквизитов", 25),
            ("подтверждение перевода", 15),
        ],
        "credential_harvesting": [
            ("учетная запись заблокирована", 25),
            ("срок действия пароля истек", 20),
            ("подтвердите ваш аккаунт", 20),
            ("подозрительная активность", 20),
        ],
        "executive_urgency": [
            ("конфиденциальное поручение", 20),
            ("купить подарочные карты", 25),
        ],
    },
    "zh": {
        "financial_urgency": [
            ("紧急付款", 20),
            ("逾期账单", 20),
            ("银行账户变更", 25),
            ("汇款通知", 15),
            ("立即转账", 20),
        ],
        "credential_harvesting": [
            ("账号已被冻结", 25),
            ("密码已过期", 20),
            ("安全验证", 20),
            ("身份核实", 20),
            ("重新激活账户", 25),
        ],
        "executive_urgency": [
            ("请协助保密", 20),
            ("采购礼品卡", 25),
            ("请问在公司吗", 15),
        ],
    },
}

LANG_INDICATORS: dict[str, list[str]] = {
    "de": ["und", "der", "die", "das", "bitte", "rechnung", "überweisung", "uberweisung", "dringende", "zahlung", "führungs"],
    "fr": ["et", "le", "la", "les", "votre", "facture", "paiement", "urgent", "virement", "compte"],
    "es": ["y", "el", "la", "los", "su", "factura", "pago", "urgente", "transferencia", "cuenta"],
    "it": ["e", "il", "la", "i", "le", "suo", "vostro", "fattura", "pagamento", "urgente", "bonifico"],
    "pt": ["e", "o", "a", "os", "as", "seu", "sua", "fatura", "pagamento", "urgente", "transferencia"],
    "nl": ["en", "de", "het", "van", "een", "voor", "factuur", "betaling", "dringende", "rekening"],
}


def _strip_diacritics(text: str) -> str:
    """Normalize unicode and strip combining diacritics for resilient keyword matching."""
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(c for c in normalized if unicodedata.category(c) != "Mn")


def detect_language(text: str) -> str:
    """
    Detect primary language code for input text using character sets and lexical indicators.
    Returns ISO 639-1 code ('en', 'de', 'fr', 'es', 'it', 'pt', 'nl', 'ja', 'ru', 'zh').
    """
    # 1. Script-based detection
    if re.search(r"[\u3040-\u309F\u30A0-\u30FF]", text):
        return "ja"
    if re.search(r"[\u0400-\u04FF]", text):
        return "ru"
    if re.search(r"[\u4E00-\u9FFF]", text):
        return "zh"

    # 2. Token-based detection for Latin-script languages
    normalized = _strip_diacritics(text.lower())
    words = set(re.findall(r"\b\w+\b", normalized))
    scores: dict[str, int] = {}

    for lang, indicators in LANG_INDICATORS.items():
        score = sum(1 for ind in indicators if _strip_diacritics(ind) in words)
        scores[lang] = score

    if not scores:
        return "en"

    best_lang, best_score = max(scores.items(), key=lambda item: item[1])
    return best_lang if best_score >= 1 else "en"


def scan_multilang_keywords(text: str) -> tuple[list[KeywordMatch], int]:
    """
    Scan text against multi-language phishing and BEC dictionaries.
    Returns matched keywords and aggregated score delta.
    """
    text_nfkc = unicodedata.normalize("NFKC", text).lower()
    text_stripped = _strip_diacritics(text_nfkc)
    lang = detect_language(text)

    if lang not in MULTILANG_DICTIONARIES:
        return [], 0

    matches: list[KeywordMatch] = []
    total_score = 0
    dictionary = MULTILANG_DICTIONARIES[lang]

    for category, phrases in dictionary.items():
        for phrase, weight in phrases:
            phrase_norm = phrase.lower()
            phrase_stripped = _strip_diacritics(phrase_norm)
            if phrase_norm in text_nfkc or phrase_stripped in text_stripped:
                matches.append(
                    KeywordMatch(
                        phrase=phrase,
                        category=f"{category}_{lang}",
                    )
                )
                total_score += weight

    return matches, total_score
