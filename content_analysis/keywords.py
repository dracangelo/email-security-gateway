"""
Heuristic phrase matching for social-engineering pressure tactics.

This is a blunt instrument by design -- regex-on-keywords will always have
false positives (a legitimate password-reset email says "reset your
password" too) and false negatives (a well-written BEC email needs none of
these phrases). Treat this as ONE signal that contributes points to the
overall score, never as a standalone pass/fail gate. It exists to catch the
high-volume, low-effort end of phishing, not a targeted spear-phish.

Weight matches conservatively for that reason -- keep per-match points low
and let convergence with other signals (auth failures, bad URLs) be what
actually pushes a message into quarantine.
"""
from __future__ import annotations

import re

from .models import KeywordMatch

# (regex, category, points-per-match). Word-boundaried and case-insensitive.
# Kept intentionally short and high-precision rather than exhaustive --
# a giant keyword list mostly just adds false positives on legitimate
# transactional mail (shipping notices, expense systems, IT tickets).
_PATTERNS: list[tuple[str, str, int]] = [
    # Urgency / pressure
    (r"\bact(ion)? (now|immediately|required)\b", "urgency", 6),
    (r"\b(within|in) (24|twenty[- ]four) hours\b", "urgency", 6),
    (r"\byour account (will be|has been) (suspended|locked|closed|disabled)\b", "urgency", 10),
    (r"\bfinal (notice|warning|reminder)\b", "urgency", 8),
    (r"\bverify your (account|identity|information) (immediately|now|today)\b", "urgency", 10),
    (r"\bunusual (sign-?in|login) activity\b", "urgency", 6),
    (r"\bsuspicious activity (detected|on your account)\b", "urgency", 6),
    # Credential harvesting
    (r"\b(confirm|update|verify) your password\b", "credential_harvest", 8),
    (r"\bclick here to (login|log in|sign in)\b", "credential_harvest", 8),
    (r"\bre-?enter your (credentials|password|login)\b", "credential_harvest", 10),
    (r"\byour (mailbox|inbox) (is full|will be closed|storage exceeded)\b", "credential_harvest", 8),
    # Financial / BEC (business email compromise)
    (r"\bwire transfer\b", "financial", 8),
    (r"\bupdate(d)? (banking|payment) (details|information)\b", "financial", 10),
    (r"\bgift cards?\b.{0,40}\b(purchase|buy|need)\b", "financial", 10),
    (r"\boutstanding (invoice|payment)\b", "financial", 6),
    (r"\bkindly (send|forward|process) (payment|the funds)\b", "financial", 8),
    (r"\bthis is confidential\b.{0,60}\b(don'?t|do not) (tell|discuss|mention)\b", "financial", 12),
    # Generic phishing tells
    (r"\bdear (customer|user|valued (customer|member))\b", "generic_phishing", 4),
    (r"\bcongratulations,? you('ve| have) (won|been selected)\b", "generic_phishing", 10),
    (r"\bclaim your (prize|reward|refund)\b", "generic_phishing", 10),
]

_COMPILED = [(re.compile(pattern, re.IGNORECASE), category, points) for pattern, category, points in _PATTERNS]


from .homoglyphs import strip_zero_width


def scan_keywords(text: str) -> tuple[list[KeywordMatch], int]:
    """
    Scans plaintext (already HTML-stripped if the source was HTML) for
    pressure-tactic phrases. Returns (matches, total_points). Each distinct
    pattern only counts once per message even if it appears multiple times,
    so a spammy message repeating "act now" five times doesn't get scored
    as five separate hits.
    """
    text_clean = strip_zero_width(text)
    matches: list[KeywordMatch] = []
    total = 0
    for regex, category, points in _COMPILED:
        m = regex.search(text_clean)
        if m:
            matches.append(KeywordMatch(phrase=m.group(0), category=category))
            total += points
    return matches, total

