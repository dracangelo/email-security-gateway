"""
Homoglyph / IDN lookalike detection and zero-width character scanning.
Catches punycode (xn--) domains, mixed-script character spoofs (e.g., Cyrillic 'а' vs Latin 'a'),
and zero-width Unicode obfuscation tricks.
"""
from __future__ import annotations

import re
from typing import NamedTuple

try:
    from confusable_homoglyphs import confusables
except ImportError:
    confusables = None

ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E]")


class HomoglyphFinding(NamedTuple):
    target: str
    reason: str
    is_punycode: bool = False
    has_confusables: bool = False
    has_zero_width: bool = False


def strip_zero_width(text: str) -> str:
    """Removes hidden zero-width unicode characters used to bypass regex keyword filters."""
    return ZERO_WIDTH_CHARS.sub("", text)


def detect_homoglyphs_and_idn(text_or_domain: str) -> list[HomoglyphFinding]:
    """
    Scans a domain, URL, or string for punycode (xn--), zero-width characters, or confusable characters.
    """
    findings: list[HomoglyphFinding] = []

    if ZERO_WIDTH_CHARS.search(text_or_domain):
        findings.append(
            HomoglyphFinding(
                target=text_or_domain,
                reason="contains zero-width / invisible Unicode characters",
                has_zero_width=True,
            )
        )

    target_lower = text_or_domain.lower()
    if "xn--" in target_lower:
        findings.append(
            HomoglyphFinding(
                target=text_or_domain,
                reason=f"IDN Punycode domain detected ({text_or_domain})",
                is_punycode=True,
            )
        )

    if confusables:
        # Check if the string contains confusable homoglyphs from different scripts
        res = confusables.is_confusable(text_or_domain, preferred_aliases=["latin"])
        if res:
            for item in res:
                char = item.get("character", "")
                homoglyphs = item.get("homoglyphs", [])
                scripts = [h.get("script", "") for h in homoglyphs]
                findings.append(
                    HomoglyphFinding(
                        target=text_or_domain,
                        reason=f"contains homoglyph char '{char}' confusable with Latin in scripts {scripts}",
                        has_confusables=True,
                    )
                )

    return findings
