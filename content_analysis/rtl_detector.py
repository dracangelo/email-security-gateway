"""
RTL (Right-to-Left) override Unicode character and filename extension spoofing detection.
Detects U+202E and related directional control characters used to evade filters or disguise file extensions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

RTL_CONTROL_CHARS = {
    "\u202e": "RIGHT-TO-LEFT OVERRIDE (RLO)",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING (RLE)",
    "\u202c": "POP DIRECTIONAL FORMATTING (PDF)",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE (LRO)",
    "\u2066": "LEFT-TO-RIGHT ISOLATE (LRI)",
    "\u2067": "RIGHT-TO-LEFT ISOLATE (RLI)",
    "\u2068": "FIRST STRONG ISOLATE (FSI)",
    "\u2069": "POP DIRECTIONAL ISOLATE (PDI)",
}

RTL_REGEX = re.compile(r"[\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]")


@dataclass
class RTLFinding:
    has_rtl_override: bool = False
    is_filename_spoof: bool = False
    detected_chars: list[str] = field(default_factory=list)
    clean_text: str = ""
    explanation: str = ""


def detect_rtl_override(text: str, filename: str = "") -> RTLFinding:
    """
    Detects directional Unicode overrides in text bodies or filenames.
    """
    found_chars = []
    has_override = False
    is_filename_spoof = False
    reasons = []

    # Check text and filename for RTL control characters
    for char, name in RTL_CONTROL_CHARS.items():
        if char in text or char in filename:
            has_override = True
            if name not in found_chars:
                found_chars.append(name)

    clean_text = RTL_REGEX.sub("", text)

    # Any RTL control character in a filename is treated as extension spoofing
    if filename:
        for char in RTL_CONTROL_CHARS:
            if char in filename:
                is_filename_spoof = True
                reasons.append(f"Filename extension spoofing using RTL override: {filename}")
                break

    if has_override and not is_filename_spoof:
        reasons.append(f"RTL directional override character(s) detected: {', '.join(found_chars)}")

    return RTLFinding(
        has_rtl_override=has_override,
        is_filename_spoof=is_filename_spoof,
        detected_chars=found_chars,
        clean_text=clean_text,
        explanation="; ".join(reasons) if reasons else "",
    )
