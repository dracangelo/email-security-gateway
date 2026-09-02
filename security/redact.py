"""
Redaction for anything that might land in logs or the audit trail.

Two distinct concerns, both handled here:
  1. Never let OUR OWN secrets (API keys, the webhook shared secret) leak
     into log lines via accidental interpolation of a config object,
     exception message, or repr().
  2. Phishing/BEC email content routinely CONTAINS credentials, API keys,
     and tokens -- either the attacker is trying to harvest them, or
     they got pasted into a forwarded thread. Don't let the audit trail
     become a second copy of whatever the attacker was after.
  3. Extended PII redaction: Redact Social Security Numbers (SSN), Credit Card Numbers (PAN),
     IBANs, and Phone Numbers from audit logs and excerpts.
"""
from __future__ import annotations

import re

_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
]

_EXTENDED_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    # US Social Security Numbers: 000-00-0000
    (re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "[REDACTED_SSN]"),
    # Credit Card Numbers (Visa, Mastercard, Amex, Discover): 13-19 digits with optional spaces/dashes
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"), "[REDACTED_CC]"),
    # IBANs: Country code (2 letters), 2 check digits, up to 30 alphanumeric
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b"), "[REDACTED_IBAN]"),
    # Phone numbers: +1-800-555-0199 or (555) 555-0199
    (re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
]

_GENERIC_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9]{32,}\b")

_REDACTED = "[REDACTED]"

# Dict keys that get fully redacted regardless of their value's shape.
_SENSITIVE_KEY_RE = re.compile(r"(key|secret|token|password|passwd|pwd|authorization|cookie|ssn|credit_card|card_number)", re.IGNORECASE)


def redact(text: str, redact_extended_pii: bool = True) -> str:
    if not text:
        return text
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(_REDACTED, out)
    if redact_extended_pii:
        for pattern, replacement in _EXTENDED_PII_PATTERNS:
            out = pattern.sub(replacement, out)
    out = _GENERIC_LONG_TOKEN.sub(_REDACTED, out)
    return out


def redact_dict(d: dict, extra_keys_to_redact: tuple[str, ...] = (), redact_extended_pii: bool = True) -> dict:
    """
    Shallow-recursive redaction: dict values whose KEY looks secret-shaped
    (or is explicitly listed in extra_keys_to_redact) are fully replaced;
    string values are pattern-scanned via redact(); nested dicts recurse;
    everything else passes through unchanged.
    """
    out = {}
    for k, v in d.items():
        if _SENSITIVE_KEY_RE.search(k) or k in extra_keys_to_redact:
            out[k] = _REDACTED
        elif isinstance(v, str):
            out[k] = redact(v, redact_extended_pii=redact_extended_pii)
        elif isinstance(v, dict):
            out[k] = redact_dict(v, extra_keys_to_redact, redact_extended_pii=redact_extended_pii)
        elif isinstance(v, list):
            out[k] = [
                redact_dict(i, extra_keys_to_redact, redact_extended_pii)
                if isinstance(i, dict)
                else (redact(i, redact_extended_pii) if isinstance(i, str) else i)
                for i in v
            ]
        else:
            out[k] = v
    return out
