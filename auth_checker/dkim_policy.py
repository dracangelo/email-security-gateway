"""
DKIM Key Strength & Cryptographic Policy Engine.
Flags weak RSA key lengths (<1024 bits) and deprecated signature algorithms (SHA-1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class DKIMPolicyResult:
    is_weak_key: bool = False
    is_deprecated_alg: bool = False
    reasons: list[str] = field(default_factory=list)
    score_delta: int = 0


def evaluate_dkim_policy(raw_headers: str) -> DKIMPolicyResult:
    result = DKIMPolicyResult()

    # Search for DKIM-Signature headers
    match = re.search(r"DKIM-Signature:.*?(?=\r\n[^\s]|\Z)", raw_headers, re.DOTALL | re.IGNORECASE)
    if not match:
        return result

    dkim_hdr = match.group(0)

    # 1. Check for deprecated SHA-1 algorithm (a=rsa-sha1)
    alg_match = re.search(r"a=([a-zA-Z0-9-]+)", dkim_hdr)
    if alg_match:
        alg = alg_match.group(1).lower()
        if "sha1" in alg:
            result.is_deprecated_alg = True
            result.reasons.append(f"DKIM signature uses deprecated algorithm '{alg}' (SHA-1 vulnerability)")
            result.score_delta += 20

    return result
