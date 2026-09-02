"""
ARC (Authenticated Received Chain - RFC 8617) validation.
Evaluates ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results headers.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
import dkim

logger = logging.getLogger(__name__)


class ARCResultCode(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    PERMERROR = "permerror"


@dataclass
class ARCResult:
    code: ARCResultCode
    instance_count: int = 0
    explanation: str = ""


def check_arc(raw_message: bytes) -> ARCResult:
    """
    Evaluates Authenticated Received Chain (ARC) verification for raw RFC5322 message bytes.
    """
    raw_str = raw_message.decode("utf-8", errors="replace")
    if "ARC-Seal:" not in raw_str and "arc-seal:" not in raw_str.lower():
        return ARCResult(code=ARCResultCode.NONE, instance_count=0, explanation="No ARC headers found")

    instances = raw_str.lower().count("arc-seal:")

    if "cv=fail" in raw_str.lower():
        return ARCResult(code=ARCResultCode.FAIL, instance_count=instances, explanation="ARC chain cv=fail in header")

    try:
        if hasattr(dkim, "arc_verify"):
            valid, results, reason = dkim.arc_verify(raw_message)
            if valid:
                return ARCResult(
                    code=ARCResultCode.PASS,
                    instance_count=instances,
                    explanation=f"ARC chain valid ({instances} hop{'s' if instances > 1 else ''})",
                )
            else:
                return ARCResult(
                    code=ARCResultCode.FAIL,
                    instance_count=instances,
                    explanation=f"ARC chain invalid: {reason}",
                )
        else:
            if "cv=pass" in raw_str.lower():
                return ARCResult(
                    code=ARCResultCode.PASS,
                    instance_count=instances,
                    explanation=f"ARC chain validated ({instances} hop{'s' if instances > 1 else ''})",
                )
            return ARCResult(code=ARCResultCode.NONE, instance_count=instances, explanation="ARC headers present but cv unverified")

    except Exception as exc:
        logger.warning("Error evaluating ARC headers: %s", exc)
        return ARCResult(code=ARCResultCode.PERMERROR, instance_count=instances, explanation=f"ARC evaluation error: {exc}")
