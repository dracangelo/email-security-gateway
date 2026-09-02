"""
MTA-STS (Mail Transfer Agent Strict Transport Security) and TLS-RPT checking.
Verifies inbound leg TLS transport policy and generates RFC 8460 TLS reports.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from .models import MTASTSResult, MTASTSResultCode

logger = logging.getLogger(__name__)


@dataclass
class MTASTSPolicy:
    version: str = "STSv1"
    mode: str = "none"  # "enforce", "testing", "none"
    max_age: int = 86400
    mx: list[str] = None

    def __post_init__(self):
        if self.mx is None:
            self.mx = []


def parse_mta_sts_policy(text: str) -> MTASTSPolicy:
    """Parse key-value pairs from an MTA-STS policy document."""
    mode = "none"
    max_age = 86400
    mx_list = []
    version = "STSv1"

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()
            if key == "version":
                version = val
            elif key == "mode":
                mode = val.lower()
            elif key == "max_age":
                try:
                    max_age = int(val)
                except ValueError:
                    pass
            elif key == "mx":
                mx_list.append(val)

    return MTASTSPolicy(version=version, mode=mode, max_age=max_age, mx=mx_list)


def check_mta_sts(
    domain: str,
    headers_blob: str = "",
    connection_tls: dict[str, Any] | None = None,
    policy: MTASTSPolicy | None = None,
) -> MTASTSResult:
    """
    Check whether the inbound message satisfied MTA-STS transport requirements.
    Detects TLS usage from connection_tls or `Received:` header signals.
    """
    if policy is None:
        policy = MTASTSPolicy(mode="none")

    tls_used = False
    tls_version = ""

    if connection_tls and isinstance(connection_tls, dict):
        tls_used = bool(connection_tls.get("tls_used"))
        tls_version = str(connection_tls.get("tls_version", ""))
    else:
        # Detect TLS from Received: headers (e.g., "using TLSv1.3", "using TLSv1.2", "with ESMTPS")
        rx_match = re.search(r"Received:.*?(using|with)\s+(TLSv[\d\.]+|ESMTPS)", headers_blob, re.IGNORECASE | re.DOTALL)
        if rx_match:
            tls_used = True
            tls_version = rx_match.group(2)
        elif "esmtps" in headers_blob.lower() or "tls" in headers_blob.lower():
            tls_used = True
            tls_version = "TLS"

    if policy.mode == "none":
        return MTASTSResult(
            code=MTASTSResultCode.NONE,
            mode="none",
            tls_used=tls_used,
            tls_version=tls_version,
            explanation="No active MTA-STS policy enforced for domain",
        )

    if not tls_used:
        if policy.mode == "enforce":
            return MTASTSResult(
                code=MTASTSResultCode.ENFORCE_FAILED,
                mode="enforce",
                tls_used=False,
                tls_version="",
                explanation="MTA-STS policy enforce requires TLS, but unencrypted cleartext transport was used",
            )
        else:  # testing
            return MTASTSResult(
                code=MTASTSResultCode.TESTING_FAILED,
                mode="testing",
                tls_used=False,
                tls_version="",
                explanation="MTA-STS policy testing mode: plain text transport detected",
            )

    return MTASTSResult(
        code=MTASTSResultCode.VALID,
        mode=policy.mode,
        tls_used=True,
        tls_version=tls_version,
        explanation=f"MTA-STS policy satisfied ({policy.mode} mode, {tls_version})",
    )


def generate_tls_rpt(domain: str, result: MTASTSResult) -> dict[str, Any]:
    """
    Generate an RFC 8460 TLS-RPT (TLS Report) JSON structure for security auditing.
    """
    is_success = result.code in (MTASTSResultCode.VALID, MTASTSResultCode.NONE)
    summary = {
        "total-successful-session-count": 1 if is_success else 0,
        "total-failure-session-count": 0 if is_success else 1,
    }

    failure_details = []
    if not is_success:
        failure_details.append({
            "result-type": "sts-policy-failure",
            "sending-mta-ip": "0.0.0.0",
            "receiving-mx-hostname": domain,
            "failed-session-count": 1,
            "additional-information": result.explanation,
        })

    return {
        "organization-name": "Email Auth Gateway",
        "date-range": {"start-datetime": "2026-08-17T00:00:00Z", "end-datetime": "2026-08-17T23:59:59Z"},
        "contact-info": f"postmaster@{domain}",
        "report-id": f"tls-rpt-{domain}",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": [f"version: STSv1", f"mode: {result.mode}"],
                    "policy-domain": domain,
                },
                "summary": summary,
                "failure-details": failure_details,
            }
        ],
    }
