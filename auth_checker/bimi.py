"""
BIMI (Brand Indicators for Message Identification) validation.
Queries default._bimi.<domain> TXT record, parses logo location and VMC authority URLs.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
import dns.resolver

logger = logging.getLogger(__name__)


class BIMIResultCode(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    NONE = "none"


@dataclass
class BIMIResult:
    code: BIMIResultCode
    record_found: bool = False
    location_url: str = ""
    authority_url: str = ""
    vmc_present: bool = False
    explanation: str = ""


def check_bimi(domain: str, resolver: dns.resolver.Resolver | None = None) -> BIMIResult:
    """
    Check BIMI DNS record for `default._bimi.<domain>`.
    """
    if not domain:
        return BIMIResult(code=BIMIResultCode.NONE, explanation="No domain provided for BIMI check")

    resolver = resolver or dns.resolver.Resolver()
    bimi_domain = f"default._bimi.{domain}"

    try:
        answers = resolver.resolve(bimi_domain, "TXT", lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return BIMIResult(code=BIMIResultCode.NONE, explanation="No BIMI TXT record found")
    except Exception as exc:
        return BIMIResult(code=BIMIResultCode.NONE, explanation=f"DNS error during BIMI lookup: {exc}")

    bimi_records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.strip().lower().startswith("v=bimi1"):
            bimi_records.append(txt.strip())

    if not bimi_records:
        return BIMIResult(code=BIMIResultCode.NONE, explanation="No v=BIMI1 record found")

    record = bimi_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    location = tags.get("l", "")
    authority = tags.get("a", "")
    vmc_present = bool(authority and authority != "self")

    if not location and not authority:
        return BIMIResult(
            code=BIMIResultCode.INVALID,
            record_found=True,
            explanation="BIMI record present but missing 'l=' location tag",
        )

    return BIMIResult(
        code=BIMIResultCode.VALID,
        record_found=True,
        location_url=location,
        authority_url=authority,
        vmc_present=vmc_present,
        explanation=f"Valid BIMI record found (VMC {'present' if vmc_present else 'absent'})",
    )
