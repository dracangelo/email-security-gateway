"""
Shared result types for the email authentication pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SPFResultCode(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"          # no SPF record published
    TEMPERROR = "temperror"  # DNS hiccup, retry later
    PERMERROR = "permerror"  # malformed record / too many lookups


class DKIMResultCode(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"           # no DKIM-Signature header present
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class DMARCPolicy(str, Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class DMARCResultCode(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"            # no DMARC record published
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


@dataclass
class SPFResult:
    code: SPFResultCode
    domain: str                 # domain the SPF record was checked against
    client_ip: str
    explanation: str = ""
    dns_lookups_used: int = 0


@dataclass
class DKIMResult:
    code: DKIMResultCode
    signing_domain: str = ""    # the d= value from the signature that passed/failed
    selector: str = ""          # the s= value
    explanation: str = ""


@dataclass
class DMARCResult:
    code: DMARCResultCode
    record_found: bool = False
    policy: DMARCPolicy = DMARCPolicy.NONE
    subdomain_policy: DMARCPolicy | None = None
    pct: int = 100
    spf_alignment_mode: str = "r"   # "r" relaxed (default) or "s" strict, from aspf= tag
    dkim_alignment_mode: str = "r"  # from adkim= tag
    spf_aligned: bool = False
    dkim_aligned: bool = False
    organizational_domain: str = ""
    explanation: str = ""


class MTASTSResultCode(str, Enum):
    VALID = "valid"
    ENFORCE_FAILED = "enforce_failed"
    TESTING_FAILED = "testing_failed"
    NONE = "none"


@dataclass
class MTASTSResult:
    code: MTASTSResultCode
    mode: str = "none"
    tls_used: bool = True
    tls_version: str = ""
    explanation: str = ""


@dataclass
class AuthVerdict:
    """Aggregate result for one message, ready to feed the risk scorer."""
    from_domain: str
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    mta_sts: MTASTSResult | None = None
    arc: Any | None = None
    bimi: Any | None = None
    fcrdns: Any | None = None
    baseline: Any | None = None
    dnssec_valid: bool = False
    score_delta: int = 0          # points to add to the message's risk score
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        data = {
            "from_domain": self.from_domain,
            "spf": {"result": self.spf.code.value, "domain": self.spf.domain},
            "dkim": {"result": self.dkim.code.value, "signing_domain": self.dkim.signing_domain},
            "dmarc": {
                "result": self.dmarc.code.value,
                "policy": self.dmarc.policy.value,
                "spf_aligned": self.dmarc.spf_aligned,
                "dkim_aligned": self.dmarc.dkim_aligned,
            },
            "dnssec_valid": self.dnssec_valid,
            "score_delta": self.score_delta,
            "reasons": self.reasons,
        }
        if self.mta_sts:
            data["mta_sts"] = {"result": self.mta_sts.code.value, "mode": self.mta_sts.mode}
        if self.arc:
            data["arc"] = {"result": getattr(self.arc, "code", "none"), "instance_count": getattr(self.arc, "instance_count", 0)}
        if self.bimi:
            data["bimi"] = {"result": getattr(self.bimi, "code", "none"), "record_found": getattr(self.bimi, "record_found", False)}
        if self.fcrdns:
            data["fcrdns"] = {"result": getattr(self.fcrdns, "code", "none"), "is_confirmed": getattr(self.fcrdns, "is_confirmed", False)}
        if self.baseline:
            data["baseline"] = {"is_first_contact": getattr(self.baseline, "is_first_contact", False), "total_messages": getattr(self.baseline, "total_messages_seen", 0)}
        return data
