"""
DMARC identifier alignment (RFC 7489 3.1).

DMARC doesn't just ask "did SPF/DKIM pass" -- it asks "did they pass FOR
THE DOMAIN THE USER ACTUALLY SEES in the From: header". This is the whole
point of DMARC: it closes the gap where SPF checks the invisible envelope
sender and DKIM's d= can be any domain the signer chooses, neither of
which the recipient ever looks at.

Classic bypass this catches: envelope-from bounces@totally-legit-bulk-mailer.com
(passes SPF for that domain) with a visible From: security@yourbank.com
(what the user sees). Without alignment, that message could pass SPF and
still successfully spoof the brand.
"""
from __future__ import annotations

from .dmarc import _org_domain
from .models import DKIMResult, DKIMResultCode, DMARCResult, DMARCResultCode, SPFResult, SPFResultCode


def _domains_aligned(candidate_domain: str, from_domain: str, mode: str) -> bool:
    if not candidate_domain:
        return False
    candidate_domain = candidate_domain.lower().rstrip(".")
    from_domain = from_domain.lower().rstrip(".")
    if mode == "s":  # strict: exact match only
        return candidate_domain == from_domain
    # relaxed (default): same organizational domain is good enough
    return _org_domain(candidate_domain) == _org_domain(from_domain)


def evaluate_dmarc(
    from_domain: str,
    spf_result: SPFResult,
    dkim_result: DKIMResult,
    dmarc_record: DMARCResult,
) -> DMARCResult:
    """
    Combines the already-computed SPF/DKIM results with the DMARC policy
    record to produce a final pass/fail + alignment verdict.
    """
    if not dmarc_record.record_found or dmarc_record.code in (DMARCResultCode.PERMERROR, DMARCResultCode.TEMPERROR):
        # No enforceable policy -- nothing to align against.
        return dmarc_record

    spf_aligned = spf_result.code == SPFResultCode.PASS and _domains_aligned(
        spf_result.domain, from_domain, dmarc_record.spf_alignment_mode
    )
    dkim_aligned = dkim_result.code == DKIMResultCode.PASS and _domains_aligned(
        dkim_result.signing_domain, from_domain, dmarc_record.dkim_alignment_mode
    )

    passed = spf_aligned or dkim_aligned

    dmarc_record.spf_aligned = spf_aligned
    dmarc_record.dkim_aligned = dkim_aligned
    dmarc_record.code = DMARCResultCode.PASS if passed else DMARCResultCode.FAIL
    dmarc_record.explanation = (
        f"policy={dmarc_record.policy.value} spf_aligned={spf_aligned} dkim_aligned={dkim_aligned}"
    )
    return dmarc_record
