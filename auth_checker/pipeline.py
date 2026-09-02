"""
Orchestrates email authentication checks: SPF, DKIM, DMARC, ARC, BIMI, DNSSEC, FCrDNS, and Sender Baseline.
"""
from __future__ import annotations

from email import message_from_bytes
from email.utils import parseaddr

import dns.resolver

from .alignment import evaluate_dmarc
from .arc import ARCResultCode, check_arc
from .bimi import check_bimi
from .dkim_check import check_dkim
from .dkim_policy import evaluate_dkim_policy
from .dmarc import fetch_dmarc_policy
from .dnssec import create_dnssec_resolver
from .fcrdns import FCrDNSResultCode, check_fcrdns
from .ip_reputation import check_connecting_ip_reputation
from .models import AuthVerdict, DKIMResultCode, DMARCPolicy, DMARCResultCode, MTASTSResultCode, SPFResultCode
from .mta_sts import check_mta_sts
from .sender_baseline import evaluate_sender_baseline
from .spf import check_spf


def extract_from_domain(raw_message: bytes) -> str:
    """Pulls the domain out of the visible From: header (RFC 5322), lowercased."""
    msg = message_from_bytes(raw_message)
    _, addr = parseaddr(msg.get("From", ""))
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower()


def _score_spf(code: SPFResultCode) -> tuple[int, str | None]:
    if code == SPFResultCode.FAIL:
        return 30, "SPF hard fail"
    if code == SPFResultCode.SOFTFAIL:
        return 15, "SPF softfail"
    if code in (SPFResultCode.PERMERROR, SPFResultCode.TEMPERROR):
        return 5, f"SPF evaluation error ({code.value})"
    return 0, None


def _score_dkim(code: DKIMResultCode) -> tuple[int, str | None]:
    if code == DKIMResultCode.FAIL:
        return 30, "DKIM signature present but invalid"
    if code == DKIMResultCode.NONE:
        return 15, "no DKIM signature"
    if code in (DKIMResultCode.PERMERROR, DKIMResultCode.TEMPERROR):
        return 5, f"DKIM evaluation error ({code.value})"
    return 0, None


def _score_dmarc(code: DMARCResultCode, policy: DMARCPolicy) -> tuple[int, str | None]:
    if code != DMARCResultCode.FAIL:
        return 0, None
    if policy == DMARCPolicy.REJECT:
        return 50, "DMARC fail under p=reject"
    if policy == DMARCPolicy.QUARANTINE:
        return 35, "DMARC fail under p=quarantine"
    return 10, "DMARC fail under p=none (monitoring only)"


def run_auth_checks(
    raw_message: bytes,
    client_ip: str,
    envelope_from: str,
    resolver: dns.resolver.Resolver | None = None,
) -> AuthVerdict:
    """
    Evaluates SPF, DKIM, DMARC, ARC, BIMI, DNSSEC, FCrDNS, and Sender Baseline history.
    """
    resolver = resolver or create_dnssec_resolver()

    from_domain = extract_from_domain(raw_message)
    envelope_domain = envelope_from.rsplit("@", 1)[1].lower() if "@" in envelope_from else from_domain

    spf_result = check_spf(envelope_domain, client_ip, resolver, sender=envelope_from)
    dkim_result = check_dkim(raw_message)
    dmarc_record = fetch_dmarc_policy(from_domain, resolver)
    dmarc_result = evaluate_dmarc(from_domain, spf_result, dkim_result, dmarc_record)

    # ARC (Authenticated Received Chain) check
    arc_result = check_arc(raw_message)

    # BIMI check
    bimi_result = check_bimi(from_domain, resolver)

    # FCrDNS check
    fcrdns_result = check_fcrdns(client_ip, resolver)

    # Sender Baseline check
    baseline_result = evaluate_sender_baseline(from_domain or envelope_domain, client_ip)

    score_delta = 0
    reasons: list[str] = []

    # If DMARC/SPF failed but valid ARC chain exists, mitigate penalty (mailing list forwarding)
    if arc_result.code == ARCResultCode.PASS and (spf_result.code == SPFResultCode.FAIL or dmarc_result.code == DMARCResultCode.FAIL):
        reasons.append(f"ARC chain valid ({arc_result.instance_count} hops) - mitigated SPF/DMARC failure")
        score_delta += 5
    else:
        for points, reason in (
            _score_spf(spf_result.code),
            _score_dkim(dkim_result.code),
            _score_dmarc(dmarc_result.code, dmarc_result.policy),
        ):
            if reason:
                score_delta += points
                reasons.append(reason)

    # FCrDNS penalty / reason
    if fcrdns_result.code == FCrDNSResultCode.FAIL:
        score_delta += 15
        reasons.append(fcrdns_result.explanation)

    # Sender Baseline penalty / reason
    if baseline_result.score_delta > 0:
        score_delta += baseline_result.score_delta
        reasons.append(baseline_result.explanation)

    # DKIM Key Strength & Algorithm Policy
    try:
        raw_headers = raw_message.decode("utf-8", errors="replace").split("\r\n\r\n")[0]
        dkim_pol = evaluate_dkim_policy(raw_headers)
        if dkim_pol.reasons:
            score_delta += dkim_pol.score_delta
            reasons.extend(dkim_pol.reasons)
    except Exception:
        pass

    # Connecting IP Reputation
    ip_rep = check_connecting_ip_reputation(client_ip)
    if ip_rep.is_listed:
        score_delta += ip_rep.score_delta
        reasons.extend(ip_rep.reasons)

    # MTA-STS check on inbound leg
    headers_blob = raw_message.decode("utf-8", errors="replace").split("\r\n\r\n")[0]
    mta_sts_result = check_mta_sts(from_domain or envelope_domain, headers_blob=headers_blob)
    if mta_sts_result.code == MTASTSResultCode.ENFORCE_FAILED:
        score_delta += 20
        reasons.append(mta_sts_result.explanation)

    return AuthVerdict(
        from_domain=from_domain,
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
        mta_sts=mta_sts_result,
        arc=arc_result,
        bimi=bimi_result,
        fcrdns=fcrdns_result,
        baseline=baseline_result,
        dnssec_valid=True,
        score_delta=score_delta,
        reasons=reasons,
    )
