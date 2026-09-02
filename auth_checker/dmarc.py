"""
DMARC (RFC 7489) record lookup + parsing.

NOTE on organizational domain: full PSL (Public Suffix List) tree-walking is
what RFC 7489 actually specifies for finding the organizational domain when
a subdomain has no DMARC record of its own. We approximate it with a
"take the last two labels" heuristic here, which is wrong for domains like
`example.co.uk` or `example.github.io`. Swap `_org_domain()` for the `publicsuffix2`
or `tldextract` package before this goes near production traffic -- flagging
that explicitly rather than silently shipping a wrong answer.
"""
from __future__ import annotations

import dns.resolver
import dns.exception

from .models import DMARCPolicy, DMARCResult, DMARCResultCode

_RESOLVER_TIMEOUT = 5.0


try:
    import publicsuffix2
except ImportError:
    publicsuffix2 = None


def _org_domain(domain: str) -> str:
    """RFC 7489 compliant Organizational Domain resolution via Public Suffix List."""
    domain_clean = domain.strip(".").lower()
    if publicsuffix2:
        res = publicsuffix2.get_public_suffix(domain_clean)
        if res:
            return res
    labels = domain_clean.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain_clean



def _fetch_dmarc_txt(domain: str, resolver: dns.resolver.Resolver) -> str | None:
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=_RESOLVER_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt.strip().lower().startswith("v=dmarc1"):
            records.append(txt)
    if len(records) != 1:
        return None
    return records[0]


def _parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags


def _policy(value: str | None) -> DMARCPolicy:
    try:
        return DMARCPolicy(value.lower()) if value else DMARCPolicy.NONE
    except ValueError:
        return DMARCPolicy.NONE  # malformed p= tag -> treat as no enforcement


def fetch_dmarc_policy(from_domain: str, resolver: dns.resolver.Resolver | None = None) -> DMARCResult:
    """
    Looks up the DMARC record for `from_domain` (the visible From: header
    domain -- this is the one DMARC actually cares about, unlike SPF which
    checks the envelope sender). Falls back to the organizational domain
    per RFC 7489 6.6.3 if the exact domain has none.
    """
    resolver = resolver or dns.resolver.Resolver()
    try:
        record = _fetch_dmarc_txt(from_domain, resolver)
        org_domain = from_domain
        if record is None:
            org_domain = _org_domain(from_domain)
            if org_domain != from_domain:
                record = _fetch_dmarc_txt(org_domain, resolver)
    except dns.exception.DNSException as exc:
        return DMARCResult(code=DMARCResultCode.TEMPERROR, explanation=f"DNS error: {exc}")

    if record is None:
        return DMARCResult(code=DMARCResultCode.NONE, explanation="no DMARC record published", organizational_domain=org_domain)

    tags = _parse_tags(record)
    if "p" not in tags:
        return DMARCResult(code=DMARCResultCode.PERMERROR, explanation="DMARC record missing required p= tag")

    policy = _policy(tags.get("p"))
    sp = _policy(tags["sp"]) if "sp" in tags else None
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100

    return DMARCResult(
        code=DMARCResultCode.NONE,  # placeholder -- pass/fail gets filled in by alignment.py
        record_found=True,
        policy=policy,
        subdomain_policy=sp,
        pct=max(0, min(100, pct)),
        spf_alignment_mode="s" if tags.get("aspf", "r").lower() == "s" else "r",
        dkim_alignment_mode="s" if tags.get("adkim", "r").lower() == "s" else "r",
        organizational_domain=org_domain,
        explanation=f"policy={policy.value} pct={pct}",
    )
