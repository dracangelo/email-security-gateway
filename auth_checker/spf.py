"""
SPF (RFC 7208) evaluation with Macro Expansion and exists: mechanism support.

Evaluates ip4, ip6, a, mx, include, redirect, exists, and macro expansion per RFC 7208 section 7.
"""
from __future__ import annotations

import ipaddress
import re
import dns.resolver
import dns.exception

from .models import SPFResult, SPFResultCode

MAX_DNS_LOOKUPS = 10  # RFC 7208 4.6.4 -- hard cap to prevent DoS via nested includes
_RESOLVER_TIMEOUT = 5.0


class _LookupBudget:
    """Tracks the shared 10-lookup ceiling across a recursive SPF evaluation."""

    def __init__(self, limit: int = MAX_DNS_LOOKUPS):
        self.limit = limit
        self.used = 0

    def spend(self) -> bool:
        """Returns False if the budget is exhausted (caller should PermError)."""
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def expand_spf_macros(
    text: str,
    sender: str,
    domain: str,
    client_ip: str,
    helo: str = "unknown",
) -> str:
    """
    RFC 7208 Section 7 macro expansion.
    Specifiers: s, l, o, d, i, p, v, h
    Escape: %%, %_, %-
    Modifiers: r (reverse labels), count (number of labels).
    """
    if "%" not in text:
        return text

    local_part = sender.rsplit("@", 1)[0] if "@" in sender else sender
    sender_domain = sender.rsplit("@", 1)[1] if "@" in sender else domain
    is_ipv6 = ":" in client_ip

    def _sub_macro(match_str: str) -> str:
        inner = match_str[2:-1]
        if not inner:
            return ""

        letter = inner[0].lower()
        if letter == "s":
            val = sender
        elif letter == "l":
            val = local_part
        elif letter == "o":
            val = sender_domain
        elif letter == "d":
            val = domain
        elif letter == "i":
            val = client_ip
        elif letter == "p":
            val = "unknown"
        elif letter == "v":
            val = "ip6" if is_ipv6 else "in-addr"
        elif letter == "h":
            val = helo
        else:
            val = letter

        modifier = inner[1:]
        if modifier:
            reverse = "r" in modifier.lower()
            digits = "".join(c for c in modifier if c.isdigit())
            count = int(digits) if digits else 0
            delimiters = [c for c in modifier if not c.isdigit() and c.lower() != "r"]
            delim = delimiters[0] if delimiters else "."

            parts = val.split(delim)
            if reverse:
                parts = parts[::-1]
            if count and count < len(parts):
                parts = parts[-count:]
            val = delim.join(parts)

        return val

    res = text.replace("%%", "%").replace("%_", " ").replace("%-", "%20")
    res = re.sub(r"%\{[^}]+\}", lambda m: _sub_macro(m.group(0)), res)
    return res


def _get_txt_records(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answers = resolver.resolve(domain, "TXT", lifetime=_RESOLVER_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        raise
    records = []
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
        records.append(txt)
    return records


def _find_spf_record(domain: str, resolver: dns.resolver.Resolver) -> str | None:
    try:
        txts = _get_txt_records(domain, resolver)
    except dns.exception.DNSException:
        return None
    spf_records = [t for t in txts if t.strip().lower().startswith("v=spf1")]
    if len(spf_records) != 1:
        return "__MULTIPLE__" if len(spf_records) > 1 else None
    return spf_records[0]


def _ip_matches_cidr(ip: str, cidr: str, default_prefix: int) -> bool:
    try:
        if "/" not in cidr:
            cidr = f"{cidr}/{default_prefix}"
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _evaluate(
    domain: str,
    client_ip: str,
    resolver: dns.resolver.Resolver,
    budget: _LookupBudget,
    sender: str = "",
    depth: int = 0,
) -> SPFResultCode:
    if depth > 10:
        return SPFResultCode.PERMERROR

    record = _find_spf_record(domain, resolver)
    if record == "__MULTIPLE__":
        return SPFResultCode.PERMERROR
    if record is None:
        return SPFResultCode.NONE

    is_ipv6 = ":" in client_ip
    sender = sender or f"user@{domain}"
    terms = record.split()[1:]
    redirect_domain = None

    for term in terms:
        qualifier = "+"
        mech = term
        if term and term[0] in "+-~?":
            qualifier, mech = term[0], term[1:]

        if mech == "all":
            return _qualifier_to_result(qualifier)

        if mech.startswith("ip4:") and not is_ipv6:
            if _ip_matches_cidr(client_ip, mech[4:], 32):
                return _qualifier_to_result(qualifier)
            continue

        if mech.startswith("ip6:") and is_ipv6:
            if _ip_matches_cidr(client_ip, mech[4:], 128):
                return _qualifier_to_result(qualifier)
            continue

        if mech.startswith("include:"):
            if not budget.spend():
                return SPFResultCode.PERMERROR
            included_domain = expand_spf_macros(mech[8:], sender, domain, client_ip)
            sub_result = _evaluate(included_domain, client_ip, resolver, budget, sender, depth + 1)
            if sub_result == SPFResultCode.PASS:
                return _qualifier_to_result(qualifier)
            if sub_result in (SPFResultCode.PERMERROR,):
                return SPFResultCode.PERMERROR
            continue

        if mech.startswith("a") and (mech == "a" or mech.startswith("a:") or mech.startswith("a/")):
            if not budget.spend():
                return SPFResultCode.PERMERROR
            target = mech.split(":", 1)[1].split("/")[0] if ":" in mech else domain
            target = expand_spf_macros(target, sender, domain, client_ip)
            if _resolve_matches(target, client_ip, resolver, is_ipv6):
                return _qualifier_to_result(qualifier)
            continue

        if mech.startswith("mx") and (mech == "mx" or mech.startswith("mx:") or mech.startswith("mx/")):
            if not budget.spend():
                return SPFResultCode.PERMERROR
            target = mech.split(":", 1)[1].split("/")[0] if ":" in mech else domain
            target = expand_spf_macros(target, sender, domain, client_ip)
            if _mx_matches(target, client_ip, resolver, is_ipv6, budget):
                return _qualifier_to_result(qualifier)
            continue

        if mech.startswith("exists:"):
            if not budget.spend():
                return SPFResultCode.PERMERROR
            target = expand_spf_macros(mech[7:], sender, domain, client_ip)
            try:
                answers = resolver.resolve(target, "A", lifetime=_RESOLVER_TIMEOUT)
                if len(answers) > 0:
                    return _qualifier_to_result(qualifier)
            except dns.exception.DNSException:
                pass
            continue


        if mech.startswith("redirect="):
            redirect_domain = expand_spf_macros(mech.split("=", 1)[1], sender, domain, client_ip)
            continue

    if redirect_domain:
        if not budget.spend():
            return SPFResultCode.PERMERROR
        return _evaluate(redirect_domain, client_ip, resolver, budget, sender, depth + 1)

    return SPFResultCode.NEUTRAL


def _qualifier_to_result(qualifier: str) -> SPFResultCode:
    return {
        "+": SPFResultCode.PASS,
        "-": SPFResultCode.FAIL,
        "~": SPFResultCode.SOFTFAIL,
        "?": SPFResultCode.NEUTRAL,
    }[qualifier]


def _resolve_matches(target: str, client_ip: str, resolver: dns.resolver.Resolver, is_ipv6: bool) -> bool:
    rtype = "AAAA" if is_ipv6 else "A"
    try:
        answers = resolver.resolve(target, rtype, lifetime=_RESOLVER_TIMEOUT)
    except dns.exception.DNSException:
        return False
    return any(str(a) == client_ip for a in answers)


def _mx_matches(
    target: str, client_ip: str, resolver: dns.resolver.Resolver, is_ipv6: bool, budget: _LookupBudget
) -> bool:
    try:
        mx_answers = resolver.resolve(target, "MX", lifetime=_RESOLVER_TIMEOUT)
    except dns.exception.DNSException:
        return False
    for mx in mx_answers:
        if not budget.spend():
            return False
        if _resolve_matches(str(mx.exchange).rstrip("."), client_ip, resolver, is_ipv6):
            return True
    return False


def check_spf(
    domain: str,
    client_ip: str,
    resolver: dns.resolver.Resolver | None = None,
    sender: str = "",
) -> SPFResult:
    """
    Evaluate SPF for `domain` with optional sender MAIL FROM address for macro expansion.
    """
    resolver = resolver or dns.resolver.Resolver()
    budget = _LookupBudget()
    try:
        code = _evaluate(domain, client_ip, resolver, budget, sender=sender)
    except dns.exception.DNSException as exc:
        return SPFResult(
            code=SPFResultCode.TEMPERROR,
            domain=domain,
            client_ip=client_ip,
            explanation=f"DNS error during SPF evaluation: {exc}",
            dns_lookups_used=budget.used,
        )
    return SPFResult(
        code=code,
        domain=domain,
        client_ip=client_ip,
        explanation=f"{code.value} for {client_ip} against {domain}'s SPF record",
        dns_lookups_used=budget.used,
    )
