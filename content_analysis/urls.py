"""
URL extraction and cheap, no-external-dependency heuristics: IP-literal
links and typosquat distance against a watchlist you supply (your own
domain, common vendors/partners -- whatever brands are worth impersonating
in your inbox). Domain age and reputation lookups (which need live network
calls to RDAP/VirusTotal/Safe Browsing) live in `reputation.py`, kept
separate so this module has zero I/O and is trivially unit-testable.
"""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .models import ExtractedURL

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


class _HrefExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value)


def _domain_of(url: str) -> tuple[str, bool]:
    """Returns (domain, is_ip_literal)."""
    try:
        netloc = urlparse(url).netloc
        host = netloc.split("@")[-1].split(":")[0]  # strip userinfo and port
    except ValueError:
        return "", False
    host = host.lower().strip("[]")  # strip IPv6 brackets
    try:
        ipaddress.ip_address(host)
        return host, True
    except ValueError:
        return host, False


def extract_urls(text: str = "", html: str = "") -> list[ExtractedURL]:
    """
    text: plaintext body part, if present.
    html: HTML body part, if present. Both are commonly sent together in a
    multipart/alternative message -- pass whichever you have.
    """
    raw_urls: set[str] = set()
    if text:
        raw_urls.update(_URL_RE.findall(text))
    if html:
        extractor = _HrefExtractor()
        try:
            extractor.feed(html)
        except Exception:
            pass  # malformed HTML -- fall back to whatever plain-text URLs we found
        for href in extractor.hrefs:
            if href.lower().startswith(("http://", "https://")):
                raw_urls.add(href)
        raw_urls.update(_URL_RE.findall(html))

    results = []
    for url in sorted(raw_urls):
        domain, is_ip = _domain_of(url)
        if not domain:
            continue
        results.append(ExtractedURL(raw=url, domain=domain, is_ip_literal=is_ip))
    return results


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


try:
    import publicsuffix2
except ImportError:
    publicsuffix2 = None


def find_typosquat_target(domain: str, watchlist: list[str], max_distance: int = 2) -> str | None:
    """
    Returns the watched brand domain this looks like it's impersonating,
    or None. Exact matches are excluded (that's just... the real domain).
    Distance is computed on the registrable label only (e.g. "paypal" not
    "paypal.com") so TLD swaps (paypal.com vs paypal.net) and subdomain
    padding (paypal.com.verify-login.ru) both still get caught.
    """
    domain = domain.lower()

    if publicsuffix2:
        reg_domain = publicsuffix2.get_public_suffix(domain)
        label = reg_domain.split(".")[0] if "." in reg_domain else domain.split(".")[0]
    else:
        label = domain.split(".")[0] if "." in domain else domain

    for watched in watchlist:
        watched = watched.lower()
        if publicsuffix2:
            watched_reg = publicsuffix2.get_public_suffix(watched)
            watched_label = watched_reg.split(".")[0] if "." in watched_reg else watched.split(".")[0]
        else:
            watched_label = watched.split(".")[0] if "." in watched else watched

        if domain == watched:
            continue  # it's the real thing


        if watched in domain and domain != watched:
            # e.g. "paypal-secure-login.com" or "paypal.com.evil.ru" containing "paypal.com"
            return watched

        if _levenshtein(label, watched_label) <= max_distance and label != watched_label:
            return watched

    return None
