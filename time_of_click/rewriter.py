"""
Time-of-Click URL rewriter.
Rewrites URLs in email bodies to route through the gateway redirect endpoint with HMAC verification signatures.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

import re
import urllib.parse
from typing import Tuple


def generate_url_signature(target_url: str, secret_key: str) -> str:
    """Generates an HMAC-SHA256 signature for a target URL."""
    sig = hmac.new(secret_key.encode("utf-8"), target_url.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig[:16]


def create_toc_url(target_url: str, gateway_base_url: str, secret_key: str) -> str:
    """Constructs signed Time-of-Click redirect URL."""
    sig = generate_url_signature(target_url, secret_key)
    encoded_target = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8")
    base = gateway_base_url.rstrip("/")
    return f"{base}/toc/redirect?url={encoded_target}&sig={sig}"


def rewrite_urls_in_html(html_content: str, gateway_base_url: str, secret_key: str) -> Tuple[str, int]:
    """Rewrites href attributes in HTML content to point to gateway Time-of-Click endpoint."""
    if not html_content or not secret_key or not gateway_base_url:
        return html_content, 0

    count = 0
    pattern = re.compile(r'(<a\s+[^>]*href=["\'])(https?://[^"\']+)(["\'][^>]*>)', re.IGNORECASE)

    def replace_href(match):
        nonlocal count
        prefix = match.group(1)
        url = match.group(2)
        suffix = match.group(3)
        if "/toc/redirect" in url:
            return match.group(0)
        count += 1
        new_url = create_toc_url(url, gateway_base_url, secret_key)
        return f"{prefix}{new_url}{suffix}"

    rewritten_html = pattern.sub(replace_href, html_content)
    return rewritten_html, count


def rewrite_urls_in_text(text_content: str, gateway_base_url: str, secret_key: str) -> Tuple[str, int]:
    """Rewrites plain text URLs to point to gateway Time-of-Click endpoint."""
    if not text_content or not secret_key or not gateway_base_url:
        return text_content, 0

    import re
    url_pattern = re.compile(r"https?://[^\s<>\"']+")
    count = 0

    def replace_url(match):
        nonlocal count
        url = match.group(0)
        if "/toc/redirect" in url:
            return url
        count += 1
        return create_toc_url(url, gateway_base_url, secret_key)

    rewritten_text = url_pattern.sub(replace_url, text_content)
    return rewritten_text, count
