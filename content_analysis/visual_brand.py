"""
Visual brand-impersonation detection.
Compares page DOM structure and brand markers against known targeted login brands.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

PROTECTED_BRANDS = {
    "microsoft": ["microsoft online", "sign in to your account", "outlook365", "office365"],
    "google": ["sign in - google accounts", "google workspace", "gmail login"],
    "docusign": ["docusign - view document", "sign your document"],
    "paypal": ["log in to your paypal account", "paypal security alert"],
    "apple": ["apple id login", "sign in with apple id"],
}


@dataclass
class VisualBrandFinding:
    is_impersonating: bool = False
    target_brand: str = ""
    score_delta: int = 0
    explanation: str = ""


def check_visual_brand_impersonation(url: str, html: str = "") -> VisualBrandFinding:
    """
    Checks if a target URL or HTML content visual markers match brand login impersonation patterns.
    """
    if not html and not url:
        return VisualBrandFinding()

    content = (html + " " + url).lower()
    url_domain = url.split("/")[2].lower() if "://" in url else url.lower()

    for brand, markers in PROTECTED_BRANDS.items():
        # If domain IS the official brand, it's not impersonation
        if brand in url_domain and any(official in url_domain for official in [f"{brand}.com", f"{brand}.net"]):
            continue

        for marker in markers:
            if marker in content:
                # Flag as brand impersonation if brand marker present on non-official domain
                if brand not in url_domain:
                    return VisualBrandFinding(
                        is_impersonating=True,
                        target_brand=brand.capitalize(),
                        score_delta=30,
                        explanation=f"Visual brand impersonation detected for {brand.capitalize()} on untrusted domain {url_domain}",
                    )

    return VisualBrandFinding()
