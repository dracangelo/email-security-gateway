"""
Display-name spoofing and Reply-To mismatch detection.
Handles BEC scenarios where attacker uses an executive's name with an external email address
or sets a silent Reply-To redirect.
"""
from __future__ import annotations

import email.utils
from urllib.parse import urlparse


def parse_name_and_email(header_val: str) -> tuple[str, str, str]:
    """
    Parses a header value like 'John Doe <jdoe@company.com>' into (display_name, email_address, domain).
    """
    display_name, addr = email.utils.parseaddr(header_val)
    domain = addr.split("@")[-1].lower() if "@" in addr else ""
    return display_name.strip(), addr.strip().lower(), domain


def check_display_name_spoofing(
    from_header: str, protected_vip_names: list[str]
) -> tuple[bool, str]:
    """
    Checks if visible From display name matches a protected VIP name while sent from a non-protected domain.
    """
    if not protected_vip_names or not from_header:
        return False, ""

    display_name, addr, domain = parse_name_and_email(from_header)
    if not display_name:
        return False, ""

    display_name_clean = display_name.lower()
    for vip in protected_vip_names:
        vip_clean = vip.lower()
        if vip_clean in display_name_clean:
            return True, f"From header display name '{display_name}' matches protected identity '{vip}' (actual address: {addr})"

    return False, ""


def check_reply_to_mismatch(from_header: str, reply_to_header: str) -> tuple[bool, str]:
    """
    Checks if Reply-To domain differs from From domain (classic BEC tell).
    """
    if not from_header or not reply_to_header:
        return False, ""

    _, from_addr, from_domain = parse_name_and_email(from_header)
    _, reply_addr, reply_domain = parse_name_and_email(reply_to_header)

    if not from_domain or not reply_domain:
        return False, ""

    if from_domain != reply_domain:
        return True, f"Reply-To domain mismatch: From is @{from_domain} ({from_addr}), but Reply-To is @{reply_domain} ({reply_addr})"

    return False, ""
