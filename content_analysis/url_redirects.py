"""
SSRF-Safe URL Redirect Chain Resolver.
Follows HTTP redirects (bit.ly, t.co, etc.) to uncover final destination URLs
while enforcing strict IP validation against loopback, private, and cloud metadata IPs.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse
import httpx


FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private IPv4
    ipaddress.ip_network("172.16.0.0/12"),     # Private IPv4
    ipaddress.ip_network("192.168.0.0/16"),    # Private IPv4
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud metadata (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast/this host
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique local
]


def is_ssrf_safe_ip(ip_str: str) -> bool:
    """Verifies whether an IP address is safe (not private, loopback, or metadata)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in FORBIDDEN_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def is_ssrf_safe_host(hostname: str) -> bool:
    """Resolves hostname to IP addresses and verifies all are SSRF safe."""
    hostname = hostname.lower().strip()
    if hostname in {"localhost", "metadata.google.internal", "169.254.169.254"}:
        return False

    try:
        # Check if direct IP
        return is_ssrf_safe_ip(hostname)
    except ValueError:
        pass

    try:
        addrs = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addrs:
            ip_str = sockaddr[0]
            if not is_ssrf_safe_ip(ip_str):
                return False
        return True
    except socket.gaierror:
        return False


async def resolve_url_redirect_chain(
    initial_url: str,
    max_redirects: int = 5,
    timeout: float = 3.0,
    client: httpx.AsyncClient | None = None
) -> tuple[str, list[str]]:
    """
    Follows HTTP redirect chains for a URL safely.
    Returns (final_url, list_of_intermediate_urls).
    """
    parsed = urlparse(initial_url)
    if parsed.scheme not in {"http", "https"}:
        return initial_url, []

    if not parsed.hostname or not is_ssrf_safe_host(parsed.hostname):
        return initial_url, []

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=False)
        close_client = True

    current_url = initial_url
    hops = []

    try:
        for _ in range(max_redirects):
            parsed_curr = urlparse(current_url)
            if not parsed_curr.hostname or not is_ssrf_safe_host(parsed_curr.hostname):
                break

            try:
                resp = await client.head(current_url)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    resp = await client.get(current_url, headers={"Range": "bytes=0-1024"})
            except httpx.RequestError:
                break

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break

                # Resolve relative redirect URLs
                next_url = httpx.URL(current_url).join(location)
                next_url_str = str(next_url)

                parsed_next = urlparse(next_url_str)
                if not parsed_next.hostname or not is_ssrf_safe_host(parsed_next.hostname):
                    break

                hops.append(current_url)
                current_url = next_url_str
            else:
                break
    finally:
        if close_client:
            await client.aclose()

    return current_url, hops
