"""
Domain age + URL reputation lookups, behind small interfaces so you can
swap providers without touching the pipeline. All real providers here need
network egress and (for VT/Safe Browsing) an API key -- neither is
available in this build sandbox, so these are written correctly against
each API's documented contract but only exercised in tests via mocked
HTTP transports, not live calls (aside from RDAP, which was exercised
against the real rdap.org during development). Test against the real APIs
before trusting this in production.

Everything is async because a message can carry several URLs and you don't
want to check them one at a time, serially, on your hot path.

Each provider wraps its HTTP call in retry-with-backoff plus a shared,
module-level circuit breaker (one breaker per provider CLASS, not per
instance -- "is VirusTotal down" is a fact about the upstream service, not
about which particular provider object happens to be asking). The public
per-call contract stays the same as before: these methods never raise:
retry exhaustion and an open circuit both degrade to the same "unknown"
result a plain HTTP error would have produced, they just get there with
fewer wasted round-trips against an upstream that's already struggling.
"""
from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx

from resilience.circuit_breaker import CircuitBreaker, CircuitOpenError
from resilience.retry import RetryExhausted, with_retry


class DomainAgeProvider(ABC):
    @abstractmethod
    async def get_domain_age_days(self, domain: str) -> int | None:
        """Returns days since registration, or None if unknown/lookup failed."""


_rdap_breaker = CircuitBreaker("rdap", failure_threshold=5, reset_timeout=30.0)


class RDAPDomainAgeProvider(DomainAgeProvider):
    """
    Uses rdap.org as an RDAP bootstrap redirector, which forwards to the
    correct registry/registrar RDAP server per RFC 9224/9082. No API key
    needed, but rate limits and coverage vary a lot by TLD -- treat a
    None result as "unknown", not "old domain, all clear".
    """

    def __init__(self, client: httpx.AsyncClient | None = None, timeout: float = 5.0,
                 max_attempts: int = 3, backoff_base: float = 0.25):
        self._client = client
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    async def get_domain_age_days(self, domain: str) -> int | None:
        @with_retry(max_attempts=self._max_attempts, base_delay=self._backoff_base, retry_on=(httpx.RequestError,))
        async def _fetch() -> httpx.Response:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            owns_client = self._client is None
            try:
                return await client.get(f"https://rdap.org/domain/{domain}")
            finally:
                if owns_client:
                    await client.aclose()

        try:
            resp = await _rdap_breaker.call(_fetch)
        except (CircuitOpenError, RetryExhausted):
            return None

        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    registered = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    return max(0, (datetime.now(timezone.utc) - registered).days)
            return None
        except (ValueError, KeyError, TypeError):
            return None


class URLReputationProvider(ABC):
    @abstractmethod
    async def check_url(self, url: str) -> tuple[str, str]:
        """Returns (verdict, source) where verdict is one of
        'malicious' | 'suspicious' | 'clean' | 'unknown'."""


class NullReputationProvider(URLReputationProvider):
    """Default no-op provider so the pipeline runs with zero external dependencies."""

    async def check_url(self, url: str) -> tuple[str, str]:
        return "unknown", "no reputation provider configured"


_vt_url_breaker = CircuitBreaker("virustotal_url", failure_threshold=5, reset_timeout=30.0)


class VirusTotalProvider(URLReputationProvider):
    """Requires a VirusTotal API key (env var VT_API_KEY or pass explicitly).
    Docs: https://docs.virustotal.com/reference/url-info"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None, client: httpx.AsyncClient | None = None, timeout: float = 8.0,
                 max_attempts: int = 3, backoff_base: float = 0.25):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self._client = client
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    async def check_url(self, url: str) -> tuple[str, str]:
        if not self.api_key:
            return "unknown", "virustotal (no API key configured)"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        @with_retry(max_attempts=self._max_attempts, base_delay=self._backoff_base, retry_on=(httpx.RequestError,))
        async def _fetch() -> httpx.Response:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            owns_client = self._client is None
            try:
                return await client.get(f"{self.BASE_URL}/urls/{url_id}", headers={"x-apikey": self.api_key})
            finally:
                if owns_client:
                    await client.aclose()

        try:
            resp = await _vt_url_breaker.call(_fetch)
        except CircuitOpenError:
            return "unknown", "virustotal (circuit open -- too many recent failures, skipping call)"
        except RetryExhausted:
            return "unknown", "virustotal (lookup error after retries)"

        if resp.status_code == 404:
            return "unknown", "virustotal (not yet analyzed -- consider submitting it)"
        if resp.status_code != 200:
            return "unknown", f"virustotal (http {resp.status_code})"
        try:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        except (ValueError, KeyError):
            return "unknown", "virustotal (unexpected response shape)"
        if stats.get("malicious", 0) > 0:
            return "malicious", "virustotal"
        if stats.get("suspicious", 0) > 0:
            return "suspicious", "virustotal"
        return "clean", "virustotal"


_gsb_breaker = CircuitBreaker("safe_browsing", failure_threshold=5, reset_timeout=30.0)


class GoogleSafeBrowsingProvider(URLReputationProvider):
    """Requires a Safe Browsing API key (env var GSB_API_KEY or pass explicitly).
    Docs: https://developers.google.com/safe-browsing/v4/lookup-api"""

    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str | None = None, client: httpx.AsyncClient | None = None, timeout: float = 8.0,
                 max_attempts: int = 3, backoff_base: float = 0.25):
        self.api_key = api_key or os.environ.get("GSB_API_KEY", "")
        self._client = client
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    async def check_url(self, url: str) -> tuple[str, str]:
        if not self.api_key:
            return "unknown", "safe_browsing (no API key configured)"
        payload = {
            "client": {"clientId": "email-auth-gateway", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        @with_retry(max_attempts=self._max_attempts, base_delay=self._backoff_base, retry_on=(httpx.RequestError,))
        async def _fetch() -> httpx.Response:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            owns_client = self._client is None
            try:
                return await client.post(f"{self.BASE_URL}?key={self.api_key}", json=payload)
            finally:
                if owns_client:
                    await client.aclose()

        try:
            resp = await _gsb_breaker.call(_fetch)
        except CircuitOpenError:
            return "unknown", "safe_browsing (circuit open -- too many recent failures, skipping call)"
        except RetryExhausted:
            return "unknown", "safe_browsing (lookup error after retries)"

        if resp.status_code != 200:
            return "unknown", f"safe_browsing (http {resp.status_code})"
        try:
            return ("malicious", "safe_browsing") if resp.json().get("matches") else ("clean", "safe_browsing")
        except ValueError:
            return "unknown", "safe_browsing (unexpected response shape)"
