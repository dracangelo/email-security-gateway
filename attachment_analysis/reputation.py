"""
File reputation by hash (VirusTotal) and live signature scanning
(ClamAV). Same pluggable-interface pattern as content_analysis/reputation.py:
default to something that works with zero external dependencies, let a
real deployment swap in the real thing.

VirusTotal calls go through retry-with-backoff and a shared circuit
breaker (module-level, so all instances of this provider in one process
track the same "is VT down" state) -- same reasoning as content_analysis's
URL reputation provider.
"""
from __future__ import annotations

import asyncio
import io
from abc import ABC, abstractmethod

import httpx

from resilience.circuit_breaker import CircuitBreaker, CircuitOpenError
from resilience.retry import RetryExhausted, with_retry


class FileReputationProvider(ABC):
    @abstractmethod
    async def check_hash(self, sha256: str) -> tuple[str, str]:
        """Returns (verdict, source): 'malicious' | 'suspicious' | 'clean' | 'unknown'."""


class NullFileReputationProvider(FileReputationProvider):
    async def check_hash(self, sha256: str) -> tuple[str, str]:
        return "unknown", "no file reputation provider configured"


_vt_file_breaker = CircuitBreaker("virustotal_file", failure_threshold=5, reset_timeout=30.0)


class VirusTotalFileProvider(FileReputationProvider):
    """Requires a VirusTotal API key. Docs: https://docs.virustotal.com/reference/file-info"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, client: httpx.AsyncClient | None = None, timeout: float = 8.0,
                 max_attempts: int = 3, backoff_base: float = 0.25):
        self.api_key = api_key
        self._client = client
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    async def check_hash(self, sha256: str) -> tuple[str, str]:
        if not self.api_key:
            return "unknown", "virustotal (no API key configured)"

        @with_retry(max_attempts=self._max_attempts, base_delay=self._backoff_base, retry_on=(httpx.RequestError,))
        async def _fetch() -> httpx.Response:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            owns_client = self._client is None
            try:
                return await client.get(f"{self.BASE_URL}/files/{sha256}", headers={"x-apikey": self.api_key})
            finally:
                if owns_client:
                    await client.aclose()

        try:
            resp = await _vt_file_breaker.call(_fetch)
        except CircuitOpenError:
            return "unknown", "virustotal (circuit open -- too many recent failures, skipping call)"
        except RetryExhausted:
            return "unknown", "virustotal (lookup error after retries)"

        if resp.status_code == 404:
            return "unknown", "virustotal (hash not seen before -- not necessarily safe, just unknown)"
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


class ClamAVScanner:
    """
    Wraps the `clamd` package against a running clamd daemon (the
    `clamav/clamav` Docker image exposes the TCP socket this expects).
    Disabled entirely (returns 'not_scanned') unless a host is configured --
    this is a live-signature scanner, not a hosted API, so it needs actual
    infrastructure running next to the gateway.

    clamd's INSTREAM protocol is synchronous/blocking; runs in a thread via
    asyncio.to_thread so it doesn't block the event loop handling other
    inbound requests while a large attachment streams through the scanner.

    Fails OPEN on scan errors (connection refused, protocol error, clamd
    down): returns "error:<detail>" rather than raising, and the caller
    treats that as "not penalized" -- a broken antivirus daemon shouldn't
    make the whole gateway start quarantining everything. This is a
    deliberate tradeoff, not an oversight: alert on clamd being down
    separately (e.g. via the readiness check), don't let its downtime
    silently become a blanket "flag everything" or "flag nothing" policy
    baked into message scoring.
    """

    def __init__(self, host: str = "", port: int = 3310, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def enabled(self) -> bool:
        return bool(self.host)

    def _scan_sync(self, data: bytes) -> str:
        import clamd

        client = clamd.ClamdNetworkSocket(host=self.host, port=self.port, timeout=self.timeout)
        result = client.instream(io.BytesIO(data))
        status, signature = result.get("stream", ("ERROR", "no result"))
        if status == "OK":
            return "clean"
        if status == "FOUND":
            return f"infected:{signature}"
        return f"error:{signature}"

    async def scan(self, data: bytes) -> str:
        if not self.enabled():
            return "not_scanned"
        try:
            return await asyncio.to_thread(self._scan_sync, data)
        except Exception as exc:  # connection issues, protocol errors, daemon down, etc.
            return f"error:{exc}"
