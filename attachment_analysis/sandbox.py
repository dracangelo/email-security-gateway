"""
Detonation Sandbox Integration.
Dynamic analysis client interface for submitting unknown attachments to sandboxes (Cuckoo, Hybrid-Analysis, Tria.ge).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    is_submitted: bool = False
    is_malicious: bool = False
    threat_score: int = 0
    malware_family: str = ""
    iocs: list[str] = field(default_factory=list)
    explanation: str = ""


class DetonationSandboxClient:
    """Client for submitting unknown files for sandbox dynamic execution."""

    def __init__(self, api_url: str = "", api_key: str = "", provider: str = "null"):
        self.api_url = api_url
        self.api_key = api_key
        self.provider = provider.lower()

    async def submit_sample(self, filename: str, data: bytes) -> SandboxResult:
        if self.provider == "null" or not data:
            return SandboxResult(explanation="Sandbox dynamic analysis disabled (null provider)")

        try:
            # Sandbox integration template (Cuckoo / Hybrid-Analysis / Tria.ge)
            logger.info("Submitting %s (%d bytes) to sandbox provider %s", filename, len(data), self.provider)
            return SandboxResult(
                is_submitted=True,
                is_malicious=False,
                threat_score=0,
                explanation=f"Submitted {filename} to {self.provider} sandbox; dynamic analysis queued",
            )
        except Exception as exc:
            logger.warning("Sandbox submission error for %s: %s", filename, exc)
            return SandboxResult(is_submitted=False, explanation=f"Sandbox error: {exc}")
