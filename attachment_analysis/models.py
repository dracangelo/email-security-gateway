"""Result types for Step 2C: attachment scanning."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Attachment:
    filename: str
    data: bytes
    content_type: str = "application/octet-stream"


@dataclass
class AttachmentFinding:
    filename: str
    size_bytes: int
    sha256: str = ""
    md5: str = ""
    is_oversized: bool = False
    is_dangerous_extension: bool = False
    is_double_extension: bool = False
    file_reputation: str = "unknown"        # "malicious" | "suspicious" | "clean" | "unknown"
    file_reputation_source: str = ""
    clamav_result: str = "not_scanned"       # "clean" | "infected:<signature>" | "error:<detail>" | "not_scanned"
    is_polyglot: bool = False
    embedded_urls: list[str] = field(default_factory=list)
    sandbox_result: Any | None = None
    policy_blocked: bool = False


@dataclass
class AttachmentVerdict:
    findings: list[AttachmentFinding] = field(default_factory=list)
    score_delta: int = 0
    reasons: list[str] = field(default_factory=list)
    extracted_embedded_urls: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "findings": [
                {
                    "filename": f.filename,
                    "size_bytes": f.size_bytes,
                    "sha256": f.sha256,
                    "is_oversized": f.is_oversized,
                    "is_dangerous_extension": f.is_dangerous_extension,
                    "is_double_extension": f.is_double_extension,
                    "file_reputation": f.file_reputation,
                    "clamav_result": f.clamav_result,
                    "is_polyglot": f.is_polyglot,
                    "embedded_urls": f.embedded_urls,
                    "policy_blocked": f.policy_blocked,
                }
                for f in self.findings
            ],
            "score_delta": self.score_delta,
            "reasons": self.reasons,
            "extracted_embedded_urls": self.extracted_embedded_urls,
        }
