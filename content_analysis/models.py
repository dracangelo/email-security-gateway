"""Result types for Step 2B: content and URL analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KeywordMatch:
    phrase: str
    category: str          # "urgency", "financial", "credential_harvest", etc.


@dataclass
class ExtractedURL:
    raw: str
    domain: str
    is_ip_literal: bool = False   # link is a bare IP address instead of a domain -- red flag on its own


@dataclass
class URLFinding:
    url: ExtractedURL
    domain_age_days: int | None = None       # None = lookup failed or was skipped
    is_newly_registered: bool = False        # domain_age_days < threshold
    reputation: str = "unknown"              # "malicious" | "suspicious" | "clean" | "unknown"
    reputation_source: str = ""
    is_typosquat_candidate: bool = False
    typosquat_target: str = ""               # which watched brand it resembles, if any


@dataclass
class ContentVerdict:
    keyword_matches: list[KeywordMatch] = field(default_factory=list)
    url_findings: list[URLFinding] = field(default_factory=list)
    score_delta: int = 0
    reasons: list[str] = field(default_factory=list)
    rtl: Any | None = None
    html_evasion: Any | None = None
    quishing: Any | None = None
    ocr: Any | None = None
    ml: Any | None = None
    visual_brand: Any | None = None
    relationship: Any | None = None

    def as_dict(self) -> dict:
        data = {
            "keyword_matches": [{"phrase": m.phrase, "category": m.category} for m in self.keyword_matches],
            "url_findings": [
                {
                    "url": f.url.raw,
                    "domain": f.url.domain,
                    "domain_age_days": f.domain_age_days,
                    "is_newly_registered": f.is_newly_registered,
                    "reputation": f.reputation,
                    "is_typosquat_candidate": f.is_typosquat_candidate,
                    "typosquat_target": f.typosquat_target,
                }
                for f in self.url_findings
            ],
            "score_delta": self.score_delta,
            "reasons": self.reasons,
        }
        if self.rtl:
            data["rtl"] = {"has_rtl_override": getattr(self.rtl, "has_rtl_override", False), "is_filename_spoof": getattr(self.rtl, "is_filename_spoof", False)}
        if self.html_evasion:
            data["html_evasion"] = {"has_evasion": getattr(self.html_evasion, "has_evasion", False), "techniques": getattr(self.html_evasion, "evasion_techniques", [])}
        if self.quishing:
            data["quishing"] = {"has_qr_code": getattr(self.quishing, "has_qr_code", False), "urls": getattr(self.quishing, "decoded_urls", [])}
        if self.ocr:
            data["ocr"] = {"has_text": getattr(self.ocr, "has_text", False)}
        if self.ml:
            data["ml"] = {"phishing_probability": getattr(self.ml, "phishing_probability", 0.0), "is_phishing": getattr(self.ml, "is_phishing", False)}
        if self.visual_brand:
            data["visual_brand"] = {"is_impersonating": getattr(self.visual_brand, "is_impersonating", False), "brand": getattr(self.visual_brand, "target_brand", "")}
        if self.relationship:
            data["relationship"] = {"is_thread_hijack": getattr(self.relationship, "is_thread_hijack", False)}
        return data
