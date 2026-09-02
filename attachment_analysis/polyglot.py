"""
Polyglot file detection.
Identifies files that simultaneously contain valid magic headers for multiple file formats (e.g. GIF+ZIP, PDF+ZIP, PNG+EXE).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PolyglotResult:
    is_polyglot: bool = False
    detected_formats: list[str] = field(default_factory=list)
    explanation: str = ""


FORMAT_SIGNATURES = {
    "GIF": [b"GIF89a", b"GIF87a"],
    "ZIP": [b"PK\x03\x04"],
    "PDF": [b"%PDF-"],
    "PNG": [b"\x89PNG\r\n\x1a\n"],
    "EXE": [b"MZ"],
    "JAVA": [b"\xca\xfe\xba\xbe"],
    "RAR": [b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
}


def detect_polyglot_file(data: bytes) -> PolyglotResult:
    """
    Scans binary data to identify polyglot files containing conflicting format signatures.
    """
    if not data or len(data) < 10:
        return PolyglotResult()

    detected = []

    for fmt, sigs in FORMAT_SIGNATURES.items():
        for sig in sigs:
            if sig in data:
                if fmt not in detected:
                    detected.append(fmt)
                break

    # If file contains more than 1 primary conflicting binary format signature
    is_polyglot = len(detected) > 1

    # Filter out normal expected combinations (e.g. JAR is valid ZIP, Office OpenXML is valid ZIP)
    if "ZIP" in detected and len(detected) == 2 and any(f in detected for f in ("JAR", "DOCX", "XLSX")):
        is_polyglot = False

    explanation = ""
    if is_polyglot:
        explanation = f"Polyglot file evasion detected: file contains signatures for {', '.join(detected)}"

    return PolyglotResult(
        is_polyglot=is_polyglot,
        detected_formats=detected,
        explanation=explanation,
    )
