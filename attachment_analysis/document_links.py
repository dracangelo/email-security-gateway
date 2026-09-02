"""
Embedded link extraction from document attachments.
Extracts embedded URLs from PDF bodies (/URI actions) and Office OpenXML (.docx, .xlsx, .pptx) relationship streams.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


@dataclass
class DocumentURLExtractionResult:
    extracted_urls: list[str] = field(default_factory=list)
    url_count: int = 0
    explanation: str = ""


def extract_document_urls(filename: str, data: bytes) -> DocumentURLExtractionResult:
    """
    Extracts embedded URLs from document attachment byte streams.
    """
    if not data:
        return DocumentURLExtractionResult()

    fn_lower = filename.lower()
    urls = []

    # 1. PDF URL extraction (/URI (http...))
    if fn_lower.endswith(".pdf") or data.startswith(b"%PDF-"):
        pdf_text = data.decode("latin-1", errors="ignore")
        pdf_uris = re.findall(r"/URI\s*\((https?://[^)]+)\)", pdf_text)
        for u in pdf_uris:
            if u not in urls:
                urls.append(u)

    # 2. Office OpenXML (.docx, .xlsx, .pptx) ZIP rels extraction
    elif any(fn_lower.endswith(ext) for ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm")) or data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for item in zf.namelist():
                    if item.endswith(".rels") or item.endswith(".xml"):
                        xml_content = zf.read(item).decode("utf-8", errors="ignore")
                        xml_urls = re.findall(r'Target="(https?://[^"]+)"', xml_content)
                        for u in xml_urls:
                            if u not in urls:
                                urls.append(u)
        except Exception:
            pass

    # 3. Fallback raw text scan for remaining document formats
    if not urls:
        raw_text = data.decode("utf-8", errors="ignore")
        raw_urls = URL_REGEX.findall(raw_text)
        for u in raw_urls:
            if u not in urls and len(u) < 200:
                urls.append(u)

    has_urls = len(urls) > 0
    explanation = f"Extracted {len(urls)} embedded URL(s) from document attachment {filename}" if has_urls else ""

    return DocumentURLExtractionResult(
        extracted_urls=urls,
        url_count=len(urls),
        explanation=explanation,
    )
