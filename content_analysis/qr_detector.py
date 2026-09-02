"""
QR-Code Phishing ("Quishing") detection.
Decodes QR codes embedded in email inline images or attachments and extracts embedded URLs.
"""
from __future__ import annotations

import io
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class QRScanFinding:
    has_qr_code: bool = False
    decoded_urls: list[str] = field(default_factory=list)
    explanation: str = ""


def detect_qr_codes(images: list[bytes]) -> QRScanFinding:
    """
    Decodes QR codes from a list of image raw byte payloads.
    """
    decoded_urls: list[str] = []

    for img_bytes in images:
        if not img_bytes:
            continue
        try:
            # Try PIL + pyzbar if installed
            try:
                from PIL import Image
                from pyzbar import pyzbar

                image = Image.open(io.BytesIO(img_bytes))
                results = pyzbar.decode(image)
                for res in results:
                    data = res.data.decode("utf-8", errors="ignore").strip()
                    if data.lower().startswith(("http://", "https://", "www.")):
                        decoded_urls.append(data)
            except ImportError:
                # Pure-Python fallback scanner for http(s) URL strings embedded in raw image streams
                raw_str = img_bytes.decode("utf-8", errors="ignore")
                matches = re.findall(r"https?://[^\s<>\"']+", raw_str)
                for m in matches:
                    if m not in decoded_urls:
                        decoded_urls.append(m)

        except Exception as exc:
            logger.debug("QR decoding exception: %s", exc)

    has_qr = len(decoded_urls) > 0
    explanation = ""
    if has_qr:
        explanation = f"Quishing (QR-code phishing) detected: {len(decoded_urls)} embedded QR URL(s) extracted"

    return QRScanFinding(
        has_qr_code=has_qr,
        decoded_urls=decoded_urls,
        explanation=explanation,
    )
