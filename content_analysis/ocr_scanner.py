"""
OCR on embedded images.
Extracts visible text from image-only bodies or image attachments to catch textless screenshot phishing.
"""
from __future__ import annotations

import io
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class OCRFinding:
    has_text: bool = False
    extracted_text: str = ""
    explanation: str = ""


def scan_image_ocr(images: list[bytes]) -> OCRFinding:
    """
    Extracts text from image byte streams.
    """
    extracted_chunks = []

    for img_bytes in images:
        if not img_bytes:
            continue
        try:
            # Tesseract OCR via pytesseract if available
            try:
                import pytesseract
                from PIL import Image

                image = Image.open(io.BytesIO(img_bytes))
                text = pytesseract.image_to_string(image)
                if text.strip():
                    extracted_chunks.append(text.strip())
            except (ImportError, Exception):
                # Fallback text extractor for printable text metadata embedded in image format headers
                txt = "".join(chr(c) for c in img_bytes if 32 <= c <= 126 or c in (10, 13))
                words = [w for w in txt.split() if len(w) > 3 and w.isalpha()]
                if len(words) >= 5:
                    extracted_chunks.append(" ".join(words[:20]))

        except Exception as exc:
            logger.debug("OCR scanner exception: %s", exc)

    full_text = "\n".join(extracted_chunks).strip()
    has_text = len(full_text) > 0
    explanation = f"OCR extracted {len(full_text)} characters of text from image(s)" if has_text else ""

    return OCRFinding(
        has_text=has_text,
        extracted_text=full_text,
        explanation=explanation,
    )
