"""
Magic-bytes verification for detecting file extension spoofing.
Inspects binary file headers to catch executable files renamed with innocent extensions
(e.g., an executable binary renamed to 'invoice.pdf' or 'photo.jpg').
"""
from __future__ import annotations

import os
from typing import NamedTuple

# Common dangerous executable signatures
_MAGIC_SIGNATURES: list[tuple[bytes, str, list[str]]] = [
    (b"MZ", "Windows Executable (PE)", [".exe", ".dll", ".scr", ".pif", ".cpl", ".sys"]),
    (b"\x7fELF", "Linux Executable (ELF)", [".elf", ".bin", ".so", ".out"]),
    (b"\xca\xfe\xba\xbe", "Java/Mach-O Executable", [".class", ".macho"]),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit Executable", [".macho"]),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit Executable", [".macho"]),
    (b"\xce\xfa\xed\xfe", "Mach-O Executable", [".macho"]),
]

_SAFE_SIGNATURES: dict[str, list[bytes]] = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
}


class MagicCheckResult(NamedTuple):
    is_extension_spoofed: bool
    detected_type: str
    reason: str


def verify_file_magic(filename: str, data: bytes) -> MagicCheckResult:
    """
    Verifies that the byte header of `data` matches `filename`'s extension.
    Flags high-risk extension spoofing (e.g. executable header with .pdf/.jpg extension).
    """
    if not data or not filename:
        return MagicCheckResult(is_extension_spoofed=False, detected_type="unknown", reason="")

    _, ext = os.path.splitext(filename.lower())

    # 1. Check if file contains executable magic bytes while using a non-executable extension
    for magic, label, valid_exts in _MAGIC_SIGNATURES:
        if data.startswith(magic):
            if ext not in valid_exts:
                return MagicCheckResult(
                    is_extension_spoofed=True,
                    detected_type=label,
                    reason=f"file '{filename}' has extension '{ext}' but starts with {label} header magic bytes",
                )
            return MagicCheckResult(is_extension_spoofed=False, detected_type=label, reason="")

    # 2. Check if file claims a safe extension (.pdf, .png, etc.) but starts with a different known binary header
    if ext in _SAFE_SIGNATURES:
        expected_magics = _SAFE_SIGNATURES[ext]
        matches = any(data.startswith(m) for m in expected_magics)
        if not matches:
            # Check if it matches ANY OTHER safe binary signature (e.g. JPG pretending to be PDF)
            for other_ext, other_magics in _SAFE_SIGNATURES.items():
                if other_ext != ext and any(data.startswith(m) for m in other_magics):
                    return MagicCheckResult(
                        is_extension_spoofed=True,
                        detected_type=f"mismatched ({other_ext})",
                        reason=f"file '{filename}' claims extension '{ext}' but starts with {other_ext} magic bytes",
                    )

    return MagicCheckResult(is_extension_spoofed=False, detected_type="normal", reason="")

