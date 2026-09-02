"""
Archive extraction and recursive scanning for attachment analysis.
Extracts contents of zip/tar archives up to max depth and detects password-protected
archives (a common AV-evasion technique).
"""
from __future__ import annotations

import io
import os
import tarfile
import zipfile
from typing import NamedTuple

from .models import Attachment

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".tar.gz"}


class ArchiveInspectionResult(NamedTuple):
    is_archive: bool
    is_encrypted: bool
    extracted_attachments: list[Attachment]
    reasons: list[str]


def inspect_and_extract_archive(
    filename: str,
    data: bytes,
    max_files: int = 10,
    max_depth: int = 3,
    current_depth: int = 1,
) -> ArchiveInspectionResult:
    """
    Inspects archive files (.zip, .tar, .gz), extracts nested files for analysis,
    and flags encrypted / password-protected archives.
    """
    reasons: list[str] = []
    extracted: list[Attachment] = []

    ext = os.path.splitext(filename.lower())[1]
    if ext not in ARCHIVE_EXTENSIONS and not filename.lower().endswith(".tar.gz"):
        return ArchiveInspectionResult(is_archive=False, is_encrypted=False, extracted_attachments=[], reasons=[])

    if current_depth > max_depth:
        reasons.append(f"archive '{filename}' exceeded max nesting depth limit ({max_depth})")
        return ArchiveInspectionResult(is_archive=True, is_encrypted=False, extracted_attachments=[], reasons=reasons)

    # 1. Handle ZIP archives
    if ext == ".zip" or data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                count = 0
                for zinfo in zf.infolist():
                    if zinfo.is_dir():
                        continue
                    if zinfo.flag_bits & 0x1:
                        reasons.append(f"archive '{filename}' is password-protected / encrypted (AV evasion risk)")
                        return ArchiveInspectionResult(is_archive=True, is_encrypted=True, extracted_attachments=[], reasons=reasons)
                    if count >= max_files:
                        reasons.append(f"archive '{filename}' contained more than {max_files} files; remaining ignored")
                        break
                    try:
                        file_data = zf.read(zinfo.filename)
                        child_name = os.path.basename(zinfo.filename) or zinfo.filename
                        extracted.append(Attachment(filename=child_name, data=file_data, content_type="application/octet-stream"))
                        count += 1
                    except RuntimeError as exc:
                        reasons.append(f"archive '{filename}' is password-protected ({exc})")
                        return ArchiveInspectionResult(is_archive=True, is_encrypted=True, extracted_attachments=[], reasons=reasons)


        except zipfile.BadZipFile:
            reasons.append(f"archive '{filename}' is a corrupted or malformed Zip file")
            return ArchiveInspectionResult(is_archive=True, is_encrypted=False, extracted_attachments=[], reasons=reasons)

    # 2. Handle TAR archives
    elif ext in {".tar", ".gz", ".tgz"} or filename.lower().endswith(".tar.gz") or data.startswith(b"\x1f\x8b"):
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                count = 0
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    if count >= max_files:
                        reasons.append(f"archive '{filename}' contained more than {max_files} files; remaining ignored")
                        break
                    f = tf.extractfile(member)
                    if f:
                        file_data = f.read()
                        child_name = os.path.basename(member.name) or member.name
                        extracted.append(Attachment(filename=child_name, data=file_data, content_type="application/octet-stream"))

                        count += 1
        except Exception:
            reasons.append(f"archive '{filename}' tar extraction failed or is malformed")

    return ArchiveInspectionResult(
        is_archive=True,
        is_encrypted=False,
        extracted_attachments=extracted,
        reasons=reasons,
    )
