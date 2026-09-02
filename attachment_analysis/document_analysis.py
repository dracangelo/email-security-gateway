"""
Static Analysis for Office Macros & PDF Structural Threats.
Detects VBA macro streams in Office documents and active code/auto-execution triggers in PDFs.
"""
from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field


@dataclass
class DocumentInspectionResult:
    has_macros: bool = False
    has_pdf_javascript: bool = False
    has_pdf_auto_action: bool = False
    has_pdf_embedded_files: bool = False
    reasons: list[str] = field(default_factory=list)


def inspect_document_attachment(filename: str, data: bytes) -> DocumentInspectionResult:
    ext = os.path.splitext(filename)[1].lower()
    result = DocumentInspectionResult()

    # 1. Office Open XML macro inspection (.docm, .xlsm, .pptm, .docx, .xlsx)
    if ext in {".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".zip"}:
        _inspect_office_zip(filename, data, result)

    # 2. Legacy binary Office macro inspection (.doc, .xls, .ppt)
    elif ext in {".doc", ".xls", ".ppt"}:
        _inspect_office_binary(filename, data, result)

    # 3. PDF structural inspection (.pdf)
    elif ext == ".pdf" or data.startswith(b"%PDF-"):
        _inspect_pdf_structure(filename, data, result)

    return result


def _inspect_office_zip(filename: str, data: bytes, result: DocumentInspectionResult) -> None:
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [name.lower() for name in zf.namelist()]
            for name in names:
                if "vbaproject.bin" in name or "vba/" in name:
                    result.has_macros = True
                    result.reasons.append(f"Office document '{filename}' contains embedded VBA macro project ({name})")
                    break

            # Search extracted xml files for auto-exec keywords if macros present
            if result.has_macros:
                for name in zf.namelist():
                    if name.endswith(".xml") or name.endswith(".bin"):
                        try:
                            content = zf.read(name)
                            if re.search(rb"(?i)(AutoOpen|Workbook_Open|Document_Open|Shell|PowerShell|cmd\.exe)", content):
                                result.reasons.append(f"Office document '{filename}' contains auto-executing macro routines")
                                break
                        except Exception:
                            continue
    except zipfile.BadZipFile:
        pass


def _inspect_office_binary(filename: str, data: bytes, result: DocumentInspectionResult) -> None:
    # Scan raw binary stream for ole / vba signatures
    if b"vbaProject.bin" in data or b"VBA" in data or b"_VBA_PROJECT" in data:
        result.has_macros = True
        result.reasons.append(f"Legacy Office document '{filename}' contains embedded VBA macros")

    if re.search(rb"(?i)(AutoOpen|Workbook_Open|Document_Open|WScript\.Shell)", data):
        if not result.has_macros:
            result.has_macros = True
        result.reasons.append(f"Legacy Office document '{filename}' contains suspicious auto-executing script strings")


def _inspect_pdf_structure(filename: str, data: bytes, result: DocumentInspectionResult) -> None:
    if re.search(rb"(?i)/JavaScript|/JS\b", data):
        result.has_pdf_javascript = True
        result.reasons.append(f"PDF document '{filename}' contains embedded JavaScript code (/JavaScript or /JS object)")

    if re.search(rb"(?i)/OpenAction|/AA\b", data):
        result.has_pdf_auto_action = True
        result.reasons.append(f"PDF document '{filename}' contains auto-execution triggers (/OpenAction or /AA)")

    if re.search(rb"(?i)/EmbeddedFiles\b|/Launch\b", data):
        result.has_pdf_embedded_files = True
        result.reasons.append(f"PDF document '{filename}' contains embedded file payload (/EmbeddedFiles or /Launch)")
