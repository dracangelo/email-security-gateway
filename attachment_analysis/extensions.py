"""
Zero-dependency, free-to-compute extension checks. Not a substitute for
real scanning -- a .pdf can carry an embedded exploit, and a renamed .exe
fools nobody who actually opens it in a scanner -- but extension is still
a meaningful, well-precedented signal on its own.
"""
from __future__ import annotations

# Deliberately conservative: rarely-if-ever legitimate as an unsolicited
# email attachment. .docm/.xlsm (macro-enabled Office) are common in real
# business workflows and would generate too many false positives to
# hard-flag on extension alone -- those are better caught by macro/content
# inspection than a blanket rule here.
_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse",
    ".ws", ".wsf", ".msi", ".msp", ".ps1", ".psm1", ".jar", ".lnk", ".hta", ".chm",
    ".reg", ".dll", ".cpl", ".sys",
}


def _extensions(filename: str) -> list[str]:
    """All dot-suffixes in order, e.g. 'invoice.pdf.exe' -> ['.pdf', '.exe']."""
    name = filename.lower().rsplit("/", 1)[-1]
    parts = name.split(".")
    return [f".{p}" for p in parts[1:]] if len(parts) > 1 else []


def is_dangerous_extension(filename: str) -> bool:
    exts = _extensions(filename)
    return bool(exts) and exts[-1] in _DANGEROUS_EXTENSIONS


def is_double_extension(filename: str) -> bool:
    """
    Flags the classic 'invoice.pdf.exe' pattern: a benign-looking
    extension immediately followed by a dangerous one, banking on a mail
    client or OS file view that truncates or hides the true suffix.
    """
    exts = _extensions(filename)
    if len(exts) < 2:
        return False
    return exts[-1] in _DANGEROUS_EXTENSIONS and exts[-2] not in _DANGEROUS_EXTENSIONS
