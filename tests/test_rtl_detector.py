"""
Unit tests for RTL override character & filename spoofing detection.
"""
from content_analysis.rtl_detector import detect_rtl_override


def test_rtl_override_clean():
    res = detect_rtl_override("Normal plain text email", filename="document.pdf")
    assert res.has_rtl_override is False
    assert res.is_filename_spoof is False


def test_rtl_override_text():
    # U+202E RIGHT-TO-LEFT OVERRIDE in text
    text_with_rlo = "Special offer \u202esdrawofni"
    res = detect_rtl_override(text_with_rlo)
    assert res.has_rtl_override is True
    assert res.clean_text == "Special offer sdrawofni"


def test_rtl_filename_extension_spoofing():
    # document_pdf\u202eexe.pdf renders as document_pdfpdf.exe
    spoofed_filename = "document_pdf\u202eexe.pdf"
    res = detect_rtl_override("Attachment included", filename=spoofed_filename)
    assert res.has_rtl_override is True
    assert res.is_filename_spoof is True
