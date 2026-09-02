"""
Unit tests for embedded document link extraction.
"""
from attachment_analysis.document_links import extract_document_urls


def test_pdf_embedded_url_extraction():
    pdf_bytes = b"%PDF-1.4 ... /URI (https://phishing-portal.com/auth/login) ... %%EOF"
    res = extract_document_urls("document.pdf", pdf_bytes)
    assert res.url_count == 1
    assert "https://phishing-portal.com/auth/login" in res.extracted_urls


def test_docx_openxml_rels_url_extraction():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships><Relationship Target="https://malicious-domain.xyz/download"/></Relationships>',
        )
    docx_bytes = buf.getvalue()

    res = extract_document_urls("invoice.docx", docx_bytes)
    assert res.url_count == 1
    assert "https://malicious-domain.xyz/download" in res.extracted_urls
