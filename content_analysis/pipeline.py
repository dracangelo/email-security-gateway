"""Step 2B orchestrator: keyword matching + URL extraction + reputation + Task 3 anti-evasion scanners."""
from __future__ import annotations

import re
from html.parser import HTMLParser

from .display_name import check_display_name_spoofing, check_reply_to_mismatch
from .homoglyphs import detect_homoglyphs_and_idn
from .html_evasion import detect_html_evasion
from .keywords import scan_keywords
from .ml_classifier import predict_phishing_probability
from .models import ContentVerdict, URLFinding
from .multilang_keywords import scan_multilang_keywords
from .ocr_scanner import scan_image_ocr
from .qr_detector import detect_qr_codes
from .relationship_graph import detect_thread_hijacking_and_relationship
from .reputation import DomainAgeProvider, NullReputationProvider, RDAPDomainAgeProvider, URLReputationProvider
from .rtl_detector import detect_rtl_override
from .urls import ExtractedURL, extract_urls, find_typosquat_target
from .visual_brand import check_visual_brand_impersonation

NEWLY_REGISTERED_THRESHOLD_DAYS = 30


class _TextExtractor(HTMLParser):
    """Minimal HTML-to-text so keyword matching sees words, not markup."""

    def __init__(self):
        super().__init__()
        self._chunks: list[str] = []

    def handle_data(self, data):
        self._chunks.append(data)

    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self._chunks)).strip()


def _html_to_text(html: str) -> str:
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
    except Exception:
        return html
    return extractor.text()


async def analyze_content(
    text: str = "",
    html: str = "",
    from_header: str = "",
    reply_to_header: str = "",
    to_header: str = "",
    in_reply_to_header: str = "",
    references_header: str = "",
    attachment_filenames: list[str] | None = None,
    image_payloads: list[bytes] | None = None,
    watchlist: list[str] | None = None,
    vip_display_names: list[str] | None = None,
    domain_age_provider: DomainAgeProvider | None = None,
    reputation_provider: URLReputationProvider | None = None,
) -> ContentVerdict:
    """
    Evaluates text, HTML, headers, attachments, and embedded images against full Task 3 content security rules.
    """
    watchlist = watchlist or []
    vip_display_names = vip_display_names or []
    attachment_filenames = attachment_filenames or []
    image_payloads = image_payloads or []
    domain_age_provider = domain_age_provider or RDAPDomainAgeProvider()
    reputation_provider = reputation_provider or NullReputationProvider()

    plain_text = text or (_html_to_text(html) if html else "")
    matches, keyword_score = scan_keywords(plain_text)

    # Multi-language keywords
    ml_matches, ml_score = scan_multilang_keywords(plain_text)
    matches.extend(ml_matches)
    keyword_score += ml_score

    reasons = [f"keyword match ({m.category}): \u201c{m.phrase}\u201d" for m in matches]
    extra_score = 0

    # Display-Name Spoofing Check
    is_spoofed, spoof_reason = check_display_name_spoofing(from_header, vip_display_names)
    if is_spoofed:
        extra_score += 40
        reasons.append(f"display-name spoofing: {spoof_reason}")

    # Reply-To Mismatch Check
    is_mismatch, mismatch_reason = check_reply_to_mismatch(from_header, reply_to_header)
    if is_mismatch:
        extra_score += 25
        reasons.append(f"reply-to mismatch: {mismatch_reason}")

    # RTL Override & Extension Spoofing Check
    fn_string = " ".join(attachment_filenames)
    rtl_res = detect_rtl_override(plain_text + " " + fn_string, filename=fn_string)
    if rtl_res.has_rtl_override:
        extra_score += 20 if not rtl_res.is_filename_spoof else 45
        reasons.append(rtl_res.explanation)

    # HTML Evasion Check
    html_evasion_res = detect_html_evasion(html)
    if html_evasion_res.has_evasion:
        extra_score += 25
        reasons.append(html_evasion_res.explanation)
        if html_evasion_res.hidden_text:
            h_matches, h_score = scan_keywords(html_evasion_res.hidden_text)
            if h_matches:
                extra_score += h_score + 15
                reasons.append(f"hidden HTML text contains suspicious keyword match")

    # QR Code Quishing Check
    qr_res = detect_qr_codes(image_payloads)
    qr_extracted_urls = []
    if qr_res.has_qr_code:
        extra_score += 30
        reasons.append(qr_res.explanation)
        for raw_u in qr_res.decoded_urls:
            dom = raw_u.split("/")[2] if "://" in raw_u else raw_u
            qr_extracted_urls.append(ExtractedURL(raw=raw_u, domain=dom))

    # OCR Image Scanning Check
    ocr_res = scan_image_ocr(image_payloads)
    if ocr_res.has_text:
        ocr_matches, ocr_k_score = scan_keywords(ocr_res.extracted_text)
        if ocr_matches:
            extra_score += ocr_k_score + 20
            reasons.append(f"OCR extracted suspicious text from image: {ocr_matches[0].phrase}")

    # Sender-Recipient Relationship Graph & Thread-Hijacking BEC Check
    rel_res = detect_thread_hijacking_and_relationship(
        sender=from_header,
        recipient=to_header,
        in_reply_to=in_reply_to_header,
        references=references_header,
        body_text=plain_text,
    )
    if rel_res.score_delta > 0:
        extra_score += rel_res.score_delta
        reasons.append(rel_res.explanation)

    # Homoglyph / Zero-width / Punycode check on body text
    body_hg_findings = detect_homoglyphs_and_idn(plain_text)
    for hg in body_hg_findings:
        if hg.has_zero_width:
            extra_score += 15
            reasons.append("body content contains hidden zero-width unicode characters")
            break

    # URL findings extraction
    urls_to_evaluate = extract_urls(text=text, html=html)
    urls_to_evaluate.extend(qr_extracted_urls)

    url_findings: list[URLFinding] = []
    url_score = 0
    visual_brand_res = None

    for url in urls_to_evaluate:
        finding = URLFinding(url=url)

        if url.is_ip_literal:
            url_score += 15
            reasons.append(f"link uses a raw IP address instead of a domain: {url.raw}")

        url_hg_findings = detect_homoglyphs_and_idn(url.domain)
        for hg in url_hg_findings:
            if hg.is_punycode or hg.has_confusables:
                url_score += 35
                reasons.append(f"URL domain {url.domain} {hg.reason}")
                break

        target = find_typosquat_target(url.domain, watchlist)
        if target:
            finding.is_typosquat_candidate = True
            finding.typosquat_target = target
            url_score += 20
            reasons.append(f"{url.domain} closely resembles watched domain {target}")

        vb_res = check_visual_brand_impersonation(url.raw, html)
        if vb_res.is_impersonating:
            visual_brand_res = vb_res
            url_score += vb_res.score_delta
            reasons.append(vb_res.explanation)

        age_days = await domain_age_provider.get_domain_age_days(url.domain)
        finding.domain_age_days = age_days
        if age_days is not None and age_days < NEWLY_REGISTERED_THRESHOLD_DAYS:
            finding.is_newly_registered = True
            url_score += 15
            reasons.append(f"{url.domain} was registered only {age_days} day(s) ago")

        verdict, source = await reputation_provider.check_url(url.raw)
        finding.reputation = verdict
        finding.reputation_source = source
        if verdict == "malicious":
            url_score += 100
            reasons.append(f"{url.domain} flagged malicious by {source}")
        elif verdict == "suspicious":
            url_score += 40
            reasons.append(f"{url.domain} flagged suspicious by {source}")

        url_findings.append(finding)

    # ML Classifier Evaluation
    ml_res = predict_phishing_probability(
        plain_text,
        url_count=len(urls_to_evaluate),
        is_first_contact=rel_res.is_first_contact_pair,
    )
    if ml_res.score_delta > 0:
        extra_score += ml_res.score_delta
        reasons.append(ml_res.explanation)

    return ContentVerdict(
        keyword_matches=matches,
        url_findings=url_findings,
        score_delta=keyword_score + url_score + extra_score,
        reasons=reasons,
        rtl=rtl_res,
        html_evasion=html_evasion_res,
        quishing=qr_res,
        ocr=ocr_res,
        ml=ml_res,
        visual_brand=visual_brand_res,
        relationship=rel_res,
    )
