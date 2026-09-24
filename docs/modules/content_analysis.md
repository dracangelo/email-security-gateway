# Module: content_analysis — Content & URL Analysis

## Purpose

Detects phishing, Business Email Compromise (BEC), and social engineering signals in email body and headers. Covers keyword matching, URL extraction and reputation, typosquatting, homoglyph detection, display-name spoofing, HTML evasion, QR code decoding, OCR on image-only bodies, multi-language detection, and RTL character abuse.

---

## Module Structure

| File | Responsibility |
|---|---|
| `pipeline.py` | Orchestrator; entry point `analyze_content()` |
| `keywords.py` | BEC/urgency keyword and phrase matching |
| `multilang_keywords.py` | Multi-language keyword support |
| `urls.py` | URL extraction from text + HTML |
| `reputation.py` | Domain/URL reputation via VirusTotal or Google Safe Browsing |
| `caching.py` | TTL cache wrapper for reputation + domain-age providers |
| `homoglyphs.py` | Unicode homoglyph and IDN punycode lookalike detection |
| `display_name.py` | Display-name spoofing detection against VIP list |
| `html_evasion.py` | CSS-hidden text, split-tag content, excessive nesting detection |
| `ocr_scanner.py` | OCR on inline image attachments (Tesseract) |
| `qr_detector.py` | QR code detection and URL decode from images |
| `rtl_detector.py` | RTL override Unicode character detection |
| `url_redirects.py` | URL redirect chain resolution (SSRF-safe) |
| `ml_classifier.py` | ML-based phishing classifier (pluggable) |
| `visual_brand.py` | Visual brand impersonation detection |
| `relationship_graph.py` | Sender–recipient communication history graph |
| `models.py` | Pydantic data models for content analysis results |

---

## Entry Point

```python
from content_analysis import analyze_content

verdict = await analyze_content(
    text=text_body,
    html=html_body,
    from_header="CEO Name <ceo-fake@gmail.com>",
    reply_to_header="reply@attacker.com",
    watchlist=["paypal.com", "apple.com"],
    vip_display_names=["Jane Doe CEO", "John Smith CFO"],
    domain_age_provider=domain_age_provider,
    reputation_provider=url_reputation_provider,
)

print(verdict.score_delta)
print(verdict.reasons)
```

---

## Checks

### Keyword / BEC Matching

Matches urgency phrases and Business Email Compromise patterns in the message body. Examples:

```
"wire transfer", "urgent payment", "account suspended within 24 hours",
"click here to verify", "your account will be terminated"
```

Score delta: `+5` per low-confidence phrase up to `+30` for explicit BEC patterns.

### Multi-Language Content Analysis (`multilang_keywords.py`)

The scanner automatically identifies the message language using Unicode script detection (Hiragana/Katakana for Japanese, Cyrillic for Russian, CJK ideographs for Chinese) and stopword frequency scoring for Latin-script languages.

| Language | Code | Scanned Attack Vectors |
|---|---|---|
| **English** | `en` | Wire transfer, payroll redirection, credential expiration, invoice fraud |
| **German** | `de` | `dringende zahlung`, `rechnung überfällig`, `überweisung ausstehend`, `bankverbindung geändert` |
| **French** | `fr` | `paiement urgent`, `facture impayée`, `virement en attente`, `changement de coordonnées bancaires` |
| **Spanish** | `es` | `pago urgente`, `factura vencida`, `transferencia pendiente`, `cambio de cuenta bancaria` |
| **Italian** | `it` | `pagamento urgente`, `fattura scaduta`, `bonifico in sospeso`, `modifica coordinate bancarie` |
| **Portuguese** | `pt` | `pagamento urgente`, `fatura vencida`, `transferência pendente`, `alteração de dados bancários` |
| **Dutch** | `nl` | `dringende betaling`, `factuur achterstallig`, `openstaande rekening`, `wijziging bankgegevens` |
| **Japanese** | `ja` | `至急の支払い`, `請求書の未払い`, `振込のお願い`, `アカウントの停止`, `振込先変更` |
| **Russian** | `ru` | `срочная оплата`, `просроченный счет`, `изменение банковских реквизитов`, `учетная запись заблокирована` |
| **Chinese** | `zh` | `紧急付款`, `逾期账单`, `银行账户变更`, `账号已被冻结`, `请协助保密` |

**Unicode & Diacritic Resilience**: All incoming text undergoes Unicode NFKC normalization and diacritic stripping (`unicodedata.normalize('NFKD')`), ensuring keywords match even when accents or umlauts are stripped by attackers to evade filters (e.g. `überweisung` matches `uberweisung`, `impayée` matches `impayee`).

### URL Extraction + Typosquat Detection

1. Extracts all URLs from both plain-text and HTML bodies (with HTML entities decoded).
2. Computes Levenshtein edit distance from each domain to all domains in your watchlist.
3. Distance ≤ 2 → typosquat signal (+20 to +35 depending on distance and brand sensitivity).
4. Punycode (`xn--`) domains are decoded and checked for homoglyph similarity.

### Homoglyph / IDN Detection

Normalizes Unicode characters to detect Cyrillic/Latin look-alike substitution:

- `аpple.com` (Cyrillic `а`) vs `apple.com` (Latin `a`)
- `gооgle.com` (Cyrillic `о`) vs `google.com`

Implemented in `homoglyphs.py` using Unicode confusable data. Score delta: +30 to +50.

### Display Name Spoofing

Checks the `From:` display name against the `VIP_DISPLAY_NAMES` list. If the display name matches a VIP but the email address is not from a trusted domain, this is flagged as a BEC/impersonation attempt.

```
"CEO Name <random123@gmail.com>" → matches VIP "CEO Name" → +40
```

### HTML Evasion

Detects common HTML obfuscation techniques used to hide content from text-based scanners:

- `display: none` / `visibility: hidden` CSS styling
- Zero or near-zero font sizes
- Content split across excessive nested `<span>` / `<div>` tags
- White text on white background

When detected, the hidden text is extracted and added to the keyword scan.

### QR Code Decoding ("Quishing")

Detects QR codes embedded in images (inline attachments or `<img>` tags). Decoded URLs are fed through the same URL analysis pipeline. This addresses a growing class of attacks that specifically use QR codes to bypass text/link scanning.

### OCR on Image-Only Bodies

Uses Tesseract OCR to extract text from image-only email bodies (a screenshot of a fake login page, for example). Extracted text is fed into keyword matching. Score delta depends on keyword hit strength.

### URL Redirect Chain Resolution

Resolves URL shorteners and multi-hop redirects to their final destination before reputation checking. The resolver is SSRF-safe:
- Blocks redirects to RFC 1918 / loopback / link-local IP ranges
- Enforces a hop limit (default 5 hops)
- Enforces a per-redirect timeout

### RTL Override Character Detection

Detects Unicode Right-to-Left Override (U+202E) and related characters used to visually disguise filenames or URLs (e.g., making `evil.exe` appear as `exe.evil` in display).

---

## Reputation Providers

Pluggable via dependency injection:

| Provider | Class | Notes |
|---|---|---|
| VirusTotal | `VirusTotalProvider` | Primary; requires `VT_API_KEY` |
| Google Safe Browsing | `GoogleSafeBrowsingProvider` | Fallback; requires `GSB_API_KEY` |
| No-op | `NullReputationProvider` | Used when no API key is configured |
| Cached | `CachedReputationProvider` | Wraps any provider with TTL caching |

Domain age is queried via RDAP (`rdap.org` redirector by default):

| Provider | Class | Notes |
|---|---|---|
| RDAP | `RDAPDomainAgeProvider` | Newly registered domains (< 30 days) flagged |
| Cached | `CachedDomainAgeProvider` | TTL: 6 hours (RDAP data changes slowly) |

---

## Data Models

```python
@dataclass
class ContentVerdict:
    score_delta: int
    reasons: list[str]
    extracted_urls: list[str]
    flagged_urls: list[str]
    keyword_matches: list[str]
    homoglyph_domains: list[str]
    display_name_spoof: bool
    html_evasion_detected: bool
    qr_urls: list[str]
    ocr_text: str | None
```

---

## Known Limitations

- **URL extraction is regex-based**, not a full HTML parser — handles common `<a href="...">` correctly but may miss links constructed via JavaScript or unusual markup.
- **Keyword list is curated**, not ML-based. False negatives on novel phishing language. Use `ml_classifier.py` for additional coverage.
- **RDAP coverage varies by TLD**; the free `rdap.org` redirector rate-limits under load.
- **OCR accuracy** depends on image quality and Tesseract language packs installed.
