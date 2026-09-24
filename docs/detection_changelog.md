# Detection Logic & Scoring Matrix Changelog

This document tracks all changes, tuning iterations, weight calibrations, and architectural rationales for the detection rules in `email-auth-gateway`. 

Maintaining an audit-ready changelog for detection logic is a requirement for SOC 2 Type II (Common Criteria CC7.1, CC7.2), ISO 27001 (Control A.12.6), and GDPR Article 32 compliance, ensuring that rule modifications are deliberate, auditable, and traceable.

---

## Current Composite Scoring Architecture (v1.4.0)

A message's composite risk score is evaluated as:
$$\text{Total Risk Score} = \text{Score}_{\text{Auth}} + \text{Score}_{\text{Content}} + \text{Score}_{\text{Attachment}} + \text{Score}_{\text{Policy}}$$

| Score Range | Action | Pipeline Behavior |
|---|---|---|
| **0 – 29** | `FORWARD` | Relayed as-is to downstream mail server without modification. |
| **30 – 69** | `WARN_AND_STRIP` | Subject tagged `[SUSPICIOUS]`, URLs defanged (`hxxps://`), attachments stripped, and warning banner injected. |
| **70 – 100+** | `QUARANTINE` | Delivery aborted immediately; message encrypted at rest with Fernet key; SecOps notified via webhook. |
| **Single-Signal Override** | `QUARANTINE` | Any verified ClamAV or VirusTotal malware signature assigns `+100` points immediately, bypassing non-malware allowlists. |

---

## Versioned Rule History & Rationale

### Version 1.4.0 (Security Regressions & Evasion Defenses)
*Effective Date: 2026-09-15*

| Rule / Check | Weight Delta | Category | Technical Rationale & Tuning Context |
|---|---|---|---|
| **Quishing (QR Code Phishing)** | `+35` | Attachment / Content | Detects QR codes inside image attachments and PDF payloads that encode phishing login URLs. Mitigates evasion of traditional text-based NLP scanners. |
| **Polyglot File Detection** | `+50` | Attachment | Identifies dual-format files (e.g., GIF89a headers wrapping PHP or JS payloads). Attackers exploit parser differentials where edge firewalls see an image, but endpoints execute code. |
| **Zero-Width Character Keyword Evasion** | `+25` | Content | Strips Unicode zero-width spaces (`\u200B`), soft hyphens (`\u00AD`), and zero-width joiners before running dictionary and urgency keyword matching. Prevents trivial bypass of keyword filters. |
| **Hidden HTML / CSS Text Extraction** | `+25` | Content | Scans for CSS properties hiding adversarial text (`display: none;`, `font-size: 0px;`, `color: transparent;`). Flags deliberate obfuscation attempts. |
| **Double Extension Executable Masking** | `+40` | Attachment | Detects patterns like `invoice.pdf.exe` or Right-to-Left Override (RLO `\u202E`) Unicode characters designed to deceive Windows/macOS file explorers. |

---

### Version 1.3.0 (ARC Protocol & Indirect Mail Flows)
*Effective Date: 2026-07-20*

| Rule / Check | Weight Delta | Category | Technical Rationale & Tuning Context |
|---|---|---|---|
| **Authenticated Received Chain (ARC) Mitigation** | `-20` to `-30` | Auth Checker | Legitimate mailing lists (e.g., Google Groups, listservs) break upstream SPF and DKIM signatures by modifying headers and footers. If a verified ARC seal (`cv=pass`) from a trusted intermediary is present, authentication penalties are mitigated. |
| **DMARC `p=quarantine` Alignment** | `+35` | Auth Checker | Adjusted from `+40` to `+35` to avoid false-positive hard drops when combined with minor body keyword hits on legitimate marketing mail. |
| **MTA-STS Policy Enforcement Failure** | `+20` | Auth Checker | Added check for domains publishing `_mta-sts` TXT records in `enforce` mode where the connecting MTA failed TLS negotiation or valid certificate presentation. |

---

### Version 1.2.0 (Typosquatting & Threat Intelligence Integration)
*Effective Date: 2026-05-10*

| Rule / Check | Weight Delta | Category | Technical Rationale & Tuning Context |
|---|---|---|---|
| **Punycode / Homoglyph Detection** | `+35` | Content | Replaces lookalike Cyrillic/Greek characters (e.g. `а` U+0430 for Latin `a` U+0061) and decodes `xn--` Punycode domains. Deters internationalized domain name (IDN) spoofing attacks. |
| **Newly Registered Domain (NRD) Penalty** | `+30` | Content | Lookups via RDAP: Domains registered < 14 days ago receive `+30`; domains registered < 30 days receive `+15`. Most phishing infrastructure is burned within 72 hours of registration. |
| **VirusTotal High-Confidence Hit** | `+100` | Attachment / URL | Single-signal quarantine trigger. If ≥ 3 antivirus engines on VirusTotal flag a URL or file hash, the message is quarantined unconditionally. |
| **Google Safe Browsing Threat Hit** | `+100` | Content | Single-signal quarantine trigger. URLs listed under `MALWARE`, `SOCIAL_ENGINEERING`, or `UNWANTED_SOFTWARE` immediately trigger quarantine. |

---

### Version 1.1.0 (Executive VIP Impersonation & Multi-Tenancy)
*Effective Date: 2026-03-01*

| Rule / Check | Weight Delta | Category | Technical Rationale & Tuning Context |
|---|---|---|---|
| **VIP Display-Name Spoofing** | `+40` | Decision / Policy | Evaluates Levenshtein distance against configured executive names (e.g., "Jane Doe CEO"). If the display name matches a VIP but originates from a non-company external address, a high penalty is applied. |
| **Forward-Confirmed Reverse DNS (FCrDNS)** | `+15` | Auth Checker | Connect-time IP must resolve via PTR to a hostname that resolves back to the same IP. Reduces low-reputation zombie botnet senders. |
| **Tenant Threshold Customization** | Dynamic | Decision Engine | Enabled per-tenant override of `warn_threshold` and `quarantine_threshold` to accommodate varying risk tolerances between departments or enterprise subsidiaries. |

---

### Version 1.0.0 (Initial Unified Baseline)
*Effective Date: 2026-01-15*

| Rule / Check | Default Weight | Description |
|---|---|---|
| **SPF Hard Fail (`-all`)** | `+30` | Sender IP explicitly unauthorized by sender domain policy. |
| **SPF Soft Fail (`~all`)** | `+15` | Sender IP not authorized, domain in transition. |
| **DKIM Invalid Signature** | `+30` | Cryptographic signature present but failed verification. |
| **DKIM Missing Signature** | `+15` | Message lacks DKIM cryptographic signing. |
| **DMARC Fail under `p=reject`** | `+50` | Domain explicitly requests rejection of unauthenticated mail. |
| **DMARC Fail under `p=quarantine`** | `+35` | Domain requests quarantine of unauthenticated mail. |
| **DMARC Fail under `p=none`** | `+10` | Domain reporting-only; slight indicator of authentication gap. |
| **BEC Urgency & Wire Transfer Keywords** | `+10` to `+30` | Phrases matching financial urgency, gift card requests, payroll account changes. |
| **ClamAV Signature Hit** | `+100` | Local clamd daemon detected known malware payload. |

---

## Rule Governance & Modification Process

To update, tune, or add a scoring rule:

1. **RFC & Threat Analysis**: Submit a pull request modifying the scoring rule in `decision_engine/` or the corresponding analysis stage. Document the rationale, target CVE / attack technique, and expected false-positive rate.
2. **Shadow / Tag-Only Validation**: Deploy to staging or enable shadow evaluation (`ShadowModeEngine`) against a minimum of 10,000 real-world emails to calculate accuracy and false-positive deltas.
3. **Changelog Entry**: Update this file (`docs/detection_changelog.md`) detailing the version, weight delta, and justification.
4. **Security Officer Approval**: The SecOps Lead reviews the changelog entry and metrics before merging to `main`.
