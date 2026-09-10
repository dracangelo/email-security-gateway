# Module: attachment_analysis — File Scanning

## Purpose

Extracts and inspects all MIME attachments. Runs extension heuristics, SHA-256/MD5 hash reputation via VirusTotal, live malware scanning via ClamAV, archive bomb detection, magic-byte type verification, polyglot detection, and document macro/link analysis.

---

## Module Structure

| File | Responsibility |
|---|---|
| `pipeline.py` | Orchestrator; entry point `analyze_attachments()` |
| `extract.py` | MIME tree traversal; attachment extraction |
| `extensions.py` | Dangerous and double-extension heuristics |
| `magic_bytes.py` | File type verification via magic bytes vs declared extension |
| `reputation.py` | VirusTotal hash lookup + ClamAV live scan |
| `archives.py` | ZIP/RAR/7z recursion with depth/count limits |
| `document_analysis.py` | Office macro detection, embedded OLE objects |
| `document_links.py` | URL extraction from PDF / Office documents |
| `polyglot.py` | Polyglot file detection (valid as multiple types) |
| `sandbox.py` | Pluggable detonation sandbox integration |
| `policy.py` | Configurable per-extension allow/deny policy |
| `models.py` | Pydantic data models |

---

## Entry Point

```python
from attachment_analysis import (
    extract_attachments,
    analyze_attachments,
    ClamAVScanner,
    VirusTotalFileProvider,
)

attachments = extract_attachments(raw_message_bytes)

verdict = await analyze_attachments(
    attachments,
    max_attachments=10,
    max_attachment_size_bytes=40 * 1024 * 1024,
    file_reputation_provider=VirusTotalFileProvider(api_key="..."),
    clamav=ClamAVScanner(host="localhost", port=3310),
)

print(verdict.score_delta)
print(verdict.malicious_filenames)
```

---

## Extraction (`extract.py`)

Walks the MIME tree recursively, collecting all leaf parts that are not the message body. Returns a list of `Attachment` objects:

```python
@dataclass
class Attachment:
    filename: str | None
    content_type: str
    data: bytes
    sha256: str
    md5: str
```

---

## Extension Heuristics (`extensions.py`)

### Dangerous Extensions

Flags attachments with high-risk extensions:

```
.exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .jse, .wsf, .hta,
.scr, .pif, .com, .msi, .jar, .lnk, .reg, .inf
```

Score delta: +30 to +50 depending on extension risk tier.

### Double Extensions

Detects disguised executables using double extensions:

```
invoice.pdf.exe  →  flagged as dangerous
report.docx.zip  →  flagged (archive hiding executable)
```

Score delta: +20.

---

## Magic Byte Verification (`magic_bytes.py`)

Compares actual file type (detected from leading bytes) against the declared extension and MIME type. A PDF that starts with `MZ` (PE executable header) is immediately flagged.

Score delta: +50.

---

## Archive Analysis (`archives.py`)

Recursively decompresses ZIP, RAR, and 7z archives:

- **Max depth**: 3 levels (prevents recursive archive bombs)
- **Max extracted files**: 10 per archive
- **Decompressed size limit**: Detects zip bombs (ratio > 100:1)

Each extracted file is passed through the same extension, magic-byte, and reputation checks.

---

## File Reputation (`reputation.py`)

### VirusTotal Hash Lookup

Queries VirusTotal's file hash endpoint with the attachment's SHA-256. Returns detection ratio across all AV engines.

- 1+ detections → score delta +100 (triggers automatic quarantine)
- Circuit breaker protects against VT outages
- Retry with exponential backoff

### ClamAV Live Scan

Streams the attachment to the `clamd` TCP daemon for real-time scanning. Implemented in a thread (not blocking the event loop).

**Fail-open behavior**: If `clamd` is unreachable, the scan result is treated as `unknown` — a ClamAV outage does not cause every message with attachments to be flagged. The circuit breaker opens after 5 consecutive failures and resets after 30 seconds.

---

## Document Analysis (`document_analysis.py`)

For Office (`.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`) documents:
- Detects VBA macros (`.doc`/`.xls` legacy formats)
- Detects XML macros in OOXML containers
- Extracts embedded OLE objects

For PDFs:
- Detects embedded JavaScript
- Detects embedded executables or archives

Score delta: +20 to +40.

---

## Polyglot Detection (`polyglot.py`)

Checks whether a file is simultaneously valid as two different file types (e.g., a file that is both a valid PDF and a valid ZIP). Polyglot files are frequently used in sandbox evasion.

Score delta: +30.

---

## Data Models

```python
@dataclass
class AttachmentVerdict:
    score_delta: int
    reasons: list[str]
    malicious_filenames: list[str]
    scanned_count: int
    skipped_count: int
    clamav_available: bool

@dataclass
class Attachment:
    filename: str | None
    content_type: str
    data: bytes
    sha256: str
    md5: str
```

---

## Known Limitations

- **ClamAV fails open**: A downed ClamAV does not block mail. Monitoring the `AntivirusCircuitBreakerOpen` alert is important.
- **Archive recursion is capped**: Deeply nested legitimate archives may not be fully scanned.
- **Sandbox integration** (`sandbox.py`) is a stub — full detonation sandbox integration (Cuckoo, FireEye, etc.) requires a running sandbox environment and is not wired up by default.
