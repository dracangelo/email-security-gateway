"""Step 2C orchestrator: hashing + extension heuristics + VT hash lookup + ClamAV + Task 4 analyzers."""
from __future__ import annotations

import hashlib

from .archives import inspect_and_extract_archive
from .document_analysis import inspect_document_attachment
from .document_links import extract_document_urls
from .extensions import is_dangerous_extension, is_double_extension
from .magic_bytes import verify_file_magic
from .models import Attachment, AttachmentFinding, AttachmentVerdict
from .policy import OrgAttachmentPolicy, evaluate_attachment_policy
from .polyglot import detect_polyglot_file
from .reputation import ClamAVScanner, FileReputationProvider, NullFileReputationProvider
from .sandbox import DetonationSandboxClient, SandboxResult


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


async def analyze_attachments(
    attachments: list[Attachment],
    max_attachments: int = 10,
    max_attachment_size_bytes: int = 40 * 1024 * 1024,
    file_reputation_provider: FileReputationProvider | None = None,
    clamav: ClamAVScanner | None = None,
    sandbox_client: DetonationSandboxClient | None = None,
    policy: OrgAttachmentPolicy | None = None,
) -> AttachmentVerdict:
    file_reputation_provider = file_reputation_provider or NullFileReputationProvider()
    clamav = clamav or ClamAVScanner()
    sandbox_client = sandbox_client or DetonationSandboxClient()
    policy = policy or OrgAttachmentPolicy(max_file_size_bytes=max_attachment_size_bytes)

    expanded_attachments: list[Attachment] = []
    archive_reasons: list[str] = []
    archive_score = 0

    for att in attachments:
        expanded_attachments.append(att)
        arc_result = inspect_and_extract_archive(att.filename, att.data)
        if arc_result.is_archive:
            if arc_result.is_encrypted:
                archive_score += 45
                archive_reasons.extend(arc_result.reasons)
            else:
                archive_reasons.extend(arc_result.reasons)
                for child in arc_result.extracted_attachments:
                    expanded_attachments.append(child)

    truncated = len(expanded_attachments) > max_attachments
    work_list = expanded_attachments[:max_attachments]

    findings: list[AttachmentFinding] = []
    score = archive_score
    reasons: list[str] = list(archive_reasons)
    all_extracted_urls: list[str] = []

    if truncated:
        reasons.append(f"message had more than {max_attachments} attachments/archive files; only the first {max_attachments} were analyzed")
        score += 10

    for att in work_list:
        size = len(att.data)
        oversized = size > max_attachment_size_bytes

        finding = AttachmentFinding(filename=att.filename, size_bytes=size, is_oversized=oversized)

        if oversized:
            score += 10
            reasons.append(f"{att.filename} exceeds size limit ({size} bytes) -- not hashed or scanned")
            findings.append(finding)
            continue

        finding.sha256 = _sha256_hex(att.data)
        finding.md5 = _md5_hex(att.data)
        finding.is_dangerous_extension = is_dangerous_extension(att.filename)
        finding.is_double_extension = is_double_extension(att.filename)

        # Magic Bytes Verification
        magic_res = verify_file_magic(att.filename, att.data)
        if magic_res.is_extension_spoofed:
            score += 50
            reasons.append(f"{att.filename} extension spoofing: {magic_res.reason}")

        if finding.is_double_extension:
            score += 40
            reasons.append(f"{att.filename} uses a double extension (extension-hiding pattern)")
        elif finding.is_dangerous_extension:
            score += 25
            reasons.append(f"{att.filename} has a high-risk executable extension")

        # Polyglot File Detection
        polyglot_res = detect_polyglot_file(att.data)
        if polyglot_res.is_polyglot:
            finding.is_polyglot = True
            score += 45
            reasons.append(polyglot_res.explanation)

        # Embedded Document Links Extraction
        doc_link_res = extract_document_urls(att.filename, att.data)
        if doc_link_res.url_count > 0:
            finding.embedded_urls = doc_link_res.extracted_urls
            all_extracted_urls.extend(doc_link_res.extracted_urls)
            score += 10
            reasons.append(doc_link_res.explanation)

        # Office Macro & PDF Structural Inspection
        doc_res = inspect_document_attachment(att.filename, att.data)
        has_macros = doc_res.has_macros
        if doc_res.has_macros:
            score += 45
            reasons.extend(doc_res.reasons)
        elif doc_res.has_pdf_javascript or doc_res.has_pdf_auto_action or doc_res.has_pdf_embedded_files:
            if doc_res.has_pdf_javascript:
                score += 35
            if doc_res.has_pdf_auto_action:
                score += 40
            if doc_res.has_pdf_embedded_files:
                score += 30
            reasons.extend(doc_res.reasons)

        # Per-Org Policy Evaluation
        pol_res = evaluate_attachment_policy(att.filename, size, has_macros=has_macros, policy=policy)
        if pol_res.is_blocked:
            finding.policy_blocked = True
            score += pol_res.score_delta
            reasons.extend(pol_res.reasons)

        # Hash Reputation Check
        verdict, source = await file_reputation_provider.check_hash(finding.sha256)
        finding.file_reputation = verdict
        finding.file_reputation_source = source
        if verdict == "malicious":
            score += 100
            reasons.append(f"{att.filename} (sha256:{finding.sha256[:12]}...) flagged malicious by {source}")
        elif verdict == "suspicious":
            score += 40
            reasons.append(f"{att.filename} flagged suspicious by {source}")

        # ClamAV AV Scanner
        clamav_result = await clamav.scan(att.data)
        finding.clamav_result = clamav_result
        if clamav_result.startswith("infected:"):
            score += 100
            reasons.append(f"{att.filename} flagged by ClamAV: {clamav_result[len('infected:'):]}")
        elif clamav_result.startswith("error:"):
            reasons.append(f"{att.filename} ClamAV scan error (fail-open, not penalized): {clamav_result}")

        # Detonation Sandbox Submission
        if verdict == "unknown" and (finding.is_dangerous_extension or finding.is_polyglot or has_macros):
            sandbox_res = await sandbox_client.submit_sample(att.filename, att.data)
            finding.sandbox_result = sandbox_res
            if sandbox_res.is_submitted and sandbox_res.explanation:
                reasons.append(sandbox_res.explanation)

        findings.append(finding)

    return AttachmentVerdict(
        findings=findings,
        score_delta=score,
        reasons=reasons,
        extracted_embedded_urls=all_extracted_urls,
    )
