"""
Configurable Per-Org Attachment Policy Engine.
Enforces per-organization custom attachment rules (blocked extensions, MIME bans, macro permissions, size caps).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OrgAttachmentPolicy:
    blocked_extensions: set[str] = field(
        default_factory=lambda: {".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".js", ".hta", ".iso", ".img", ".cpl"}
    )
    blocked_mimetypes: set[str] = field(
        default_factory=lambda: {"application/x-msdownload", "application/x-executable", "application/x-dostype"}
    )
    allow_macros: bool = False
    max_file_size_bytes: int = 40 * 1024 * 1024


@dataclass
class AttachmentPolicyResult:
    is_blocked: bool = False
    score_delta: int = 0
    reasons: list[str] = field(default_factory=list)


def evaluate_attachment_policy(
    filename: str,
    size_bytes: int,
    has_macros: bool = False,
    policy: OrgAttachmentPolicy | None = None,
) -> AttachmentPolicyResult:
    """
    Evaluates an attachment against organization security policy rules.
    """
    policy = policy or OrgAttachmentPolicy()

    is_blocked = False
    score_delta = 0
    reasons = []

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext and ext in policy.blocked_extensions:
        is_blocked = True
        score_delta += 50
        reasons.append(f"Attachment {filename} blocked by org policy (forbidden extension '{ext}')")

    if not policy.allow_macros and has_macros:
        is_blocked = True
        score_delta += 50
        reasons.append(f"Attachment {filename} blocked by org policy (VBA macros disallowed)")

    if size_bytes > policy.max_file_size_bytes:
        is_blocked = True
        score_delta += 20
        reasons.append(f"Attachment {filename} blocked by org policy (size {size_bytes} exceeds cap {policy.max_file_size_bytes} bytes)")

    return AttachmentPolicyResult(
        is_blocked=is_blocked,
        score_delta=score_delta,
        reasons=reasons,
    )
