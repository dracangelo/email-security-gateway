"""
Modifies a message for the warn_and_strip action: adds a visible warning
to the subject, neuters links (removes the actual href so they're not
clickable, replaces the visible text with a defanged, clearly-marked
version for anyone investigating), and strips attachments (replaced with
a text note listing what was removed).

Operates on bytes in, bytes out -- keeps this module usable regardless of
what parsed the message elsewhere in the pipeline.
"""
from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

DEFAULT_SUBJECT_PREFIX = "[SUSPICIOUS] "

_HREF_RE = re.compile(r'href\s*=\s*(["\'])(.*?)\1', re.IGNORECASE)
_PLAIN_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


def _defang(url: str) -> str:
    """https://paypal.com/login -> hxxps[://]paypal[.]com/login -- readable
    for investigation, not clickable, not auto-linkified by mail clients
    that re-render plain text."""
    defanged = url.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    return defanged.replace(".", "[.]")


def defang_html_links(html: str) -> str:
    """
    Replaces every <a href="..."> with href="#" and prepends the visible
    link text with a bracketed, defanged marker showing what the link
    used to point to -- so an investigator can still see the original
    target without it being clickable or auto-parsed as a live URL.
    """

    def _replace_href(match: re.Match) -> str:
        quote, url = match.group(1), match.group(2)
        if not url.lower().startswith(("http://", "https://")):
            return match.group(0)  # leave mailto:, anchors, etc. alone
        return f'href={quote}#{quote} data-original-link-removed="{_defang(url)}"'

    out = _HREF_RE.sub(_replace_href, html)
    return out


def defang_text_links(text: str) -> str:
    """Same idea for plain-text bodies: rewrites bare URLs to a defanged, non-clickable form."""
    return _PLAIN_URL_RE.sub(lambda m: f"[LINK REMOVED: {_defang(m.group(0))}]", text)


def add_subject_warning(msg: EmailMessage, prefix: str = DEFAULT_SUBJECT_PREFIX) -> None:
    subject = msg.get("Subject", "")
    if subject.startswith(prefix):
        return  # don't double-prefix on reprocessing
    del msg["Subject"]
    msg["Subject"] = f"{prefix}{subject}".rstrip() if not subject else f"{prefix}{subject}"


def strip_attachments(msg: EmailMessage) -> list[str]:
    """
    Removes every attachment part in place, returns the list of filenames
    that were removed. Uses EmailMessage's modern API (iter_attachments /
    get_body) rather than a manual walk -- it correctly distinguishes
    "this is a displayable body part" from "this is an attachment" even
    for messages with unusual MIME structure (inline images, nested
    multipart/related inside multipart/mixed, etc.) in a way a naive
    is_multipart() walk over legacy Message objects doesn't reliably.
    """
    removed: list[str] = []
    if not msg.is_multipart():
        return removed

    for part in list(msg.iter_attachments()):
        filename = part.get_filename() or "unnamed-attachment"
        removed.append(filename)
        # set_content() (rather than poking _payload/set_payload directly)
        # correctly resets Content-Transfer-Encoding along with the body --
        # leaving the original part's encoding (e.g. base64, chosen for
        # binary content) in place while swapping in plain text made the
        # replacement note itself get base64-encoded into unreadable
        # garbage. del + set_content is what actually clears it.
        del part["Content-Disposition"]
        del part["Content-Transfer-Encoding"]
        part.set_content(f"[Attachment removed by security gateway: {filename}]")

    return removed


def apply_warn_and_strip(raw_message: bytes, subject_prefix: str = DEFAULT_SUBJECT_PREFIX) -> tuple[bytes, list[str]]:
    """
    The full warn_and_strip transform: parse, prefix subject, defang
    every HTML/text body part's links, strip attachments, re-serialize.
    Returns (modified_bytes, removed_attachment_filenames).
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    except Exception:
        # Malformed message -- can't safely modify it. Returning the
        # original bytes unchanged here would silently skip the warning
        # this function exists to add, so the caller should treat a
        # parse failure as its own signal (e.g. escalate to quarantine)
        # rather than relay something we couldn't even parse.
        raise

    add_subject_warning(msg, subject_prefix)
    removed = strip_attachments(msg)

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                html = part.get_content()
                part.set_content(defang_html_links(html), subtype="html")
            elif content_type == "text/plain":
                text = part.get_content()
                part.set_content(defang_text_links(text))
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            msg.set_content(defang_html_links(msg.get_content()), subtype="html")
        elif content_type == "text/plain":
            msg.set_content(defang_text_links(msg.get_content()))

    return msg.as_bytes(), removed


def apply_tag_only(raw_message: bytes, score: int, action: str, reasons: list[str]) -> bytes:
    """
    Tag-only mode transform: parses message, inserts X-Gateway-Verdict headers
    detailing the score, decision action, and reasons, without modifying body or attachments.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    except Exception:
        return raw_message

    if "X-Gateway-Verdict" in msg:
        del msg["X-Gateway-Verdict"]
    if "X-Gateway-Score" in msg:
        del msg["X-Gateway-Score"]

    msg["X-Gateway-Verdict"] = action
    msg["X-Gateway-Score"] = str(score)
    reasons_clean = "; ".join(reasons[:5])
    msg["X-Gateway-Reasons"] = reasons_clean[:250]

    return msg.as_bytes()

