"""
Safe Email Preview Sanitizer Engine.
Strips executable JavaScript, unsafe HTML elements, inline event handlers, and dangerous URL schemes.
"""
from __future__ import annotations

import html
import re


class SafeEmailPreviewRenderer:
    # Dangerous HTML tags to strip completely
    DANGEROUS_TAGS_PATTERN = re.compile(
        r"<\s*(script|iframe|object|embed|applet|form|meta|link|base)[^>]*?>.*?</\s*\1\s*>",
        re.IGNORECASE | re.DOTALL,
    )
    SINGLE_DANGEROUS_TAGS = re.compile(
        r"<\s*(script|iframe|object|embed|applet|form|meta|link|base)[^>]*?>",
        re.IGNORECASE,
    )

    # Inline event handlers (onload, onclick, onerror, etc.)
    EVENT_HANDLER_PATTERN = re.compile(r"\s+on[a-z]+\s*=\s*(?:'[^']*'|\"[^\"]*\"|[^\s>]+)", re.IGNORECASE)

    # Executable or malicious URI schemes
    DANGEROUS_SCHEMES_PATTERN = re.compile(
        r"(href|src|action)\s*=\s*['\"]?\s*(javascript:|data:text/html|vbscript:)[^'\">]*['\"]?",
        re.IGNORECASE,
    )

    @classmethod
    def sanitize_html(cls, html_content: str) -> str:
        """Sanitize raw HTML body for safe display in browser DOM."""
        if not html_content:
            return "<div class='email-preview-empty'><em>[No HTML Content]</em></div>"

        sanitized = cls.DANGEROUS_TAGS_PATTERN.sub("", html_content)
        sanitized = cls.SINGLE_DANGEROUS_TAGS.sub("", sanitized)
        sanitized = cls.EVENT_HANDLER_PATTERN.sub("", sanitized)
        sanitized = cls.DANGEROUS_SCHEMES_PATTERN.sub(r'\1="#"', sanitized)

        return f'<div class="sanitized-email-body">{sanitized}</div>'

    @classmethod
    def render_plain_text(cls, text_content: str) -> str:
        """Safely escape plain text content into HTML."""
        if not text_content:
            return "<div class='email-preview-empty'><em>[No Text Content]</em></div>"

        escaped = html.escape(text_content)
        return f'<pre class="sanitized-text-body" style="white-space: pre-wrap; font-family: monospace;">{escaped}</pre>'
