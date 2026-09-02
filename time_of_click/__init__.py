"""
Time-of-Click (ToC) URL Protection module.
"""
from .rewriter import rewrite_urls_in_html, rewrite_urls_in_text
from .service import TimeOfClickService

__all__ = ["rewrite_urls_in_html", "rewrite_urls_in_text", "TimeOfClickService"]
