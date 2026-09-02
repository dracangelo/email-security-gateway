"""
HTML evasion handling.
Detects CSS-hidden text (display:none, font-size:0, visibility:hidden, off-screen absolute positioning)
used by attackers to fool text/keyword filters while displaying different text to human readers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass
class HTMLEvasionFinding:
    has_evasion: bool = False
    hidden_text: str = ""
    visible_text: str = ""
    evasion_techniques: list[str] = field(default_factory=list)
    explanation: str = ""


class _HTMLEvasionParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.visible_chunks: list[str] = []
        self.hidden_chunks: list[str] = []
        self.techniques: set[str] = set()

        self._style_stack: list[dict[str, str]] = []
        self._tag_stack: list[str] = []

    def _parse_style(self, style_attr: str) -> dict[str, str]:
        styles = {}
        for rule in style_attr.split(";"):
            if ":" in rule:
                k, v = rule.split(":", 1)
                styles[k.strip().lower()] = v.strip().lower()
        return styles

    def _is_hidden(self, styles: dict[str, str]) -> tuple[bool, str]:
        if styles.get("display") in ("none", "inline-none"):
            return True, "display:none"
        if styles.get("visibility") == "hidden":
            return True, "visibility:hidden"
        if styles.get("font-size") in ("0", "0px", "0pt", "0em"):
            return True, "font-size:0"
        if styles.get("opacity") in ("0", "0.0"):
            return True, "opacity:0"
        if "left:-" in styles.get("left", "") or "top:-999" in styles.get("top", ""):
            return True, "off-screen positioning"
        if styles.get("color") == "transparent":
            return True, "color:transparent"
        if styles.get("color") and styles.get("color") == styles.get("background-color"):
            return True, "color matching background"
        return False, ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = dict(attrs)
        style_str = attr_dict.get("style", "")
        styles = self._parse_style(style_str)

        self._tag_stack.append(tag)
        self._style_stack.append(styles)

    def handle_endtag(self, tag: str):
        if self._tag_stack:
            self._tag_stack.pop()
        if self._style_stack:
            self._style_stack.pop()

    def handle_data(self, data: str):
        if not data.strip():
            return

        is_currently_hidden = False
        technique_found = ""

        # Check stack for inherited hidden status
        for styles in reversed(self._style_stack):
            hidden, tech = self._is_hidden(styles)
            if hidden:
                is_currently_hidden = True
                technique_found = tech
                break

        if is_currently_hidden:
            self.hidden_chunks.append(data.strip())
            if technique_found:
                self.techniques.add(technique_found)
        else:
            self.visible_chunks.append(data.strip())


def detect_html_evasion(html: str) -> HTMLEvasionFinding:
    """
    Analyzes HTML structure and CSS styling for hidden text evasion techniques.
    """
    if not html or "<" not in html:
        return HTMLEvasionFinding()

    parser = _HTMLEvasionParser()
    try:
        parser.feed(html)
    except Exception:
        return HTMLEvasionFinding()

    hidden_text = " ".join(parser.hidden_chunks).strip()
    visible_text = " ".join(parser.visible_chunks).strip()
    techniques = sorted(list(parser.techniques))
    has_evasion = bool(hidden_text and techniques)

    explanation = ""
    if has_evasion:
        explanation = f"HTML CSS evasion detected using {', '.join(techniques)} ({len(hidden_text)} chars hidden text)"

    return HTMLEvasionFinding(
        has_evasion=has_evasion,
        hidden_text=hidden_text,
        visible_text=visible_text,
        evasion_techniques=techniques,
        explanation=explanation,
    )
