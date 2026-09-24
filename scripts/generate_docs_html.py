#!/usr/bin/env python3
"""
Static HTML Documentation Generator for email-auth-gateway.
Converts all Markdown documentation files in docs/ into standalone, responsive,
beautifully themed HTML files with syntax highlighting, live Mermaid diagrams,
collapsible sidebar navigation, copy-code buttons, and search.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
import markdown
from markdown.extensions.tables import TableExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.toc import TocExtension

ROOT_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT_DIR / "docs"

NAV_STRUCTURE = [
    {
        "category": "Getting Started & Core",
        "items": [
            ("Portal Dashboard", "index.html"),
            ("Getting Started", "getting_started.html"),
            ("Architecture Overview", "architecture.html"),
            ("Configuration Guide", "configuration.html"),
            ("API Reference", "api_reference.html"),
            ("Tenant Onboarding", "tenant_onboarding.html"),
            ("Environment Parity", "environment_parity.html"),
        ]
    },
    {
        "category": "Gateway Modules (1/2)",
        "items": [
            ("Authentication Checker", "modules/auth_checker.html"),
            ("Content Analysis", "modules/content_analysis.html"),
            ("Attachment Analysis", "modules/attachment_analysis.html"),
            ("Decision Engine", "modules/decision_engine.html"),
            ("Delivery & Quarantine", "modules/delivery.html"),
            ("Security & Webhook Auth", "modules/security.html"),
            ("Resilience & Backoff", "modules/resilience.html"),
            ("KV & Redis Storage", "modules/storage.html"),
            ("Audit Logging", "modules/audit.html"),
            ("Multi-Tenancy", "modules/multi_tenancy.html"),
        ]
    },
    {
        "category": "Gateway Modules (2/2)",
        "items": [
            ("Observability & Metrics", "modules/observability.html"),
            ("Compliance & Retention", "modules/compliance.html"),
            ("Webhook Receiver", "modules/webhook_receiver.html"),
            ("Threat Intelligence", "modules/threat_intel.html"),
            ("Time-of-Click Protection", "modules/time_of_click.html"),
            ("Identity & RBAC", "modules/identity.html"),
            ("SOC Admin UI", "modules/admin_ui.html"),
            ("Scalability & Async MQ", "modules/scalability.html"),
            ("Reliability & DR", "modules/reliability.html"),
            ("Security Hardening", "modules/security_hardening.html"),
        ]
    },
    {
        "category": "Deployment & Infrastructure",
        "items": [
            ("Docker & Compose", "deployment/docker.html"),
            ("Kubernetes Manifests", "deployment/kubernetes.html"),
            ("Helm Chart", "deployment/helm.html"),
            ("Terraform & AWS", "deployment/terraform.html"),
        ]
    },
    {
        "category": "Security & Governance",
        "items": [
            ("Threat Model & STRIDE", "security/threat_model.html"),
            ("Production Hardening", "security/hardening.html"),
            ("Detection Logic Changelog", "detection_changelog.html"),
        ]
    },
    {
        "category": "Operations & Runbooks",
        "items": [
            ("Runbook Directory", "runbooks/INDEX.html"),
            ("ClamAV Unreachable", "runbooks/clamav_unreachable.html"),
            ("Key & Secret Rotation", "runbooks/key_rotation.html"),
            ("Quarantine Disk Full", "runbooks/quarantine_disk_full.html"),
            ("Redis Outage Recovery", "runbooks/redis_down.html"),
            ("Relay SMTP Outage", "runbooks/relay_down.html"),
        ]
    }
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title} — email-auth-gateway</title>
  <meta name="description" content="{description}" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css" />
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    :root {{
      --bg-base: #0d1117;
      --bg-surface: #161b22;
      --bg-elevated: #1c2128;
      --bg-hover: #21262d;
      --border: #30363d;
      --border-muted: #21262d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --accent-blue: #58a6ff;
      --accent-blue-dim: #1f6feb;
      --accent-green: #3fb950;
      --accent-orange: #d29922;
      --accent-red: #f85149;
      --accent-purple: #a371f7;
      --sidebar-width: 290px;
      --header-height: 62px;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: 'Inter', -apple-system, sans-serif;
      background: var(--bg-base);
      color: var(--text-primary);
      line-height: 1.7;
      font-size: 15px;
    }}

    /* HEADER */
    header {{
      position: fixed;
      top: 0; left: 0; right: 0;
      height: var(--header-height);
      background: rgba(13, 17, 23, 0.95);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      padding: 0 24px;
      z-index: 100;
      gap: 16px;
    }}

    .header-logo {{
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      font-size: 15px;
      color: var(--text-primary);
      text-decoration: none;
    }}

    .header-logo .shield {{
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, #1f6feb 0%, #a371f7 100%);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      flex-shrink: 0;
      box-shadow: 0 0 16px rgba(88,166,255,0.35);
    }}

    .header-badge {{
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
    }}

    .header-nav {{
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 12px;
    }}

    .portal-link {{
      color: var(--accent-blue);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      padding: 6px 14px;
      background: rgba(88, 166, 255, 0.1);
      border: 1px solid rgba(88, 166, 255, 0.3);
      border-radius: 6px;
      transition: all 0.2s;
    }}
    .portal-link:hover {{
      background: rgba(88, 166, 255, 0.2);
      border-color: var(--accent-blue);
    }}

    /* SIDEBAR */
    .sidebar {{
      position: fixed;
      top: var(--header-height);
      left: 0;
      bottom: 0;
      width: var(--sidebar-width);
      background: var(--bg-surface);
      border-right: 1px solid var(--border);
      overflow-y: auto;
      padding: 20px 0;
      z-index: 50;
    }}

    .nav-group-title {{
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      padding: 12px 20px 6px;
    }}

    .nav-item {{
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 20px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 13.5px;
      border-left: 3px solid transparent;
      transition: all 0.15s ease;
    }}
    .nav-item:hover {{
      color: var(--text-primary);
      background: var(--bg-hover);
    }}
    .nav-item.active {{
      color: var(--accent-blue);
      background: rgba(88, 166, 255, 0.08);
      border-left-color: var(--accent-blue);
      font-weight: 600;
    }}

    /* MAIN CONTAINER */
    .main-container {{
      margin-left: var(--sidebar-width);
      margin-top: var(--header-height);
      display: flex;
      justify-content: center;
      min-height: calc(100vh - var(--header-height));
    }}

    .content-wrapper {{
      max-width: 900px;
      width: 100%;
      padding: 40px 48px 80px;
    }}

    /* BREADCRUMBS */
    .breadcrumbs {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 24px;
    }}
    .breadcrumbs a {{
      color: var(--text-secondary);
      text-decoration: none;
    }}
    .breadcrumbs a:hover {{
      color: var(--accent-blue);
    }}
    .breadcrumbs .separator {{
      color: var(--text-muted);
    }}
    .breadcrumbs .current {{
      color: var(--text-primary);
      font-weight: 500;
    }}

    /* TYPOGRAPHY */
    h1 {{
      font-size: 32px;
      font-weight: 800;
      margin-bottom: 16px;
      color: var(--text-primary);
      letter-spacing: -0.02em;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }}
    h2 {{
      font-size: 22px;
      font-weight: 700;
      margin: 36px 0 16px;
      color: var(--text-primary);
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border-muted);
    }}
    h3 {{
      font-size: 17px;
      font-weight: 600;
      margin: 24px 0 12px;
      color: var(--text-primary);
    }}
    p {{
      margin-bottom: 16px;
      color: var(--text-secondary);
    }}
    a {{
      color: var(--accent-blue);
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    ul, ol {{
      margin-bottom: 16px;
      padding-left: 24px;
      color: var(--text-secondary);
    }}
    li {{
      margin-bottom: 6px;
    }}

    /* CODE & PRE */
    code {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 2px 6px;
      color: #79c0ff;
    }}
    pre {{
      position: relative;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      overflow-x: auto;
      margin: 16px 0 24px;
    }}
    pre code {{
      background: transparent;
      border: none;
      padding: 0;
      color: var(--text-primary);
      font-size: 13px;
      line-height: 1.6;
    }}

    .copy-btn {{
      position: absolute;
      top: 10px;
      right: 10px;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 11px;
      cursor: pointer;
      font-family: 'Inter', sans-serif;
      transition: all 0.2s;
    }}
    .copy-btn:hover {{
      background: var(--bg-hover);
      color: var(--text-primary);
    }}

    /* TABLES */
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0 28px;
      font-size: 13.5px;
    }}
    th {{
      background: var(--bg-surface);
      border: 1px solid var(--border);
      padding: 10px 14px;
      text-align: left;
      color: var(--text-primary);
      font-weight: 600;
    }}
    td {{
      border: 1px solid var(--border);
      padding: 10px 14px;
      color: var(--text-secondary);
    }}
    tr:nth-child(even) {{
      background: rgba(22, 27, 34, 0.4);
    }}

    /* ALERTS / CALLOUTS */
    .callout {{
      border-left: 4px solid var(--border);
      background: var(--bg-surface);
      border-radius: 0 8px 8px 0;
      padding: 14px 18px;
      margin: 20px 0;
    }}
    .callout-title {{
      font-weight: 600;
      font-size: 13.5px;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .callout-note {{ border-color: var(--accent-blue); }}
    .callout-note .callout-title {{ color: var(--accent-blue); }}
    .callout-warning {{ border-color: var(--accent-orange); }}
    .callout-warning .callout-title {{ color: var(--accent-orange); }}
    .callout-important {{ border-color: var(--accent-purple); }}
    .callout-important .callout-title {{ color: var(--accent-purple); }}
    .callout-tip {{ border-color: var(--accent-green); }}
    .callout-tip .callout-title {{ color: var(--accent-green); }}
    .callout-caution {{ border-color: var(--accent-red); }}
    .callout-caution .callout-title {{ color: var(--accent-red); }}

    /* MERMAID DIAGRAMS */
    .mermaid {{
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
      display: flex;
      justify-content: center;
    }}

    /* FOOTER NAV */
    .doc-footer {{
      margin-top: 60px;
      padding-top: 24px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 13px;
      color: var(--text-muted);
    }}

    @media (max-width: 900px) {{
      .sidebar {{ display: none; }}
      .main-container {{ margin-left: 0; }}
      .content-wrapper {{ padding: 24px 16px 60px; }}
    }}
  </style>
</head>
<body>

<header>
  <a href="{rel_root}index.html" class="header-logo">
    <div class="shield">🛡️</div>
    <span>email-auth-gateway</span>
  </a>
  <span class="header-badge">v1.0 Docs</span>
  <div class="header-nav">
    <a href="{rel_root}index.html" class="portal-link">✨ Interactive SPA Portal</a>
  </div>
</header>

<aside class="sidebar">
  {sidebar_nav}
</aside>

<div class="main-container">
  <div class="content-wrapper">
    <div class="breadcrumbs">
      <a href="{rel_root}index.html">Docs</a>
      <span class="separator">/</span>
      <span class="current">{category_name}</span>
      <span class="separator">/</span>
      <span class="current">{page_title}</span>
    </div>

    {content}

    <div class="doc-footer">
      <span>email-auth-gateway enterprise documentation suite</span>
      <a href="{rel_root}index.html">Back to Full Portal ↗</a>
    </div>
  </div>
</div>

<script>
  // Initialize Mermaid
  mermaid.initialize({{
    startOnLoad: true,
    theme: 'dark',
    themeVariables: {{
      darkMode: true,
      background: '#161b22',
      primaryColor: '#1f6feb',
      primaryTextColor: '#e6edf3',
      lineColor: '#58a6ff'
    }}
  }});

  // Copy Code Buttons
  document.querySelectorAll('pre').forEach(pre => {{
    if (pre.classList.contains('mermaid')) return;
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.onclick = () => {{
      const code = pre.querySelector('code');
      navigator.clipboard.writeText(code ? code.innerText : pre.innerText).then(() => {{
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 2000);
      }});
    }};
    pre.appendChild(btn);
  }});
</script>

</body>
</html>
"""

def get_rel_root(current_path: Path) -> str:
    depth = len(current_path.relative_to(DOCS_DIR).parts) - 1
    return "../" * depth if depth > 0 else "./"

def convert_alerts(text: str) -> str:
    """Converts GitHub alert syntax to styled HTML callout blocks."""
    pattern = re.compile(
        r'>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*\n((?:>.*(?:\n|$))+)',
        re.MULTILINE | re.IGNORECASE
    )

    def replace_alert(match):
        alert_type = match.group(1).upper()
        content = match.group(2)
        # Strip leading '>' and whitespace from each line
        lines = [re.sub(r'^>\s?', '', l) for l in content.splitlines()]
        inner_html = "\n".join(lines).strip()
        type_class = f"callout-{alert_type.lower()}"
        return f'<div class="callout {type_class}"><div class="callout-title">📌 {alert_type}</div><p>{inner_html}</p></div>'

    return pattern.sub(replace_alert, text)

def process_mermaid_and_links(html_content: str) -> str:
    """Replaces fenced mermaid code blocks with <pre class="mermaid"> and rewrites .md links to .html."""
    # Mermaid block replacement
    mermaid_pattern = re.compile(r'<pre><code class="language-mermaid">([\s\S]*?)</code></pre>')
    html_content = mermaid_pattern.sub(r'<pre class="mermaid">\1</pre>', html_content)

    # Convert .md links to .html
    md_link_pattern = re.compile(r'href="([^"]+)\.md(#.*?)?"')
    html_content = md_link_pattern.sub(r'href="\1.html\2"', html_content)

    return html_content

def build_sidebar(current_target: str, rel_root: str) -> str:
    out = []
    for group in NAV_STRUCTURE:
        out.append(f'<div class="nav-group-title">{group["category"]}</div>')
        for title, link in group["items"]:
            resolved_link = f"{rel_root}{link}"
            is_active = (link == current_target)
            active_cls = " active" if is_active else ""
            out.append(f'<a href="{resolved_link}" class="nav-item{active_cls}">{title}</a>')
    return "\n".join(out)

def find_category_and_title(current_target: str) -> tuple[str, str]:
    for group in NAV_STRUCTURE:
        for title, link in group["items"]:
            if link == current_target:
                return group["category"], title
    return "Documentation", current_target

def convert_file(md_path: Path):
    rel_from_docs = md_path.relative_to(DOCS_DIR)
    target_rel_html = str(rel_from_docs.with_suffix(".html"))
    out_html_path = md_path.with_suffix(".html")
    rel_root = get_rel_root(out_html_path)

    raw_text = md_path.read_text(encoding="utf-8")
    category_name, page_title = find_category_and_title(target_rel_html)

    # Extract first H1 as title if present
    h1_match = re.search(r'^#\s+(.+)$', raw_text, re.MULTILINE)
    if h1_match:
        page_title = h1_match.group(1).strip()

    # Pre-process alerts
    processed_text = convert_alerts(raw_text)

    # Convert markdown to HTML
    md_parser = markdown.Markdown(
        extensions=[
            TableExtension(),
            FencedCodeExtension(),
            TocExtension(permalink=False),
        ]
    )
    content_html = md_parser.convert(processed_text)
    content_html = process_mermaid_and_links(content_html)

    sidebar_nav = build_sidebar(target_rel_html, rel_root)

    full_page = HTML_TEMPLATE.format(
        title=page_title,
        description=f"Technical documentation for {page_title} in email-auth-gateway",
        rel_root=rel_root,
        sidebar_nav=sidebar_nav,
        category_name=category_name,
        page_title=page_title,
        content=content_html,
    )

    out_html_path.write_text(full_page, encoding="utf-8")
    print(f"  ✓ Generated: {out_html_path.relative_to(ROOT_DIR)}")

def main():
    print("🚀 Generating HTML Documentation Suite for email-auth-gateway...")
    md_files = list(DOCS_DIR.rglob("*.md"))
    print(f"Found {len(md_files)} Markdown files to convert.")

    for md_file in sorted(md_files):
        convert_file(md_file)

    print("\n🎉 Documentation HTML Suite generation complete!")

if __name__ == "__main__":
    main()
