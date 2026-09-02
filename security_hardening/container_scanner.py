"""
Container Image & Infrastructure Security Scanner.
Audits Dockerfiles and container configurations for root user execution, unpinned base images, and insecure configurations.
"""
from __future__ import annotations

import os


class ContainerSecurityScanner:
    """Audits Dockerfile security parameters."""

    def scan_dockerfile(self, dockerfile_path: str) -> list[dict]:
        findings = []
        if not os.path.exists(dockerfile_path):
            return findings

        with open(dockerfile_path, "r") as f:
            lines = f.readlines()

        has_user = False
        has_healthcheck = False

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()

            if line_str.startswith("FROM") and ":latest" in line_str:
                findings.append({
                    "line": idx,
                    "severity": "MEDIUM",
                    "issue": "Base image uses mutable ':latest' tag instead of specific version hash/tag",
                })

            if line_str.startswith("USER") and "root" not in line_str.lower():
                has_user = True

            if line_str.startswith("HEALTHCHECK"):
                has_healthcheck = True

            if any(k in line_str.upper() for k in ["ENV SECRET", "ENV PASSWORD", "ENV API_KEY"]):
                findings.append({
                    "line": idx,
                    "severity": "HIGH",
                    "issue": "Hardcoded secret exposed in Dockerfile ENV instruction",
                })

        if not has_user:
            findings.append({
                "line": 0,
                "severity": "HIGH",
                "issue": "Container runs as root user; missing non-root USER instruction",
            })

        if not has_healthcheck:
            findings.append({
                "line": 0,
                "severity": "LOW",
                "issue": "Missing HEALTHCHECK instruction in Dockerfile",
            })

        return findings
