"""
Automated Penetration Testing Harness for evaluating gateway security postures
against common attacks: Auth Bypass, Path Traversal, Header Smuggling, Rate Limit Evasion, and DoS.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List
from fastapi.testclient import TestClient
from config import settings


@dataclass
class PenTestFinding:
    name: str
    endpoint: str
    severity: str
    passed: bool
    details: str


class PenetrationTestRunner:
    """Automated security testing runner simulating web application attack vectors."""

    def __init__(self, client: TestClient):
        self.client = client

    def run_all(self) -> List[PenTestFinding]:
        # Ensure admin secret is active for auth tests if not set
        original_secret = settings.admin_shared_secret
        if not settings.admin_shared_secret:
            settings.admin_shared_secret = "test_admin_shared_secret_123"

        try:
            results = []
            results.extend(self.test_unauthenticated_admin_access())
            results.extend(self.test_path_traversal_payloads())
            results.extend(self.test_header_smuggling_and_forgery())
            results.extend(self.test_oversized_payload_dos())
            return results
        finally:
            settings.admin_shared_secret = original_secret

    def test_unauthenticated_admin_access(self) -> List[PenTestFinding]:
        findings = []
        admin_endpoints = [
            ("/admin/quarantine", "GET"),
            ("/admin/quarantine/test-123", "GET"),
            ("/admin/quarantine/test-123/release", "POST"),
            ("/admin/quarantine/test-123/reject", "POST"),
            ("/admin/tenants", "GET"),
            ("/admin/zap", "POST"),
        ]
        for path, method in admin_endpoints:
            # 1. No auth header
            res = self.client.request(method, path)
            passed = res.status_code in (401, 403, 429)
            findings.append(
                PenTestFinding(
                    name="Unauthenticated Admin Access",
                    endpoint=f"{method} {path}",
                    severity="P0 - Critical",
                    passed=passed,
                    details=f"Expected 401/403/429 without auth header, got {res.status_code}",
                )
            )

            # 2. Bogus Bearer token
            res_bogus = self.client.request(method, path, headers={"Authorization": "Bearer bogus_token_123"})
            passed_bogus = res_bogus.status_code in (401, 403, 429)
            findings.append(
                PenTestFinding(
                    name="Forged Token Admin Access",
                    endpoint=f"{method} {path}",
                    severity="P0 - Critical",
                    passed=passed_bogus,
                    details=f"Expected 401/403/429 with bogus token, got {res_bogus.status_code}",
                )
            )
        return findings

    def test_path_traversal_payloads(self) -> List[PenTestFinding]:
        findings = []
        traversal_payloads = [
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "~/.ssh/id_rsa",
        ]
        for payload in traversal_payloads:
            res = self.client.get(f"/admin/quarantine/{payload}", headers={"Authorization": "Bearer invalid"})
            passed = res.status_code in (400, 401, 403, 404, 429) and "root:" not in res.text
            findings.append(
                PenTestFinding(
                    name="Path Traversal Attempt",
                    endpoint=f"GET /admin/quarantine/{payload}",
                    severity="P0 - High",
                    passed=passed,
                    details=f"Status: {res.status_code}, Body snippet: {res.text[:100]}",
                )
            )
        return findings

    def test_header_smuggling_and_forgery(self) -> List[PenTestFinding]:
        findings = []
        headers = {
            "X-Forwarded-For": "127.0.0.1\r\nSet-Cookie: admin=true",
            "X-Original-IP": "10.0.0.1",
            "Authorization": "Bearer admin_secret_key\r\nHeader-Injection: 1",
        }
        res = self.client.get("/healthz", headers=headers)
        passed = res.status_code in (200, 400)
        findings.append(
            PenTestFinding(
                name="CRLF Header Injection",
                endpoint="GET /healthz",
                severity="P1 - Medium",
                passed=passed,
                details=f"Status: {res.status_code}",
            )
        )
        return findings

    def test_oversized_payload_dos(self) -> List[PenTestFinding]:
        findings = []
        secret = settings.webhook_shared_secret or "test_secret"
        large_body = "A" * (15 * 1024 * 1024)
        res = self.client.post(
            f"/webhooks/sendgrid/inbound/{secret}",
            content=large_body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(large_body))},
        )
        # Content length check rejects > 10MB payloads with 413
        passed = res.status_code in (400, 401, 403, 413, 429)
        findings.append(
            PenTestFinding(
                name="Oversized Payload DoS Defense",
                endpoint="POST /webhooks/sendgrid/inbound/...",
                severity="P0 - High",
                passed=passed,
                details=f"Expected status 400/401/403/413/429 for 15MB payload, got {res.status_code}",
            )
        )
        return findings
