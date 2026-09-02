import pytest
from fastapi.testclient import TestClient
from security.pen_tester import PenetrationTestRunner
from webhook_receiver import app


def test_penetration_test_suite():
    client = TestClient(app)
    runner = PenetrationTestRunner(client)

    findings = runner.run_all()
    assert len(findings) > 0

    failed_findings = [f for f in findings if not f.passed]
    assert len(failed_findings) == 0, f"Penetration testing detected vulnerabilities: {failed_findings}"
