#!/usr/bin/env bash
set -eo pipefail

echo "========================================================"
echo "      Email Auth Gateway — Security Scanning Suite      "
echo "========================================================"

FAILED=0

# 1. Bandit SAST Scanning
echo "[+] Running Bandit SAST scan on Python codebase..."
if command -v bandit &> /dev/null; then
    bandit -r auth_checker content_analysis attachment_analysis decision_engine delivery security storage audit config webhook_receiver admin_ui identity observability scalability threat_intel multi_tenancy reliability time_of_click -ll || FAILED=1
else
    echo "[-] Bandit not installed in environment. Install with 'pip install bandit'."
fi

echo ""

# 2. Pip-Audit Dependency Scanning
echo "[+] Running pip-audit dependency vulnerability check..."
if command -v pip-audit &> /dev/null; then
    pip-audit --desc || FAILED=1
else
    echo "[-] pip-audit not installed in environment. Install with 'pip install pip-audit'."
fi

echo ""

# 3. Trivy Container / Filesystem Security Scanning
echo "[+] Running Trivy security scan..."
if command -v trivy &> /dev/null; then
    trivy fs --severity HIGH,CRITICAL . || FAILED=1
else
    echo "[-] Trivy not installed locally. Skipping Trivy CLI check."
fi

echo "========================================================"
if [ $FAILED -eq 0 ]; then
    echo "[✓] Security scanning completed successfully."
    exit 0
else
    echo "[!] Security scanning detected vulnerabilities or warnings."
    exit $FAILED
fi
