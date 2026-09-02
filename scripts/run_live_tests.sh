#!/usr/bin/env bash
set -eo pipefail

echo "========================================================"
echo "    Email Auth Gateway — Live Integration Test Tier     "
echo "========================================================"
echo "[+] Starting live integration tests against live resolvers,"
echo "    local SMTP daemon, and end-to-end webhook pipelines..."
echo ""

export RUN_LIVE_TESTS=1

if [ -f ".venv/bin/pytest" ]; then
    PYTEST_BIN=".venv/bin/pytest"
elif command -v pytest &> /dev/null; then
    PYTEST_BIN="pytest"
else
    echo "[-] pytest not found in environment."
    exit 1
fi

$PYTEST_BIN tests/test_live_suite.py -v --run-live

echo ""
echo "========================================================"
echo "[✓] Live integration test suite passed successfully."
echo "========================================================"
