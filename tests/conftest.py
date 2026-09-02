"""
Pytest global configuration and fixtures.
Provides custom command-line options and test tiering logic.
"""
import os
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run live integration tests against live DNS, RDAP, and network endpoints",
    )


def pytest_collection_modifyitems(config, items):
    run_live_flag = config.getoption("--run-live")
    run_live_env = os.environ.get("RUN_LIVE_TESTS", "").lower() in ("1", "true", "yes")
    
    if not (run_live_flag or run_live_env):
        skip_live = pytest.mark.skip(
            reason="Live integration test skipped by default. Run with '--run-live' or RUN_LIVE_TESTS=1 to execute."
        )
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)
