"""
Alias module for test_live_tier.py.
"""
from tests.test_live_tier import (
    TestLiveDNSIntegration,
    TestLiveRDAPIntegration,
    TestLiveSMTPE2EPipeline,
)

__all__ = [
    "TestLiveDNSIntegration",
    "TestLiveRDAPIntegration",
    "TestLiveSMTPE2EPipeline",
]
