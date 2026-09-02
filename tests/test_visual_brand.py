"""
Unit tests for visual brand impersonation detection.
"""
from content_analysis.visual_brand import check_visual_brand_impersonation


def test_visual_brand_legitimate():
    res = check_visual_brand_impersonation("https://login.microsoftonline.com/oauth", html="<title>Sign in to your account</title>")
    assert res.is_impersonating is False


def test_visual_brand_impersonation():
    res = check_visual_brand_impersonation("https://login-verify-account.attacker-domain.xyz/auth", html="<h1>Sign in to your account</h1> Microsoft Online")
    assert res.is_impersonating is True
    assert res.target_brand == "Microsoft"
    assert res.score_delta > 0
