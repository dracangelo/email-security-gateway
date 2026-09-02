import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from content_analysis.keywords import scan_keywords
from content_analysis.urls import extract_urls, find_typosquat_target


class TestKeywords:
    def test_urgency_match(self):
        matches, score = scan_keywords("Your account will be suspended within 24 hours, act now.")
        categories = {m.category for m in matches}
        assert "urgency" in categories
        assert score > 0

    def test_no_false_positive_on_clean_text(self):
        matches, score = scan_keywords("Hey, lunch tomorrow at noon? Let me know.")
        assert matches == []
        assert score == 0

    def test_duplicate_phrase_counted_once(self):
        text = "act now. act now. act now."
        matches, score = scan_keywords(text)
        urgency_matches = [m for m in matches if "act" in m.phrase.lower()]
        assert len(urgency_matches) == 1  # dedup per-pattern, not per-occurrence

    def test_gift_card_bec_pattern(self):
        matches, score = scan_keywords("This is confidential, please buy gift cards and don't tell anyone.")
        categories = {m.category for m in matches}
        assert "financial" in categories


class TestURLExtraction:
    def test_plaintext_url(self):
        urls = extract_urls(text="Click here: https://example.com/reset?token=abc")
        assert len(urls) == 1
        assert urls[0].domain == "example.com"
        assert urls[0].is_ip_literal is False

    def test_html_href(self):
        html = '<a href="https://phish.example/login">Sign in</a>'
        urls = extract_urls(html=html)
        assert len(urls) == 1
        assert urls[0].domain == "phish.example"

    def test_ip_literal_flagged(self):
        urls = extract_urls(text="http://198.51.100.20/wp-login.php")
        assert len(urls) == 1
        assert urls[0].is_ip_literal is True

    def test_dedup_across_text_and_html(self):
        text = "https://example.com/a"
        html = '<a href="https://example.com/a">link</a>'
        urls = extract_urls(text=text, html=html)
        assert len(urls) == 1

    def test_malformed_html_does_not_crash(self):
        urls = extract_urls(html="<a href='https://example.com'>unclosed")
        assert len(urls) == 1


class TestTyposquat:
    def test_exact_match_is_not_flagged(self):
        assert find_typosquat_target("paypal.com", ["paypal.com"]) is None

    def test_close_edit_distance_flagged(self):
        target = find_typosquat_target("paypa1.com", ["paypal.com"])
        assert target == "paypal.com"

    def test_subdomain_padding_flagged(self):
        target = find_typosquat_target("paypal.com.verify-account.ru", ["paypal.com"])
        assert target == "paypal.com"

    def test_unrelated_domain_not_flagged(self):
        assert find_typosquat_target("wikipedia.org", ["paypal.com", "chase.com"]) is None
