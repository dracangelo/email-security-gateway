import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from content_analysis.models import ContentVerdict
from content_analysis.pipeline import analyze_content
from content_analysis.reputation import DomainAgeProvider, URLReputationProvider


class FakeDomainAgeProvider(DomainAgeProvider):
    def __init__(self, ages: dict[str, int | None]):
        self.ages = ages

    async def get_domain_age_days(self, domain: str) -> int | None:
        return self.ages.get(domain)


class FakeReputationProvider(URLReputationProvider):
    def __init__(self, verdicts: dict[str, str]):
        self.verdicts = verdicts

    async def check_url(self, url: str) -> tuple[str, str]:
        return self.verdicts.get(url, "unknown"), "fake_provider"


def _run(coro):
    return asyncio.run(coro)


class TestContentPipeline:
    def test_clean_message_scores_zero(self):
        result: ContentVerdict = _run(
            analyze_content(
                text="Hey, are we still on for lunch tomorrow?",
                domain_age_provider=FakeDomainAgeProvider({}),
                reputation_provider=FakeReputationProvider({}),
            )
        )
        assert result.score_delta == 0
        assert result.keyword_matches == []
        assert result.url_findings == []

    def test_malicious_url_dominates_score(self):
        result = _run(
            analyze_content(
                text="Please review: https://bad.example/invoice.pdf",
                domain_age_provider=FakeDomainAgeProvider({"bad.example": 3000}),
                reputation_provider=FakeReputationProvider({"https://bad.example/invoice.pdf": "malicious"}),
            )
        )
        assert result.score_delta >= 100
        assert result.url_findings[0].reputation == "malicious"

    def test_newly_registered_domain_flagged(self):
        result = _run(
            analyze_content(
                text="Login here: https://freshly-registered.example/login",
                domain_age_provider=FakeDomainAgeProvider({"freshly-registered.example": 2}),
                reputation_provider=FakeReputationProvider({}),
            )
        )
        assert result.url_findings[0].is_newly_registered is True
        assert result.score_delta > 0

    def test_typosquat_plus_urgency_combine(self):
        result = _run(
            analyze_content(
                text="Your account will be suspended immediately. Verify here: https://paypa1.com/verify",
                watchlist=["paypal.com"],
                domain_age_provider=FakeDomainAgeProvider({"paypa1.com": 10}),
                reputation_provider=FakeReputationProvider({}),
            )
        )
        assert result.url_findings[0].is_typosquat_candidate is True
        assert len(result.keyword_matches) >= 1
        # both signals should contribute -- this is exactly the kind of
        # message that should NOT rely on any single check alone
        assert result.score_delta >= 30

    def test_html_only_body_still_scanned_for_keywords(self):
        result = _run(
            analyze_content(
                html="<p>Final notice: verify your account immediately.</p>",
                domain_age_provider=FakeDomainAgeProvider({}),
                reputation_provider=FakeReputationProvider({}),
            )
        )
        assert len(result.keyword_matches) >= 1
