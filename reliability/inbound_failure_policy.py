"""
Inbound-Failure Behavior per Provider Inspection & Simulation.
Documents and simulates provider retry policies, queue retention periods, and bounce conditions during gateway outages.
"""
from __future__ import annotations

from dataclasses import dataclass

PROVIDER_POLICIES = {
    "sendgrid": {
        "retry_duration_hours": 72,
        "backoff_strategy": "Exponential backoff up to 72 hours",
        "bounces_on_failure": False,
        "description": "SendGrid queues inbound webhooks and retries delivery for up to 72 hours if gateway returns 5xx/4xx or times out.",
    },
    "aws_ses": {
        "retry_duration_hours": 84,
        "backoff_strategy": "Exponential backoff up to 84 hours",
        "bounces_on_failure": False,
        "description": "AWS SES / SNS retries webhook notifications for up to 84 hours with automatic fallback queues.",
    },
    "mailgun": {
        "retry_duration_hours": 80,
        "backoff_strategy": "Exponential backoff up to 80 hours",
        "bounces_on_failure": False,
        "description": "Mailgun retries failed webhook posts periodically over 80 hours before dropping the message notification.",
    },
    "m365": {
        "retry_duration_hours": 24,
        "backoff_strategy": "Exponential backoff up to 24 hours",
        "bounces_on_failure": False,
        "description": "Microsoft 365 Exchange Online retries outbound connector delivery for up to 24 hours.",
    },
    "postfix": {
        "retry_duration_hours": 120,
        "backoff_strategy": "Configurable maximal_queue_lifetime (default 5d)",
        "bounces_on_failure": False,
        "description": "Standard MTA (Postfix/Exim) queues undelivered mail in deferred queue for up to 5 days before generating DSN bounce.",
    },
}


@dataclass
class ProviderFailurePolicy:
    provider_name: str
    retry_duration_hours: int
    backoff_strategy: str
    bounces_on_failure: bool
    description: str


@dataclass
class OutageImpactReport:
    provider_name: str
    outage_duration_hours: float
    mail_lost: bool
    retries_expected: bool
    explanation: str


class InboundFailureInspector:
    """Inspects and simulates provider retry behavior during gateway downtime."""

    def get_provider_policy(self, provider_name: str) -> ProviderFailurePolicy:
        p_name = provider_name.lower().replace("-", "_")
        pol = PROVIDER_POLICIES.get(p_name, {
            "retry_duration_hours": 24,
            "backoff_strategy": "Standard 24h retry queue",
            "bounces_on_failure": False,
            "description": f"Generic provider policy for {provider_name}",
        })

        return ProviderFailurePolicy(
            provider_name=provider_name,
            retry_duration_hours=pol["retry_duration_hours"],
            backoff_strategy=pol["backoff_strategy"],
            bounces_on_failure=pol["bounces_on_failure"],
            description=pol["description"],
        )

    def simulate_gateway_outage(self, provider_name: str, outage_duration_hours: float) -> OutageImpactReport:
        pol = self.get_provider_policy(provider_name)
        mail_lost = outage_duration_hours > pol.retry_duration_hours

        if mail_lost:
            explanation = (
                f"Outage duration ({outage_duration_hours}h) exceeded {provider_name}'s max queue retry period "
                f"({pol.retry_duration_hours}h); messages will bounce or be dropped by sender MTA."
            )
        else:
            explanation = (
                f"Outage duration ({outage_duration_hours}h) is within {provider_name}'s queue retry window "
                f"({pol.retry_duration_hours}h); provider will queue and deliver messages once gateway recovers."
            )

        return OutageImpactReport(
            provider_name=provider_name,
            outage_duration_hours=outage_duration_hours,
            mail_lost=mail_lost,
            retries_expected=not mail_lost,
            explanation=explanation,
        )
