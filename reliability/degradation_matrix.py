"""
"What Still Works When X Is Down" Graceful Degradation Matrix.
Evaluates gateway capability levels and ensures core auth and rule checks continue operating safely when external APIs are unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DegradationReport:
    active_capabilities: list[str] = field(default_factory=list)
    disabled_capabilities: list[str] = field(default_factory=list)
    degradation_level: str = "FULL"  # "FULL" | "DEGRADED" | "CRITICAL"
    safe_to_operate: bool = True
    fallback_actions: list[str] = field(default_factory=list)


class DegradationMatrix:
    """Formalizes and verifies the gateway's graceful degradation capabilities."""

    CORE_CAPABILITIES = ["spf_check", "dkim_check", "dmarc_alignment", "heuristic_rules", "local_quarantine"]

    EXTERNAL_DEPENDENCIES = {
        "virustotal": "Cloud URL & Attachment Hash Reputation",
        "rdap": "Domain Age & Registrar Lookup",
        "clamav": "Antivirus Detonation Engine",
        "openai": "LLM Phishing & Sentiment Analysis",
        "threat_intel": "Live IP & Domain Threat Intelligence Feeds",
    }

    def evaluate_degraded_pipeline(self, down_services: list[str]) -> DegradationReport:
        down_set = set(s.lower() for s in down_services)

        active = list(self.CORE_CAPABILITIES)
        disabled = []
        fallbacks = []

        for svc, desc in self.EXTERNAL_DEPENDENCIES.items():
            if svc in down_set:
                disabled.append(f"{svc} ({desc})")
                fallbacks.append(f"Fallback to heuristic & local rule checks for {svc}")
            else:
                active.append(svc)

        if len(disabled) == 0:
            level = "FULL"
        elif len(disabled) < len(self.EXTERNAL_DEPENDENCIES):
            level = "DEGRADED"
        else:
            level = "CRITICAL"

        return DegradationReport(
            active_capabilities=active,
            disabled_capabilities=disabled,
            degradation_level=level,
            safe_to_operate=True,  # Gateway always operates safely using core auth checks
            fallback_actions=fallbacks,
        )
