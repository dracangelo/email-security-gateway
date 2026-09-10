# Module: decision_engine — Routing & Policy

## Purpose

Combines stage scores from `auth_checker`, `content_analysis`, and `attachment_analysis` into a single routing decision. Applies enterprise policy layers: per-tenant configurable thresholds, VIP protection, allow/block rules, feedback loop adjustments, campaign clustering boosts, shadow mode A/B testing, and generates human-readable explainability reports.

---

## Module Structure

| File | Responsibility |
|---|---|
| `scorer.py` | Main `decide()` function — score aggregation + policy layers |
| `models.py` | `Action`, `RoutingDecision`, `StageScore` data models |
| `allow_block.py` | Precedence allow/block rule evaluation |
| `tenant_config.py` | Per-tenant threshold + stage weight configuration |
| `vip_policy.py` | VIP/executive protection scoring and threshold lowering |
| `campaign_clustering.py` | High-velocity campaign detection with score boost |
| `feedback_loop.py` | Domain trust adjustments from analyst feedback |
| `shadow_mode.py` | A/B rule testing without affecting real decisions |
| `explainability.py` | Human-readable decision reports |

---

## Entry Point

```python
from decision_engine import decide, StageScore

decision = decide(
    stage_scores=[
        StageScore(stage="auth", score_delta=65, reasons=["SPF fail", "DMARC fail"]),
        StageScore(stage="content", score_delta=25, reasons=["BEC keyword match"]),
        StageScore(stage="attachments", score_delta=0, reasons=[]),
    ],
    tenant_id="tenant_acme",
)

print(decision.action)       # Action.QUARANTINE
print(decision.total_score)  # 90
print(decision.all_reasons)  # ["SPF fail", "DMARC fail", "BEC keyword match"]
```

---

## Decision Logic

```
total_score = sum(stage.score_delta * stage_weight for each stage)
            + feedback_adjustment
            + vip_score_boost
            + campaign_score_boost

if allow_block_result.is_blocked:
    action = QUARANTINE  # precedence override

elif allow_block_result.is_allowed and no malware signal (score < 100):
    action = FORWARD     # precedence override

elif total_score >= quarantine_threshold:
    action = QUARANTINE

elif total_score >= warn_threshold:
    action = WARN_AND_STRIP

else:
    action = FORWARD
```

> **Malware exception to allowlist**: If any single stage score is ≥ 100 (indicating a ClamAV/VirusTotal malware hit), the allowlist override is **not applied** — even explicitly whitelisted senders cannot bypass a confirmed malware signal.

---

## Default Thresholds

| Variable | Default | Notes |
|---|---|---|
| `WARN_THRESHOLD` | `30` | Score ≥ 30 → `WARN_AND_STRIP` |
| `QUARANTINE_THRESHOLD` | `70` | Score ≥ 70 → `QUARANTINE` |

Thresholds can be overridden per-tenant via `TenantConfig`.

---

## Policy Layers

### 1. Per-Tenant Configuration

Each tenant can configure:

```python
@dataclass
class TenantConfig:
    tenant_id: str
    warn_threshold: int          # override default 30
    quarantine_threshold: int    # override default 70
    stage_weights: dict[str, float]  # e.g. {"auth": 1.5, "content": 0.8}
```

Stage weights allow certain tenants to weight auth failures more heavily (e.g., a financial institution) or content signals more lightly (e.g., a marketing platform with legitimate urgency language).

### 2. Allow / Block Rules (`allow_block.py`)

Precedence rules evaluated before threshold scoring:

- **Block rules**: Force `QUARANTINE` regardless of score
- **Allow rules**: Force `FORWARD` regardless of score (unless malware)

Rules can match on: sender domain, sender IP, envelope-from, `From:` header, subject pattern.

### 3. VIP / Executive Protection (`vip_policy.py`)

When a VIP match is detected in `content_analysis` (display-name spoof against `VIP_DISPLAY_NAMES`):

- Score is boosted by `VIPPolicyResult.score_boost` (+25 to +40)
- `quarantine_threshold` is lowered to `VIPPolicyResult.lowered_quarantine_threshold`
- Ensures VIP impersonation is quarantined even with borderline scores

### 4. Feedback Loop (`feedback_loop.py`)

Analysts releasing false positives and confirming phishing verdicts feed into the domain reputation store. Future messages from the same domain receive a score adjustment:

- Known legitimate sender domain: negative `feedback_adjustment` (reduces score)
- Confirmed phishing domain: positive `feedback_adjustment` (raises score)

### 5. Campaign Clustering (`campaign_clustering.py`)

Tracks message similarity across a time window. When the same or highly similar content is received from multiple senders in a short period (a campaign):

- Score is boosted by `CampaignClusterResult.score_boost`
- The campaign `cluster_id` is attached to the decision for correlation

### 6. Shadow Mode (`shadow_mode.py`)

Allows testing experimental scoring rules alongside the production rules without affecting actual routing decisions. The shadow engine evaluates messages under the experimental rules and logs discrepancies for analysis.

---

## Explainability Reports

Every decision includes a structured explainability report accessible via `decision.explainability`:

```json
{
  "tenant_id": "tenant_acme",
  "action": "QUARANTINE",
  "total_score": 90,
  "warn_threshold": 30,
  "quarantine_threshold": 70,
  "score_breakdown": {
    "auth": 65,
    "content": 25,
    "attachments": 0
  },
  "top_reasons": [
    "SPF hard fail (+30)",
    "DMARC fail under p=reject (+50)",
    "BEC urgency keyword match (+25)"
  ],
  "policy_overrides": []
}
```

---

## Data Models

```python
class Action(Enum):
    FORWARD = "forward"
    WARN_AND_STRIP = "warn_and_strip"
    QUARANTINE = "quarantine"

@dataclass
class StageScore:
    stage: str           # "auth", "content", "attachments"
    score_delta: int
    reasons: list[str]

@dataclass
class RoutingDecision:
    total_score: int
    action: Action
    stage_scores: list[StageScore]
    all_reasons: list[str]
    explainability: dict | None = None
    shadow_result: dict | None = None
    vip_info: dict | None = None
    campaign_info: dict | None = None
```
