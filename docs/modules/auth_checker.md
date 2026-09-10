# Module: auth_checker — Email Authentication

## Purpose

Implements the gateway's authentication stack: SPF, DKIM, DMARC, ARC, BIMI, DNSSEC, FCrDNS, MTA-STS, IP reputation, DKIM key policy, and sender baseline history. All checks run on every message; results feed `score_delta` values into the decision engine.

---

## Module Structure

| File | Responsibility |
|---|---|
| `pipeline.py` | Orchestrates all checks; entry point `run_auth_checks()` |
| `spf.py` | RFC 7208 SPF evaluation (own implementation, not a library) |
| `dkim_check.py` | DKIM signature verification via `dkimpy` |
| `dkim_policy.py` | DKIM key strength and algorithm policy evaluation |
| `dmarc.py` | DMARC DNS record fetch, org-domain resolution |
| `alignment.py` | DMARC identifier alignment (SPF + DKIM against From domain) |
| `arc.py` | ARC (Authenticated Received Chain) header validation |
| `bimi.py` | BIMI DNS record fetch and VMC certificate chain validation |
| `fcrdns.py` | Forward-Confirmed Reverse DNS consistency check |
| `dnssec.py` | Creates a DNSSEC-validating DNS resolver |
| `ip_reputation.py` | Connecting IP reputation against DNSBL feeds (Spamhaus ZEN etc.) |
| `mta_sts.py` | MTA-STS policy fetch and inbound TLS enforcement check |
| `sender_baseline.py` | Historical sender domain volume/IP baseline |
| `models.py` | Pydantic data models for all results |

---

## Entry Point

```python
from auth_checker import run_auth_checks

verdict: AuthVerdict = run_auth_checks(
    raw_message=raw_bytes,   # full MIME message
    client_ip="203.0.113.5", # SMTP-connecting IP
    envelope_from="sender@example.com",
)

print(verdict.score_delta)  # e.g. 65
print(verdict.reasons)      # e.g. ["SPF hard fail", "DMARC fail under p=reject"]
```

---

## Checks & Score Contributions

### SPF (RFC 7208)

Evaluated against the **envelope-from domain** and client IP. Own implementation (no third-party SPF library) supporting:
- `a`, `mx`, `ip4`, `ip6`, `include`, `redirect` mechanisms
- `~all` / `-all` / `?all` qualifiers
- `ptr` and `exists` mechanisms are explicitly **not supported** (rare, security-sensitive)

| Result | Score delta |
|---|---|
| `pass` | 0 |
| `softfail (~all)` | +15 |
| `fail (-all)` | +30 |
| `permerror` / `temperror` | +5 |

### DKIM

Signature verification via `dkimpy`. Verifies the `DKIM-Signature` header against the public key in DNS.

| Result | Score delta |
|---|---|
| `pass` | 0 |
| `none` (no signature) | +15 |
| `fail` (invalid signature) | +30 |
| `permerror` / `temperror` | +5 |

### DMARC + Alignment

Fetches the `_dmarc.{domain}` TXT record. Evaluates alignment between the `From:` domain and the authenticated SPF/DKIM domain.

> **Note**: Org-domain resolution uses a naive last-two-labels heuristic rather than a full Public Suffix List walk — this is correct for most TLDs but wrong for multi-label CCTLDs like `.co.uk`. Track issue [#42] to swap in `publicsuffix2`.

| Result | Score delta |
|---|---|
| `pass` | 0 |
| `fail` under `p=none` | +10 |
| `fail` under `p=quarantine` | +35 |
| `fail` under `p=reject` | +50 |

### ARC (Authenticated Received Chain)

Validates the ARC header set chain (`ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`). A valid ARC chain from a trusted forwarder **mitigates** SPF/DMARC failures — this is essential for mail legitimately forwarded through mailing lists.

When ARC passes and SPF/DMARC would have failed:
- The SPF/DMARC penalties are **not applied**
- A reason is added: `"ARC chain valid (N hops) - mitigated SPF/DMARC failure"`

### FCrDNS (Forward-Confirmed Reverse DNS)

Checks that the client IP's reverse PTR record resolves forward back to the same IP. A supplementary signal — cheap to compute, catches crude spoofing.

| Result | Score delta |
|---|---|
| `pass` | 0 |
| `fail` | +15 |

### MTA-STS

Fetches the `_mta-sts.{domain}` TXT record and the `https://mta-sts.{domain}/.well-known/mta-sts.txt` policy file. If the domain has `mode: enforce` and the inbound connection headers indicate the message was delivered without TLS, this signals a potential downgrade attack.

| Result | Score delta |
|---|---|
| `pass` | 0 |
| `enforce_failed` | +20 |
| `policy_not_found` / `testing` | 0 |

### BIMI

Fetches the `default._bimi.{domain}` TXT record and optionally validates the VMC/CMC certificate chain. Used as a soft positive trust signal — BIMI does not affect score_delta but is included in the `AuthVerdict` for dashboard display.

### DKIM Key Policy

Evaluates the DKIM signature's algorithm and key length:
- SHA-1 algorithm: flagged (deprecated)
- RSA key < 1024 bits: flagged
- Score delta varies; reasons are appended.

### IP Reputation

Checks the SMTP-connecting IP against DNSBL feeds (Spamhaus ZEN, SORBS). Score delta ranges from +15 to +30 based on the specific listing category.

### Sender Baseline

Maintains per-domain send history: first-seen timestamp, historical IP ranges, typical volume. A domain that has never contacted your infrastructure before AND scores high elsewhere is weighted differently than an established sender with a transient auth failure.

---

## Data Models

```python
@dataclass
class AuthVerdict:
    from_domain: str
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    arc: ARCResult
    bimi: BIMIResult
    fcrdns: FCrDNSResult
    mta_sts: MTASTSResult
    baseline: SenderBaselineResult
    dnssec_valid: bool
    score_delta: int
    reasons: list[str]
```

---

## Known Limitations

- **PSL walk**: Org-domain resolution in `dmarc.py` uses naive last-two-labels — wrong for `.co.uk`, `.github.io`, etc. Replace with `publicsuffix2`/`tldextract`.
- **SPF `ptr`/`exists`**: Not implemented (security-sensitive, rare in practice).
- **SPF macro expansion**: Not implemented — affects some enterprise SPF records using `%{i}`, `%{s}`.
- **DNSSEC**: The resolver is configured for DNSSEC validation but its correctness depends on the upstream resolver's own DNSSEC posture.
