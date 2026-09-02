"""
Campaign clustering and fuzzy-hash similarity engine.
Detects high-velocity phishing campaigns targeting multiple recipients.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import time
from typing import Dict, List, Tuple


@dataclass
class CampaignClusterResult:
    is_campaign: bool = False
    cluster_id: str = ""
    cluster_size: int = 1
    score_boost: int = 0
    reasons: List[str] = field(default_factory=list)


def _compute_simhash(text: str) -> int:
    """Computes a 64-bit SimHash of normalized text tokens and bigrams."""
    normalized = re.sub(r"\d+", "num", text.lower())
    tokens = re.findall(r"\w+", normalized)
    if not tokens:
        return 0

    features = tokens + [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]

    v = [0] * 64
    for item in features:
        item_hash = int(hashlib.md5(item.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(64):
            bit = (item_hash >> i) & 1
            if bit:
                v[i] += 1
            else:
                v[i] -= 1

    fingerprint = 0
    for i in range(64):
        if v[i] >= 0:
            fingerprint |= (1 << i)
    return fingerprint


def _hamming_distance(hash1: int, hash2: int) -> int:
    """Calculates bitwise Hamming distance between two 64-bit integers."""
    x = hash1 ^ hash2
    return bin(x).count("1")


class CampaignClusterEngine:
    def __init__(
        self,
        window_seconds: int = 3600,
        similarity_max_distance: int = 5,
        campaign_threshold: int = 3,
        default_score_boost: int = 20,
    ):
        self.window_seconds = window_seconds
        self.similarity_max_distance = similarity_max_distance
        self.campaign_threshold = campaign_threshold
        self.default_score_boost = default_score_boost
        # Store tuples of (cluster_id, simhash, timestamp)
        self._entries: List[Tuple[str, int, float]] = []

    def evaluate_and_register(self, text_body: str, subject: str = "", from_domain: str = "") -> CampaignClusterResult:
        now = time.time()
        # Clean expired entries
        self._entries = [e for e in self._entries if now - e[2] <= self.window_seconds]

        content_sample = f"{subject} {from_domain} {text_body}"
        fingerprint = _compute_simhash(content_sample)
        if fingerprint == 0:
            return CampaignClusterResult()

        matched_cluster_id = ""
        cluster_count = 1

        for cluster_id, h, ts in self._entries:
            if _hamming_distance(fingerprint, h) <= self.similarity_max_distance:
                matched_cluster_id = cluster_id
                cluster_count += 1

        if not matched_cluster_id:
            matched_cluster_id = hashlib.sha256(f"{fingerprint}:{now}".encode()).hexdigest()[:12]

        # Register this entry
        self._entries.append((matched_cluster_id, fingerprint, now))

        if cluster_count >= self.campaign_threshold:
            reasons = [
                f"Campaign Alert: high-velocity fuzzy match (cluster '{matched_cluster_id}', {cluster_count} occurrences in last hour)"
            ]
            return CampaignClusterResult(
                is_campaign=True,
                cluster_id=matched_cluster_id,
                cluster_size=cluster_count,
                score_boost=self.default_score_boost,
                reasons=reasons,
            )

        return CampaignClusterResult(
            is_campaign=False,
            cluster_id=matched_cluster_id,
            cluster_size=cluster_count,
        )
