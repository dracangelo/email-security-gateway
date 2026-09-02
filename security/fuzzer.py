"""
Fuzz testing engine providing property-based and mutation-based fuzzing targets for
MIME parsing, attachment extraction, archive unpacking, and document analysis.
Ensures parser resilience against corrupted, malformed, or malicious payloads.
"""
from __future__ import annotations

import os
import random
import string
from typing import Callable, List, Tuple


class Fuzzer:
    """Mutation and seed-based fuzzing generator for email payloads and attachments."""

    @staticmethod
    def mutate_bytes(data: bytes, mutation_rate: float = 0.05) -> bytes:
        """Mutate random bytes in payload (bit flips, byte overwrites, truncations)."""
        if not data:
            return b"FAKEMIME\r\n\r\ncorrupted"
        mutable = bytearray(data)
        num_mutations = max(1, int(len(mutable) * mutation_rate))
        for _ in range(num_mutations):
            choice = random.choice(["flip", "replace", "insert", "delete"])
            pos = random.randint(0, len(mutable) - 1)
            if choice == "flip":
                mutable[pos] ^= random.randint(1, 255)
            elif choice == "replace":
                mutable[pos] = random.randint(0, 255)
            elif choice == "insert":
                mutable.insert(pos, random.randint(0, 255))
            elif choice == "delete" and len(mutable) > 1:
                del mutable[pos]
        return bytes(mutable)

    @staticmethod
    def generate_malformed_mime(depth: int = 5) -> bytes:
        """Generate deeply nested, unclosed, or invalid header MIME structures."""
        headers = [
            f"From: {'a'*200}@example.com",
            f"To: victim{'@example.com'*10}",
            f"Subject: {'=?UTF-8?B? invalid_base64_blob!?=' * 5}",
            f"Content-Type: multipart/mixed; boundary=\"{'='*50}\"",
            "MIME-Version: 1.0",
        ]
        body_parts = []
        for i in range(depth):
            body_parts.append(f"--{'='*50}\nContent-Type: text/plain; charset=utf-8\n\nNested part {i}")
            body_parts.append(f"--{'='*50}\nContent-Type: application/x-executable\nContent-Disposition: attachment; filename=\"test_{i}.exe\"\n\n\x7fELF\x01\x01\x01\x00" + os.urandom(64).decode("latin-1", errors="ignore"))

        raw_mime = "\r\n".join(headers) + "\r\n\r\n" + "\r\n".join(body_parts)
        return raw_mime.encode("utf-8", errors="ignore")

    @classmethod
    def fuzz_target(
        cls,
        target_fn: Callable[[bytes], None],
        seed_corpus: List[bytes],
        iterations: int = 100,
    ) -> List[Tuple[bytes, Exception]]:
        """
        Executes target_fn against mutated variants of seed_corpus.
        Returns a list of payloads that caused uncaught exceptions (crashes).
        """
        crashes: List[Tuple[bytes, Exception]] = []
        for i in range(iterations):
            seed = random.choice(seed_corpus) if seed_corpus else cls.generate_malformed_mime()
            payload = cls.mutate_bytes(seed, mutation_rate=random.uniform(0.01, 0.15))
            try:
                target_fn(payload)
            except Exception as exc:
                # Catch unexpected failures / panics (excluding known validation errors)
                crashes.append((payload, exc))
        return crashes
