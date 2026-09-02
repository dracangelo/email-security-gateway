"""
MFA / TOTP Authenticator Engine (RFC 6238).
Provides secret generation, TOTP code creation, and clock-drift tolerant verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time


class TOTPAuthenticator:
    @staticmethod
    def generate_secret() -> str:
        """Generate a random 20-byte base32 secret key."""
        raw = os.urandom(20)
        return base64.b32encode(raw).decode("utf-8").replace("=", "")

    @staticmethod
    def generate_totp_code(secret: str, time_step: int = 30, timestamp: float | None = None) -> str:
        """Generate 6-digit TOTP code for a given secret key."""
        if timestamp is None:
            timestamp = time.time()

        counter = int(timestamp // time_step)
        # Standard base32 decode with padding fix
        padding = "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode((secret.upper() + padding).encode("utf-8"))

        msg = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()

        offset = hmac_digest[-1] & 0x0F
        binary = struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
        code = binary % 1_000_000
        return f"{code:06d}"

    @classmethod
    def verify_totp_code(cls, secret: str, code: str, window: int = 1, time_step: int = 30) -> bool:
        """Verify TOTP code within +/- `window` time steps."""
        if not secret or not code:
            return False

        code_clean = code.strip()
        now = time.time()

        for delta in range(-window, window + 1):
            ts = now + (delta * time_step)
            expected = cls.generate_totp_code(secret, time_step=time_step, timestamp=ts)
            if hmac.compare_digest(expected, code_clean):
                return True

        return False
