"""
At-rest encryption for stored raw mail. Raw .eml files routinely contain
credentials, PII, and internal infrastructure detail -- either from the
phishing content itself, or just because it's someone's real inbox
traffic. Encrypting them at rest is the same call any findings/evidence
datastore holding sensitive captured content should make.

Fernet (symmetric, AES-128-CBC + HMAC under the hood) rather than
anything fancier: this is data at rest on a single disk, not a
multi-party protocol, and Fernet's authenticated encryption means a
tampered file fails to decrypt loudly instead of silently returning
garbage.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["RawMailCipher", "InvalidToken"]


class RawMailCipher:
    def __init__(self, key: str = ""):
        self.key = key
        self._fernet = Fernet(key.encode()) if key else None

    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, data: bytes) -> bytes:
        """Returns ciphertext, or the original bytes unchanged if no key is configured."""
        if not self._fernet:
            return data
        return self._fernet.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        """Raises InvalidToken if the key is wrong or the data wasn't Fernet-encrypted."""
        if not self._fernet:
            return data
        return self._fernet.decrypt(data)
