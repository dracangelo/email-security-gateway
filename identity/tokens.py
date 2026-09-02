"""
Session Token Management, Key Rotation, and Revocation.
Generates short-lived, signed session tokens (HMAC-SHA256) with refresh capabilities.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Optional, Set
import hmac
import hashlib

from identity.rbac import RBACManager


class InvalidTokenError(Exception):
    pass


class TokenExpiredError(InvalidTokenError):
    pass


class SessionTokenManager:
    def __init__(self, secret_key: str, default_ttl_seconds: int = 3600):
        self.secret_key = secret_key
        self.default_ttl_seconds = default_ttl_seconds
        self._revoked_tokens: Set[str] = set()

    def _b64encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _b64decode(self, s: str) -> bytes:
        padding = "=" * (4 - (len(s) % 4))
        return base64.urlsafe_b64decode(s + padding)

    def _sign(self, message: str) -> str:
        sig = hmac.new(self.secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
        return self._b64encode(sig)

    def create_session_token(
        self,
        user_id: str,
        username: str,
        role: str,
        tenant_id: Optional[str] = None,
        mfa_verified: bool = False,
        scopes: Optional[list[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """Create a signed, short-lived session token."""
        now = int(time.time())
        ttl = ttl_seconds or self.default_ttl_seconds
        all_scopes = list(RBACManager.get_role_scopes(role).union(set(scopes or [])))

        payload = {
            "sub": user_id,
            "username": username,
            "role": role,
            "tenant_id": tenant_id,
            "mfa_verified": mfa_verified,
            "scopes": all_scopes,
            "iat": now,
            "exp": now + ttl,
        }

        header_b64 = self._b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
        payload_b64 = self._b64encode(json.dumps(payload).encode("utf-8"))
        token_body = f"{header_b64}.{payload_b64}"
        signature_b64 = self._sign(token_body)

        return f"{token_body}.{signature_b64}"

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify session token signature, expiration, and revocation status."""
        if token in self._revoked_tokens:
            raise InvalidTokenError("Session token has been revoked")

        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise InvalidTokenError("Malformed token structure")

            header_b64, payload_b64, signature_b64 = parts
            token_body = f"{header_b64}.{payload_b64}"
            expected_sig = self._sign(token_body)

            if not hmac.compare_digest(signature_b64, expected_sig):
                raise InvalidTokenError("Invalid token signature")

            payload = json.loads(self._b64decode(payload_b64).decode("utf-8"))
            now = int(time.time())

            if payload.get("exp", 0) < now:
                raise TokenExpiredError("Session token expired")

            return payload
        except (InvalidTokenError, TokenExpiredError):
            raise
        except Exception as exc:
            raise InvalidTokenError(f"Token verification failed: {exc}")

    def revoke_token(self, token: str) -> None:
        """Revoke/blacklist session token."""
        self._revoked_tokens.add(token)

    def refresh_session_token(self, token: str, ttl_seconds: Optional[int] = None) -> str:
        """Issue new token for valid unexpired token."""
        payload = self.verify_token(token)
        self.revoke_token(token)
        return self.create_session_token(
            user_id=payload["sub"],
            username=payload["username"],
            role=payload["role"],
            tenant_id=payload.get("tenant_id"),
            mfa_verified=payload.get("mfa_verified", False),
            scopes=payload.get("scopes", []),
            ttl_seconds=ttl_seconds,
        )
