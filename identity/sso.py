"""
SSO (OpenID Connect / SAML) Identity Provider Integration.
Parses OIDC claims, authenticates IdP tokens, and maps enterprise groups to RBAC roles.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from identity.models import User, hash_password
from identity.rbac import RBACManager

logger = logging.getLogger(__name__)


class OIDCAuthProvider:
    def __init__(self, default_role_mapping: Optional[Dict[str, str]] = None):
        # group/claim name -> gateway role
        self.role_mapping = default_role_mapping or {
            "GatewayAdmins": "admin",
            "SOCAnalysts": "analyst",
            "Auditors": "read_only",
        }

    def map_claims_to_role(self, groups: list[str]) -> str:
        """Resolve highest priority role from IdP user groups."""
        assigned_role = "read_only"
        for group in groups:
            mapped = self.role_mapping.get(group)
            if mapped == "admin":
                return "admin"
            elif mapped == "analyst":
                assigned_role = "analyst"

        return assigned_role

    def authenticate_oidc_claims(self, claims: Dict[str, Any]) -> User:
        """Process validated OIDC token claims and return user object."""
        email = claims.get("email") or claims.get("sub")
        if not email:
            raise ValueError("OIDC claims missing required 'email' or 'sub'")

        username = claims.get("preferred_username") or claims.get("name") or email
        groups = claims.get("groups", [])
        role = self.map_claims_to_role(groups)

        user_id = f"sso_{hash_password(email)[:8]}"
        user = User(
            user_id=user_id,
            username=username,
            password_hash="SSO_EXTERNAL_AUTH",
            role=role,
            tenant_id=claims.get("tenant_id"),
            mfa_enabled=True,  # Delegated to enterprise IdP
            is_active=True,
            scopes=list(RBACManager.get_role_scopes(role)),
        )

        logger.info("Authenticated SSO user %s with role %s", username, role)
        return user
