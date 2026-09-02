"""
Role-Based Access Control (RBAC) & Scope Management.
Defines role permissions, scope evaluation, and least-privilege checks.
"""
from __future__ import annotations

from typing import Dict, List, Set

# Role permissions hierarchy mapping
ROLE_SCOPES: Dict[str, Set[str]] = {
    "admin": {
        "quarantine:read",
        "quarantine:write",
        "report:submit",
        "tenant:manage",
        "user:manage",
        "audit:read",
        "stats:read",
        "system:admin",
    },
    "analyst": {
        "quarantine:read",
        "quarantine:write",
        "report:submit",
        "audit:read",
        "stats:read",
    },
    "read_only": {
        "quarantine:read",
        "audit:read",
        "stats:read",
    },
}


class RBACManager:
    @staticmethod
    def get_role_scopes(role: str) -> Set[str]:
        return ROLE_SCOPES.get(role, set())

    @staticmethod
    def has_permission(user_role: str, user_custom_scopes: List[str] | None, required_scope: str) -> bool:
        """Check if user role or explicit custom scopes grant required_scope."""
        if user_role == "admin":
            return True

        role_scopes = ROLE_SCOPES.get(user_role, set())
        if required_scope in role_scopes:
            return True

        if user_custom_scopes and required_scope in user_custom_scopes:
            return True

        return False

    @staticmethod
    def validate_role(role: str) -> bool:
        return role in ROLE_SCOPES
