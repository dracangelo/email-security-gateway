"""
Tests for Identity, Access & Admin Module (Task 8):
- User account creation & password hashing
- RBAC permissions & fine-grained scope enforcement
- RFC 6238 TOTP MFA generation & clock-drift verification
- Short-lived signed session tokens, expiration, refresh & revocation
- OIDC SSO authentication & group claim mapping
- FastAPI auth login, token refresh, user management & RBAC endpoint protection
"""
from __future__ import annotations

import time
import pytest
from fastapi.testclient import TestClient

from identity import (
    IdentityAuthManager,
    InvalidTokenError,
    OIDCAuthProvider,
    RBACManager,
    SessionTokenManager,
    TOTPAuthenticator,
    UserManager,
    hash_password,
    verify_password,
)
from webhook_receiver.app import app


def test_password_hashing():
    p = "SuperSecretPassword123!"
    h = hash_password(p)
    assert verify_password(p, h) is True
    assert verify_password("WrongPassword", h) is False


def test_user_manager():
    um = UserManager()

    # Create users
    admin = um.create_user("admin_user", "AdminPass123!", role="admin")
    analyst = um.create_user("analyst_user", "AnalystPass123!", role="analyst", mfa_enabled=True)

    assert admin.role == "admin"
    assert analyst.role == "analyst"
    assert analyst.mfa_secret is not None

    # Authenticate
    authenticated = um.authenticate("analyst_user", "AnalystPass123!")
    assert authenticated is not None
    assert authenticated.user_id == analyst.user_id

    assert um.authenticate("analyst_user", "wrong_pass") is None


def test_rbac_manager():
    assert RBACManager.has_permission("admin", None, "system:admin") is True
    assert RBACManager.has_permission("analyst", None, "quarantine:read") is True
    assert RBACManager.has_permission("analyst", None, "system:admin") is False
    assert RBACManager.has_permission("read_only", None, "quarantine:write") is False

    # Custom scope grant
    assert RBACManager.has_permission("read_only", ["quarantine:write"], "quarantine:write") is True


def test_totp_mfa():
    secret = TOTPAuthenticator.generate_secret()
    code = TOTPAuthenticator.generate_totp_code(secret)

    assert TOTPAuthenticator.verify_totp_code(secret, code) is True
    assert TOTPAuthenticator.verify_totp_code(secret, "000000") is False


def test_session_token_manager():
    tm = SessionTokenManager(secret_key="test_secret_key", default_ttl_seconds=3600)

    token = tm.create_session_token(
        user_id="u_1", username="testuser", role="analyst", scopes=["quarantine:read"]
    )
    assert token is not None

    payload = tm.verify_token(token)
    assert payload["sub"] == "u_1"
    assert payload["role"] == "analyst"

    # Token Refresh
    refreshed = tm.refresh_session_token(token, ttl_seconds=7200)
    assert refreshed is not None
    assert refreshed != token

    # Verification of revoked token fails
    with pytest.raises(InvalidTokenError):
        tm.verify_token(token)


def test_oidc_sso_provider():
    oidc = OIDCAuthProvider()
    claims = {
        "sub": "user@enterprise.com",
        "email": "user@enterprise.com",
        "preferred_username": "Jane Doe",
        "groups": ["SOCAnalysts"],
    }

    user = oidc.authenticate_oidc_claims(claims)
    assert user.username == "Jane Doe"
    assert user.role == "analyst"
    assert "quarantine:read" in user.scopes


def test_identity_fastapi_endpoints():
    client = TestClient(app)

    # 1. Login with root admin account
    resp_login = client.post(
        "/admin/auth/login",
        json={"username": "admin", "password": "AdminPassword123!"},
    )
    assert resp_login.status_code == 200
    data = resp_login.json()
    assert data["status"] == "authenticated"
    token = data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. List Users with session token
    resp_users = client.get("/admin/users", headers=headers)
    assert resp_users.status_code == 200
    users = resp_users.json()
    assert any(u["username"] == "admin" for u in users)

    # 3. Create Analyst User
    resp_create = client.post(
        "/admin/users",
        headers=headers,
        json={"username": "soc_analyst", "password": "AnalystPassword123!", "role": "analyst"},
    )
    assert resp_create.status_code == 200
    analyst_data = resp_create.json()
    assert analyst_data["username"] == "soc_analyst"

    # 4. Login as Analyst User
    resp_analyst_login = client.post(
        "/admin/auth/login",
        json={"username": "soc_analyst", "password": "AnalystPassword123!"},
    )
    assert resp_analyst_login.status_code == 200
    analyst_token = resp_analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 5. Analyst attempting User Management -> 403 Forbidden
    resp_forbidden = client.get("/admin/users", headers=analyst_headers)
    assert resp_forbidden.status_code == 403

    # 6. Delete Analyst User as Admin
    resp_del = client.delete("/admin/users/soc_analyst", headers=headers)
    assert resp_del.status_code == 200
    assert resp_del.json()["status"] == "deleted"
