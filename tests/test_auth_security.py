"""
Comprehensive Authentication & Privilege Escalation Security Suite.
Validates:
1. Strict PBKDF2-HMAC-SHA256 password verification on /auth/login.
2. Prevention of caller role self-assignment (roles bound strictly to authenticated identities).
3. Hard prohibition of plaintext 'X-Admin-Role' privilege escalation.
4. Cryptographic verification of JWT Bearer tokens and RBAC permission enforcement.
5. Rejection of forged, tampered, or expired tokens.
"""

from __future__ import annotations

import time
import uuid

import jwt
from fastapi.testclient import TestClient

from agent_registry.admin_rbac import AdminRole
from identity_manager.admin_auth import AdminAuthManager
from identity_manager.jwt_auth import JWT_ALGORITHM, JWTAuthManager
from server import app

client = TestClient(app)


def test_login_rejects_missing_or_incorrect_password():
    """Verify that login fails closed with 401 when password is invalid or missing."""
    # 1. Invalid password for admin
    res_bad_pw = client.post(
        "/auth/login",
        json={"username": "admin", "password": "wrong_password_123"},
    )
    assert res_bad_pw.status_code == 401
    assert "Invalid administrator username or password" in res_bad_pw.json()["detail"]

    # 2. Unknown user
    res_unknown = client.post(
        "/auth/login",
        json={"username": "nonexistent_attacker", "password": "any_password"},
    )
    assert res_unknown.status_code == 401
    assert "Invalid administrator username or password" in res_unknown.json()["detail"]

    # 3. Empty password
    res_empty_pw = client.post(
        "/auth/login",
        json={"username": "admin", "password": ""},
    )
    assert res_empty_pw.status_code == 401


def test_login_authenticates_with_valid_password():
    """Verify that login succeeds and issues a signed JWT token when password is correct."""
    res = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == AdminRole.SYSTEM_ADMIN.value
    assert data["username"] == "admin"

    # Verify the issued token is cryptographically valid
    payload = JWTAuthManager.verify_token(data["access_token"])
    assert payload["sub"] == "admin"
    assert payload["role"] == AdminRole.SYSTEM_ADMIN.value


def test_login_prevents_role_spoofing():
    """Verify that a user cannot self-assign a higher role via the request payload."""
    # Auditor logging in but requesting SYSTEM_ADMIN role
    res = client.post(
        "/auth/login",
        json={
            "username": "auditor",
            "password": "AuditorTrust#2026!Secured",
            "role": "SYSTEM_ADMIN",  # Attacker attempts role spoofing
        },
    )
    assert res.status_code == 200
    data = res.json()
    # Must bind strictly to AUDITOR, ignoring attacker's requested role
    assert data["role"] == AdminRole.AUDITOR.value

    payload = JWTAuthManager.verify_token(data["access_token"])
    assert payload["role"] == AdminRole.AUDITOR.value


def test_raw_admin_role_header_privilege_escalation_is_blocked():
    """Verify that raw unauthenticated 'X-Admin-Role: SYSTEM_ADMIN' headers are strictly rejected."""
    # Attempting to register an agent using plaintext header
    res = client.post(
        "/agents/register",
        json={
            "agent_id": f"ATTACKER-AGENT-{uuid.uuid4().hex[:4]}",
            "agent_name": "RogueAgent",
            "owner": "Attacker",
        },
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res.status_code == 401
    assert "Plaintext 'X-Admin-Role' headers are prohibited" in res.json()["detail"]


def test_jwt_bearer_token_authorization_succeeds():
    """Verify that a properly signed JWT Bearer token grants administrative access."""
    admin_token = JWTAuthManager.create_admin_token(role="SYSTEM_ADMIN", identity_id="admin")
    agent_id = f"AUTH-AGENT-{uuid.uuid4().hex[:4]}"

    res = client.post(
        "/agents/register",
        json={
            "agent_id": agent_id,
            "agent_name": "AuthenticatedAgent",
            "owner": "SecOps",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["agent"]["agent_id"] == agent_id


def test_jwt_in_x_admin_role_header_succeeds():
    """Verify that passing a valid signed JWT in X-Admin-Role is supported for backwards compatibility."""
    admin_token = JWTAuthManager.create_admin_token(role="SYSTEM_ADMIN", identity_id="admin")
    agent_id = f"JWT-HEADER-AGENT-{uuid.uuid4().hex[:4]}"

    res = client.post(
        "/agents/register",
        json={
            "agent_id": agent_id,
            "agent_name": "JwtHeaderAgent",
            "owner": "SecOps",
        },
        headers={"X-Admin-Role": admin_token},
    )
    assert res.status_code == 200
    assert res.json()["agent"]["agent_id"] == agent_id


def test_rbac_denies_unprivileged_authenticated_role():
    """Verify that an authenticated user with insufficient role permissions receives 403 Forbidden."""
    auditor_token = JWTAuthManager.create_admin_token(role="AUDITOR", identity_id="auditor")

    res = client.post(
        "/agents/register",
        json={
            "agent_id": f"DENIED-AGENT-{uuid.uuid4().hex[:4]}",
            "agent_name": "DeniedAgent",
            "owner": "Ops",
        },
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert res.status_code == 403
    assert "RBAC Denial" in res.json()["detail"]
    assert "AUDITOR" in res.json()["detail"]


def test_forged_and_expired_jwt_are_rejected():
    """Verify that forged signature or expired tokens are rejected with 401."""
    # 1. Forged token signed with a bogus key
    bogus_token = jwt.encode(
        {"sub": "attacker", "role": "SYSTEM_ADMIN", "exp": int(time.time()) + 3600, "iss": "AgentTrust-Auth-Server"},
        "wrong_secret_key_12345678901234567890",
        algorithm=JWT_ALGORITHM,
    )
    res_forged = client.post(
        "/agents/register",
        json={"agent_id": "FORGED-AGENT", "agent_name": "Forged", "owner": "Attacker"},
        headers={"Authorization": f"Bearer {bogus_token}"},
    )
    assert res_forged.status_code == 401
    assert "JWT Authentication Failure" in res_forged.json()["detail"]

    # 2. Expired token
    expired_token = jwt.encode(
        {"sub": "admin", "role": "SYSTEM_ADMIN", "exp": int(time.time()) - 100, "iss": "AgentTrust-Auth-Server"},
        JWTAuthManager.get_active_secret(),
        algorithm=JWT_ALGORITHM,
    )
    res_expired = client.post(
        "/agents/register",
        json={"agent_id": "EXPIRED-AGENT", "agent_name": "Expired", "owner": "Ops"},
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_expired.status_code == 401
    assert "Expired" in res_expired.json()["detail"]
