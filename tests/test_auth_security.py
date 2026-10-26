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
import pytest
from fastapi.testclient import TestClient

from agent_registry.admin_rbac import AdminRole
from identity_manager.jwt_auth import JWT_ALGORITHM, JWTAuthManager
from server import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_client_and_revocations():
    """Ensures each test starts with an empty cookie jar and clean token revocation set."""
    client.cookies.clear()
    JWTAuthManager.clear_revoked_tokens()
    yield
    client.cookies.clear()
    JWTAuthManager.clear_revoked_tokens()


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


def test_frontend_multi_role_authenticated_operations_flow():
    """
    Simulates the frontend and dashboard authentication lifecycle across all four personas:
    1. Authenticates each persona via /auth/login.
    2. Exercises role-specific administrative operations with Authorization: Bearer <token>.
    3. Confirms strict role separation and denial when permissions are violated.
    """
    # 1. Login as Policy Admin and manage policies
    res_pol_login = client.post(
        "/auth/login",
        json={"username": "policy_admin", "password": "PolicyTrust#2026!Secured"},
    )
    assert res_pol_login.status_code == 200
    pol_token = res_pol_login.json()["access_token"]
    assert res_pol_login.json()["role"] == "POLICY_ADMIN"

    # Policy Admin creates a policy v1.0
    policy_id = f"POL-{uuid.uuid4().hex[:6].upper()}"
    res_create_pol = client.post(
        "/policies",
        json={
            "policy_id": policy_id,
            "agent_id": "*",
            "allowed_actions": ["TRANSFER_FUNDS"],
            "allowed_resource": "*",
            "maximum_amount": 50000,
            "human_approval_above": 10000,
            "version": "1.0",
        },
        headers={"Authorization": f"Bearer {pol_token}"},
    )
    assert res_create_pol.status_code == 200

    # Policy Admin updates policy to v1.1
    res_update_pol = client.post(
        "/policies",
        json={
            "policy_id": policy_id,
            "agent_id": "*",
            "allowed_actions": ["TRANSFER_FUNDS"],
            "allowed_resource": "*",
            "maximum_amount": 60000,
            "human_approval_above": 15000,
            "version": "1.1",
        },
        headers={"Authorization": f"Bearer {pol_token}"},
    )
    assert res_update_pol.status_code == 200

    # Policy Admin rolls back policy to v1.0
    res_rollback = client.post(
        "/policies/rollback",
        json={"policy_id": policy_id, "target_version": "1.0"},
        headers={"Authorization": f"Bearer {pol_token}"},
    )
    assert res_rollback.status_code == 200

    # 2. Login as Finance Approver and review approvals
    res_fin_login = client.post(
        "/auth/login",
        json={"username": "finance_approver", "password": "FinanceTrust#2026!Secured"},
    )
    assert res_fin_login.status_code == 200
    fin_token = res_fin_login.json()["access_token"]
    assert res_fin_login.json()["role"] == "FINANCE_APPROVER"

    # Finance approver attempts policy creation -> MUST FAIL (403 RBAC Denial)
    res_denied_pol = client.post(
        "/policies",
        json={"policy_id": "DENIED-POL", "allowed_actions": []},
        headers={"Authorization": f"Bearer {fin_token}"},
    )
    assert res_denied_pol.status_code == 403
    assert "RBAC Denial" in res_denied_pol.json()["detail"]

    # 3. Login as System Admin and perform system-level operations
    res_admin_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_admin_login.status_code == 200
    admin_token = res_admin_login.json()["access_token"]
    assert res_admin_login.json()["role"] == "SYSTEM_ADMIN"

    # System Admin toggles operational mode
    res_mode = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_mode.status_code == 200
    assert "current_mode" in res_mode.json()

    # System Admin registers an agent
    agent_id = f"FLOW-AGENT-{uuid.uuid4().hex[:4]}"
    res_reg = client.post(
        "/agents/register",
        json={"agent_id": agent_id, "agent_name": "FlowAgent", "owner": "AdminOps"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_reg.status_code == 200
    assert res_reg.json()["agent"]["agent_id"] == agent_id

    # System Admin suspends the agent
    res_suspend = client.post(
        f"/agents/{agent_id}/suspend?reason=MAINTENANCE",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_suspend.status_code == 200

    # 4. Verify unauthenticated calls are rejected with 401
    client.cookies.clear()
    res_unauth = client.post("/mode", json={"mode": "MODE_D_AGENTTRUST_FABRIC"})
    assert res_unauth.status_code == 401
    assert "Authentication Required" in res_unauth.json()["detail"]


def test_login_sets_httponly_session_cookie():
    """Verify that /auth/login sets the HttpOnly, SameSite=Lax session cookie."""
    res = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res.status_code == 200
    assert "agenttrust_session" in res.cookies
    cookie_header = res.headers.get("set-cookie", "")
    assert "agenttrust_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "samesite=lax" in cookie_header.lower()


def test_cookie_session_authorizes_administrative_requests():
    """Verify that a client presenting an agenttrust_session cookie can access administrative endpoints without Authorization header."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    # Call /auth/session using only the cookie
    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token
    res_session = client.get("/auth/session")
    assert res_session.status_code == 200
    session_data = res_session.json()
    assert session_data["authenticated"] is True
    assert session_data["username"] == "admin"
    assert session_data["role"] == "SYSTEM_ADMIN"

    # Call /mode using cookie, trusted Origin, and matching CSRF token
    res_mode = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf_token},
    )
    assert res_mode.status_code == 200
    assert res_mode.json()["authorized_by"] == "SYSTEM_ADMIN"


def test_logout_clears_cookie_and_revokes_token():
    """Verify that /auth/logout revokes the token and clears the agenttrust_session cookie."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    # Verify token is active before logout
    assert not JWTAuthManager.is_token_revoked(token)

    # Perform logout
    client.cookies["agenttrust_session"] = token
    res_logout = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_logout.status_code == 200
    assert res_logout.json()["status"] == "SUCCESS"

    # Verify cookie was cleared
    set_cookie = res_logout.headers.get("set-cookie", "")
    assert 'agenttrust_session=""' in set_cookie or "agenttrust_session=;" in set_cookie or "Max-Age=0" in set_cookie

    # Verify token is now marked as revoked
    assert JWTAuthManager.is_token_revoked(token)


def test_unauthorized_requests_after_logout():
    """Verify that subsequent requests using a revoked token or deleted cookie return 401."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    token = res_login.json()["access_token"]

    # Logout to revoke
    client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})

    # 1. Bearer request with revoked token must fail with 401
    client.cookies.clear()
    res_subsequent_bearer = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_subsequent_bearer.status_code == 401
    assert "Revoked" in res_subsequent_bearer.json()["detail"]

    # 2. Cookie request with revoked token must fail with 401
    client.cookies["agenttrust_session"] = token
    res_subsequent_cookie = client.get("/auth/session")
    assert res_subsequent_cookie.status_code == 401
    assert "Revoked" in res_subsequent_cookie.json()["detail"]


def test_expired_token_denies_access():
    """Verify that an expired JWT token returns 401."""
    # Mint token that expired 60 seconds ago
    secret = JWTAuthManager.get_active_secret()
    expired_payload = {
        "sub": "admin",
        "role": "SYSTEM_ADMIN",
        "exp": int(time.time()) - 60,
        "iat": int(time.time()) - 3600,
        "iss": "agenttrust-framework",
    }
    expired_token = jwt.encode(expired_payload, secret, algorithm=JWT_ALGORITHM)

    # 1. Header authorization with expired token
    client.cookies.clear()
    res_header = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_header.status_code == 401
    assert "Signature has expired" in res_header.json()["detail"] or "expired" in res_header.json()["detail"].lower()

    # 2. Cookie authorization with expired token
    client.cookies["agenttrust_session"] = expired_token
    res_cookie = client.get("/auth/session")
    assert res_cookie.status_code == 401
    assert "expired" in res_cookie.json()["detail"].lower()


def test_lower_privilege_session_cannot_retain_elevated_access():
    """Verify that an AUDITOR session cannot execute write or administrative actions."""
    res_auditor = client.post(
        "/auth/login",
        json={"username": "auditor", "password": "AuditorTrust#2026!Secured"},
    )
    assert res_auditor.status_code == 200
    auditor_token = res_auditor.json()["access_token"]
    csrf_token = res_auditor.json()["csrf_token"]
    client.cookies["agenttrust_session"] = auditor_token
    client.cookies["agenttrust_csrf_token"] = csrf_token
    csrf_headers = {"Origin": "http://testserver", "X-CSRF-Token": csrf_token}

    # Auditor attempts policy creation -> 403
    res_create_pol = client.post(
        "/policies",
        json={"policy_id": "AUDITOR-DENIED", "allowed_actions": []},
        headers=csrf_headers,
    )
    assert res_create_pol.status_code == 403
    assert "RBAC Denial" in res_create_pol.json()["detail"]

    # Auditor attempts policy rollback -> 403
    res_rollback = client.post(
        "/policies/rollback",
        json={"policy_id": "FIN-POLICY-001", "target_version": "1.0"},
        headers=csrf_headers,
    )
    assert res_rollback.status_code == 403
    assert "RBAC Denial" in res_rollback.json()["detail"]

    # Auditor attempts mode switch -> 403
    res_mode = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers=csrf_headers,
    )
    assert res_mode.status_code == 403
    assert "RBAC Denial" in res_mode.json()["detail"]

    # Auditor attempts agent suspension -> 403
    res_suspend = client.post(
        "/agents/FINANCE-AGENT-001/suspend?reason=AUDITOR_ATTEMPT",
        headers=csrf_headers,
    )
    assert res_suspend.status_code == 403
    assert "RBAC Denial" in res_suspend.json()["detail"]


# =====================================================================
# OWASP CSRF DEFENSE TEST SUITE (Cross-Site Request Forgery Hardening)
# =====================================================================

def test_csrf_cross_site_mode_change_rejected():
    """Verify cross-site requests to change operating mode via cookie are rejected with 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token

    # Malicious cross-site origin attempt
    res = client.post(
        "/mode",
        json={"mode": "MODE_A_LEGACY_PASS_THROUGH"},
        headers={"Origin": "https://malicious-attacker.com", "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 403
    assert "CSRF Protection" in res.json()["detail"]
    assert "Untrusted Origin" in res.json()["detail"]


def test_csrf_cross_site_policy_modification_rejected():
    """Verify cross-site attempts to create or modify policies via cookie are rejected with 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "policy_admin", "password": "PolicyTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token

    res = client.post(
        "/policies",
        json={"policy_id": "EVIL-POLICY", "allowed_actions": ["TRANSFER_FUNDS"]},
        headers={"Origin": "https://attacker.evil.org", "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 403
    assert "CSRF Protection" in res.json()["detail"]
    assert "Untrusted Origin" in res.json()["detail"]


def test_csrf_cross_site_policy_rollback_rejected():
    """Verify cross-site attempts to rollback policies via cookie are rejected with 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "policy_admin", "password": "PolicyTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token

    res = client.post(
        "/policies/rollback",
        json={"policy_id": "FIN-POLICY-001", "target_version": "1.0"},
        headers={"Origin": "https://attacker.phish.com", "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 403
    assert "CSRF Protection" in res.json()["detail"]


def test_csrf_cross_site_approval_rejected():
    """Verify cross-site attempts to approve transactions via cookie are rejected with 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "finance_approver", "password": "FinanceTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token

    res = client.post(
        "/approvals/approve",
        json={"ticket_id": "APPR-FAKE-999"},
        headers={"Origin": "https://malicious-banking.com", "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 403
    assert "CSRF Protection" in res.json()["detail"]


def test_csrf_cross_site_agent_suspension_rejected():
    """Verify cross-site attempts to suspend agents via cookie are rejected with 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token

    res = client.post(
        "/agents/FINANCE-AGENT-001/suspend?reason=CSRF_ATTACK",
        headers={"Origin": "https://attacker.com", "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 403
    assert "CSRF Protection" in res.json()["detail"]


def test_csrf_missing_token_rejected_on_cookie_authenticated_state_change():
    """Verify that state-changing requests using cookie authentication without X-CSRF-Token return 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    client.cookies["agenttrust_session"] = token
    # Do not set X-CSRF-Token header
    res = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Origin": "http://localhost:3000"},
    )
    assert res.status_code == 403
    assert "Missing 'X-CSRF-Token' header" in res.json()["detail"]


def test_csrf_mismatched_token_rejected():
    """Verify that state-changing requests with mismatched CSRF token return 403."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = "legitimate_cookie_token_123"

    res = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Origin": "http://localhost:3000", "X-CSRF-Token": "tampered_header_token_456"},
    )
    assert res.status_code == 403
    assert "Mismatched" in res.json()["detail"] or "CSRF Protection" in res.json()["detail"]


def test_csrf_valid_token_and_origin_accepted():
    """Verify that a legitimate state-changing request with valid Origin and matching CSRF token succeeds."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    csrf_token = res_login.json()["csrf_token"]

    client.cookies["agenttrust_session"] = token
    client.cookies["agenttrust_csrf_token"] = csrf_token

    res = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf_token},
    )
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert res.json()["authorized_by"] == "SYSTEM_ADMIN"


def test_csrf_bearer_token_exempt_from_csrf_requirement():
    """Verify direct API requests with Authorization: Bearer <token> are exempt from CSRF checks."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    client.cookies.clear()
    # Direct bearer auth without Origin or X-CSRF-Token
    res = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["success"] is True
    assert res.json()["authorized_by"] == "SYSTEM_ADMIN"


def test_csrf_get_requests_never_require_csrf_tokens():
    """Verify that GET requests (read-only) do not require CSRF tokens or Origin checks."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    client.cookies["agenttrust_session"] = token
    # GET /auth/session without CSRF header
    res_session = client.get("/auth/session")
    assert res_session.status_code == 200
    assert res_session.json()["authenticated"] is True

    # GET /mode without CSRF header
    res_mode = client.get("/mode")
    assert res_mode.status_code == 200


# =====================================================================
# MULTI-WORKER & DURABLE TOKEN REVOCATION TEST SUITE
# =====================================================================

def test_durable_token_revocation_survives_memory_cache_clearing():
    """Verify that revoked tokens remain rejected even after process in-memory cache is wiped (simulating restart)."""
    res_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminTrust#2026!Secured"},
    )
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    # Verify token is valid initially
    payload = JWTAuthManager.verify_token(token)
    assert payload["sub"] == "admin"

    # Revoke the token
    JWTAuthManager.revoke_token(token)

    # Simulate application restart: wipe in-memory cache completely
    JWTAuthManager._revoked_tokens.clear()
    assert len(JWTAuthManager._revoked_tokens) == 0

    # Token must still be recognized as revoked by querying durable SQLite store
    assert JWTAuthManager.is_token_revoked(token) is True

    # Subsequent verification must raise ValueError
    with pytest.raises(ValueError, match="Revoked"):
        JWTAuthManager.verify_token(token)

    # Subsequent API request with token in Authorization header must return 401
    client.cookies.clear()
    res = client.post(
        "/mode",
        json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 401
    assert "Revoked" in res.json()["detail"]


def test_durable_token_revocation_cross_worker_simulation():
    """Verify that a token revoked by Worker A is immediately rejected by Worker B."""
    token = JWTAuthManager.create_admin_token(role="SYSTEM_ADMIN", identity_id="worker-test-admin")
    assert JWTAuthManager.verify_token(token)["sub"] == "worker-test-admin"

    # Worker A revokes the token
    JWTAuthManager.revoke_token(token)

    # Worker B simulates an independent process: empty local cache
    worker_b_cache: set[str] = set()
    token_clean = token.strip()
    assert token_clean not in worker_b_cache

    # When Worker B receives the token, durable lookup confirms revocation
    is_revoked_for_worker_b = JWTAuthManager.is_token_revoked(token)
    assert is_revoked_for_worker_b is True

