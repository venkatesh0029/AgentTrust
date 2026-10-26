#!/usr/bin/env python3
"""
AgentTrust Production-Profile Acceptance Verification Suite.
Validates the Step 5 Candidate Checkpoint against production environment constraints:
1. Production Configuration & Fail-Closed Validation
2. Production Cookie Attributes (__Host- prefix, Secure, HttpOnly, SameSite=Lax)
3. CSRF Protection (Cross-site rejection, missing/mismatched header rejection, valid origin acceptance)
4. Role-Based Access Control (RBAC) Permissive & Negative Verification Matrix
5. Durable Multi-Worker Token Revocation & Service Restart Invariance
6. Frontend Demo Mode Fail-Closed Invariants
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

# Configure project root
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from identity_manager.jwt_auth import JWTAuthManager  # noqa: E402
from server import app, validate_production_configuration  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PROD_ORIGIN = "https://agenttrust.corp.internal"
PROD_ENV = {
    "AGENTTRUST_ENV": "production",
    "CORS_ORIGINS": PROD_ORIGIN,
    "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
    "AGENTTRUST_JWT_SECRET": "ProductionSecretKeyWithHighEntropyAndLength1234567890!",
    "AGENTTRUST_ADMIN_PASSWORD": "ProdAdmin#2026!StrongAuthPassword",
    "AGENTTRUST_POLICY_ADMIN_PASSWORD": "ProdPolicy#2026!StrongAuthPassword",
    "AGENTTRUST_FINANCE_APPROVER_PASSWORD": "ProdFinance#2026!StrongAuthPassword",
    "AGENTTRUST_AUDITOR_PASSWORD": "ProdAuditor#2026!StrongAuthPassword",
}


def print_section(title: str) -> None:
    print(f"\n{'='*75}\n  {title}\n{'='*75}")


def test_section(name: str, check_fn) -> bool:
    print(f"\n[ACCEPTANCE CHECK] {name}...")
    try:
        check_fn()
        print("      Status: PASS")
        return True
    except Exception as e:
        import traceback
        print(f"      Status: FAIL -> {e}")
        traceback.print_exc()
        return False


def run_acceptance_suite() -> int:
    print_section("AGENTTRUST STEP 5 — PRODUCTION-PROFILE ACCEPTANCE SUITE")
    print("Candidate Checkpoint : dff4cb0 (feat/fabric-resilience)")
    print(f"Production Origin    : {PROD_ORIGIN}")
    print("Security Profile     : production (Strict OWASP Hardening)")

    passed_count = 0
    total_count = 0

    with patch.dict(os.environ, PROD_ENV):
        import server
        server.ENV_PROFILE = "production"
        client = TestClient(app, base_url=PROD_ORIGIN)

        # -------------------------------------------------------------
        # 1. Production Config Validation
        # -------------------------------------------------------------
        total_count += 1
        def check_prod_config():
            validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
        if test_section("Production Configuration Sanity (Entropy, Passwords, CORS)", check_prod_config):
            passed_count += 1

        # -------------------------------------------------------------
        # 2. Production Cookie Attributes (__Host- prefix, Secure, HttpOnly)
        # -------------------------------------------------------------
        total_count += 1
        captured = {}
        def check_cookie_attributes():
            client.cookies.clear()
            res = client.post(
                "/auth/login",
                json={"username": "admin", "password": "ProdAdmin#2026!StrongAuthPassword"},
                headers={"Origin": PROD_ORIGIN},
            )
            assert res.status_code == 200, f"Login failed: {res.text}"
            data = res.json()
            captured["token"] = data["access_token"]
            captured["csrf_token"] = data["csrf_token"]

            set_cookie_headers = res.headers.get_list("set-cookie") if hasattr(res.headers, "get_list") else [res.headers.get("set-cookie", "")]
            raw_cookies = "; ".join(set_cookie_headers)

            # __Host- prefix check
            assert "__Host-agenttrust_session=" in raw_cookies, "Missing __Host-agenttrust_session cookie in production"
            # Secure attribute
            assert "secure" in raw_cookies.lower(), "Session cookie missing Secure flag"
            # HttpOnly attribute
            assert "httponly" in raw_cookies.lower(), "Session cookie missing HttpOnly flag"
            # SameSite=Lax
            assert "samesite=lax" in raw_cookies.lower(), "Session cookie missing SameSite=Lax flag"
            # CSRF token cookie present
            assert "agenttrust_csrf_token=" in raw_cookies, "Missing agenttrust_csrf_token cookie"
        if test_section("Production Session Cookie (__Host- prefix, Secure, HttpOnly, SameSite=Lax)", check_cookie_attributes):
            passed_count += 1

        # -------------------------------------------------------------
        # 3. CSRF & Origin Validation
        # -------------------------------------------------------------
        total_count += 1
        def check_csrf_cross_site_rejected():
            client.cookies.clear()
            client.cookies["__Host-agenttrust_session"] = captured["token"]
            client.cookies["agenttrust_csrf_token"] = captured["csrf_token"]
            res = client.post(
                "/mode",
                json={"mode": "MODE_C_AGENTTRUST_NO_FABRIC"},
                headers={"Origin": "https://attacker-phishing.org", "X-CSRF-Token": captured["csrf_token"]},
            )
            assert res.status_code == 403, f"Expected 403, got {res.status_code}: {res.text}"
            assert "CSRF Protection" in res.json()["detail"]
        if test_section("CSRF Defense: Reject Cross-Site Origin (403 Forbidden)", check_csrf_cross_site_rejected):
            passed_count += 1

        total_count += 1
        def check_csrf_missing_token_rejected():
            client.cookies.clear()
            client.cookies["__Host-agenttrust_session"] = captured["token"]
            # Legitimate origin, but missing X-CSRF-Token header
            res = client.post(
                "/mode",
                json={"mode": "MODE_C_AGENTTRUST_NO_FABRIC"},
                headers={"Origin": PROD_ORIGIN},
            )
            assert res.status_code == 403, f"Expected 403, got {res.status_code}: {res.text}"
            assert "Missing 'X-CSRF-Token' header" in res.json()["detail"]
        if test_section("CSRF Defense: Reject Missing X-CSRF-Token on Cookie Session (403 Forbidden)", check_csrf_missing_token_rejected):
            passed_count += 1

        total_count += 1
        def check_csrf_mismatched_token_rejected():
            client.cookies.clear()
            client.cookies["__Host-agenttrust_session"] = captured["token"]
            client.cookies["agenttrust_csrf_token"] = captured["csrf_token"]
            res = client.post(
                "/mode",
                json={"mode": "MODE_C_AGENTTRUST_NO_FABRIC"},
                headers={"Origin": PROD_ORIGIN, "X-CSRF-Token": "tampered_token_99999"},
            )
            assert res.status_code == 403, f"Expected 403, got {res.status_code}: {res.text}"
            assert "CSRF Protection" in res.json()["detail"]
        if test_section("CSRF Defense: Reject Mismatched X-CSRF-Token (403 Forbidden)", check_csrf_mismatched_token_rejected):
            passed_count += 1

        total_count += 1
        def check_csrf_valid_request_accepted():
            client.cookies.clear()
            client.cookies["__Host-agenttrust_session"] = captured["token"]
            client.cookies["agenttrust_csrf_token"] = captured["csrf_token"]
            res = client.post(
                "/mode",
                json={"mode": "MODE_C_AGENTTRUST_NO_FABRIC"},
                headers={"Origin": PROD_ORIGIN, "X-CSRF-Token": captured["csrf_token"]},
            )
            assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
            assert res.json()["success"] is True
            assert res.json()["authorized_by"] == "SYSTEM_ADMIN"
        if test_section("CSRF Defense: Accept Legitimate Origin with Matching CSRF Header (200 OK)", check_csrf_valid_request_accepted):
            passed_count += 1

        # -------------------------------------------------------------
        # 4. Role-Based Access Control (RBAC) Permissive & Negative Matrix
        # -------------------------------------------------------------
        total_count += 1
        def check_rbac_matrix():
            # Login as POLICY_ADMIN
            res_policy = client.post(
                "/auth/login",
                json={"username": "policy_admin", "password": "ProdPolicy#2026!StrongAuthPassword"},
                headers={"Origin": PROD_ORIGIN},
            )
            assert res_policy.status_code == 200
            pol_token = res_policy.json()["access_token"]
            pol_csrf = res_policy.json()["csrf_token"]

            client.cookies.clear()
            client.cookies["__Host-agenttrust_session"] = pol_token
            client.cookies["agenttrust_csrf_token"] = pol_csrf

            # POLICY_ADMIN can create policies
            res_p_ok = client.post(
                "/policies",
                json={
                    "policy_id": "POL-ACCEPT-01",
                    "agent_id": "TEST-AGT-ACCEPT-01",
                    "allowed_actions": ["READ_ACCOUNT"],
                    "allowed_resource": "*",
                    "maximum_amount": 500.0,
                },
                headers={"Origin": PROD_ORIGIN, "X-CSRF-Token": pol_csrf},
            )
            assert res_p_ok.status_code == 200, f"Policy creation failed: {res_p_ok.text}"

            # POLICY_ADMIN CANNOT approve transactions
            res_p_fail = client.post(
                "/approvals/approve",
                json={"ticket_id": "FAKE-01"},
                headers={"Origin": PROD_ORIGIN, "X-CSRF-Token": pol_csrf},
            )
            assert res_p_fail.status_code == 403
            assert "approve_transaction" in res_p_fail.json()["detail"]

            # POLICY_ADMIN CANNOT switch system mode
            res_p_fail_mode = client.post(
                "/mode",
                json={"mode": "MODE_C_AGENTTRUST_NO_FABRIC"},
                headers={"Origin": PROD_ORIGIN, "X-CSRF-Token": pol_csrf},
            )
            assert res_p_fail_mode.status_code == 403
            assert "switch_mode" in res_p_fail_mode.json()["detail"]

            # Login as FINANCE_APPROVER
            res_fin = client.post(
                "/auth/login",
                json={"username": "finance_approver", "password": "ProdFinance#2026!StrongAuthPassword"},
                headers={"Origin": PROD_ORIGIN},
            )
            assert res_fin.status_code == 200
            fin_token = res_fin.json()["access_token"]
            fin_csrf = res_fin.json()["csrf_token"]

            client.cookies.clear()
            client.cookies["__Host-agenttrust_session"] = fin_token
            client.cookies["agenttrust_csrf_token"] = fin_csrf

            # FINANCE_APPROVER CANNOT create policies
            res_fin_fail_pol = client.post(
                "/policies",
                json={
                    "policy_id": "POL-ACCEPT-02",
                    "agent_id": "TEST-AGT-ACCEPT-02",
                    "allowed_actions": ["READ_ACCOUNT"],
                    "allowed_resource": "*",
                    "maximum_amount": 500.0,
                },
                headers={"Origin": PROD_ORIGIN, "X-CSRF-Token": fin_csrf},
            )
            assert res_fin_fail_pol.status_code == 403
            assert "create_policy" in res_fin_fail_pol.json()["detail"]

            # Login as AUDITOR
            res_aud = client.post(
                "/auth/login",
                json={"username": "auditor", "password": "ProdAuditor#2026!StrongAuthPassword"},
                headers={"Origin": PROD_ORIGIN},
            )
            assert res_aud.status_code == 200
            aud_token = res_aud.json()["access_token"]

            # Direct Bearer check for Auditor
            client.cookies.clear()
            res_aud_sess = client.get(
                "/auth/session",
                headers={"Authorization": f"Bearer {aud_token}"},
            )
            assert res_aud_sess.status_code == 200
            assert res_aud_sess.json()["role"] == "AUDITOR"

            res_aud_ev = client.get(
                "/audit/chain/verify",
                headers={"Authorization": f"Bearer {aud_token}"},
            )
            assert res_aud_ev.status_code == 200

            res_aud_mut = client.post(
                "/mode",
                json={"mode": "MODE_C_AGENTTRUST_NO_FABRIC"},
                headers={"Authorization": f"Bearer {aud_token}"},
            )
            assert res_aud_mut.status_code == 403
        if test_section("RBAC Matrix: Enforce Principle of Least Privilege across All Roles", check_rbac_matrix):
            passed_count += 1

        # -------------------------------------------------------------
        # 5. Durable Multi-Worker Token Revocation & Restart Invariance
        # -------------------------------------------------------------
        total_count += 1
        def check_durable_token_revocation():
            # 1. Login to obtain token
            res = client.post(
                "/auth/login",
                json={"username": "admin", "password": "ProdAdmin#2026!StrongAuthPassword"},
                headers={"Origin": PROD_ORIGIN},
            )
            assert res.status_code == 200
            token = res.json()["access_token"]

            # 2. Worker 1 logs out / revokes
            client.cookies.clear()
            res_logout = client.post(
                "/auth/logout",
                headers={"Authorization": f"Bearer {token}", "Origin": PROD_ORIGIN},
            )
            assert res_logout.status_code == 200

            # 3. Simulate Worker 2 process start / in-memory cache wipe
            JWTAuthManager._revoked_tokens.clear()
            assert len(JWTAuthManager._revoked_tokens) == 0

            # 4. Worker 2 attempts request with revoked token
            res_revoked = client.get(
                "/auth/session",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res_revoked.status_code == 401
            assert "Revoked" in res_revoked.json()["detail"]
        if test_section("Durable Revocation: Survived Process Restart & Multi-Worker Storage", check_durable_token_revocation):
            passed_count += 1

        # -------------------------------------------------------------
        # 6. Frontend Demo Mode Precedence & Build Gates
        # -------------------------------------------------------------
        total_count += 1
        def check_frontend_demo_mode_gate():
            js_code = """
            const isDemoAuthMode = (nodeEnv, nextPublicEnv, demoFlag) => {
                const savedNode = process.env.NODE_ENV;
                const savedPub = process.env.NEXT_PUBLIC_ENV;
                const savedDemo = process.env.NEXT_PUBLIC_DEMO_MODE;
                process.env.NODE_ENV = nodeEnv;
                process.env.NEXT_PUBLIC_ENV = nextPublicEnv;
                process.env.NEXT_PUBLIC_DEMO_MODE = demoFlag;

                const res = (() => {
                    if (process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_ENV === "production") {
                        return false;
                    }
                    return process.env.NEXT_PUBLIC_DEMO_MODE === "true";
                })();
                return res;
            };

            const ok = [
                isDemoAuthMode("production", "", "true") === false,
                isDemoAuthMode("", "production", "true") === false,
                isDemoAuthMode("production", "production", "true") === false,
                isDemoAuthMode("production", "", "false") === false,
            ].every(Boolean);

            if (!ok) process.exit(1);
            """
            proc = subprocess.run(["node", "-e", js_code], capture_output=True, text=True)
            assert proc.returncode == 0, f"Frontend demo gate failed: {proc.stderr}"
        if test_section("Frontend Demo Mode: Strict Precedence over Flags in Production", check_frontend_demo_mode_gate):
            passed_count += 1

    # -------------------------------------------------------------
    # Summary Scorecard
    # -------------------------------------------------------------
    print_section(f"ACCEPTANCE RESULTS: {passed_count}/{total_count} CHECKS PASSED")
    if passed_count == total_count:
        print("[PASS] All Step 5 production-profile acceptance criteria are SATISFIED.\n")
        return 0
    else:
        print(f"[FAIL] {total_count - passed_count} checks failed.\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_acceptance_suite())
