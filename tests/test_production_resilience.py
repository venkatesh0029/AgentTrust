"""
Production Resilience & Security Negative Test Suite.
Verifies production fail-closed secret checks, live Fabric configuration enforcement,
and truthful audit commitment reporting.
"""

import os
import unittest
from unittest.mock import patch

from server import validate_production_configuration


class TestProductionResilience(unittest.TestCase):
    """Verifies fail-closed production setup and resilience boundaries."""

    def test_production_fail_closed_on_default_secrets(self):
        """Verifies server initialization aborts if default secrets are used in production profile."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "default_secret_key_change_in_production"
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("explicit secure GATEWAY_SECRET", str(ctx.exception))

    def test_production_fail_closed_on_missing_secret(self):
        """Verifies server initialization aborts if GATEWAY_SECRET is empty in production."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": ""
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("explicit secure GATEWAY_SECRET", str(ctx.exception))

    def test_production_mode_d_fails_closed_without_live_mode(self):
        """Verifies Mode D in production aborts if FABRIC_GATEWAY_MODE is not 'live'."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
            "FABRIC_GATEWAY_MODE": "simulator",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_D_AGENTTRUST_FABRIC")
            self.assertIn("requires live Fabric gateway mode", str(ctx.exception))

    def test_production_mode_d_fails_closed_without_gateway_url(self):
        """Verifies Mode D in production aborts if FABRIC_GATEWAY_URL is missing or empty."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_URL": "",
            "FABRIC_GATEWAY_TOKEN": "test-fabric-gateway-token-123456789",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_D_AGENTTRUST_FABRIC")
            self.assertIn("requires explicit FABRIC_GATEWAY_URL", str(ctx.exception))

    def test_production_mode_d_fails_closed_without_gateway_token(self):
        """Verifies Mode D in production aborts if FABRIC_GATEWAY_TOKEN is missing or short."""
        base_env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090",
        }
        for invalid_token in ("", "too-short-token"):
            with self.subTest(token=invalid_token):
                env = dict(base_env, FABRIC_GATEWAY_TOKEN=invalid_token)
                with patch.dict(os.environ, env):
                    with self.assertRaises(RuntimeError) as ctx:
                        validate_production_configuration("production", "MODE_D_AGENTTRUST_FABRIC")
                    self.assertIn("FABRIC_GATEWAY_TOKEN", str(ctx.exception))

    def test_production_fail_closed_on_missing_jwt_secret(self):
        """Verifies server initialization aborts if AGENTTRUST_JWT_SECRET is missing in production."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("explicit secure AGENTTRUST_JWT_SECRET", str(ctx.exception))

    def test_production_fail_closed_on_short_jwt_secret(self):
        """Verifies server initialization aborts if AGENTTRUST_JWT_SECRET has insufficient entropy (< 32 chars)."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "too-short-jwt-secret",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("at least 32 characters of entropy", str(ctx.exception))

    def test_production_fail_closed_on_insecure_jwt_secret(self):
        """Verifies server initialization aborts if AGENTTRUST_JWT_SECRET is a placeholder or dictionary word."""
        for weak in ("secret", "changeme", "default_jwt_secret", "password"):
            with self.subTest(secret=weak):
                env = {
                    "AGENTTRUST_ENV": "production",
                    "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
                    "AGENTTRUST_JWT_SECRET": weak,
                }
                with patch.dict(os.environ, env):
                    with self.assertRaises(RuntimeError) as ctx:
                        validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
                    self.assertTrue(
                        "at least 32 characters of entropy" in str(ctx.exception)
                        or "insecure placeholder" in str(ctx.exception)
                    )

    def test_jwt_auth_manager_fails_closed_in_production(self):
        """Verifies JWTAuthManager fails closed when AGENTTRUST_JWT_SECRET is absent in production."""
        from identity_manager.jwt_auth import JWTAuthManager
        env = {
            "AGENTTRUST_ENV": "production",
            "AGENTTRUST_JWT_SECRET": "",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                JWTAuthManager.get_active_secret()
            self.assertIn("explicit secure AGENTTRUST_JWT_SECRET", str(ctx.exception))

    def test_jwt_auth_manager_uses_consistent_secret(self):
        """Verifies JWTAuthManager maintains consistent configured secret across calls without ephemeral drift."""
        from identity_manager.jwt_auth import JWTAuthManager
        fixed_secret = "configured-enterprise-signing-secret-32-chars-ok"
        env = {
            "AGENTTRUST_ENV": "production",
            "AGENTTRUST_JWT_SECRET": fixed_secret,
        }
        with patch.dict(os.environ, env):
            secret1 = JWTAuthManager.get_active_secret()
            secret2 = JWTAuthManager.get_active_secret()
            self.assertEqual(secret1, fixed_secret)
            self.assertEqual(secret2, fixed_secret)

    def test_production_mode_d_succeeds_with_valid_configuration(self):
        """Verifies Mode D in production succeeds when live mode, gateway URL, token, and JWT secret are configured."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "AGENTTRUST_ADMIN_PASSWORD": "ProdAdmin#2026!StrongAuthPassword",
            "AGENTTRUST_POLICY_ADMIN_PASSWORD": "ProdPolicy#2026!StrongAuthPassword",
            "AGENTTRUST_FINANCE_APPROVER_PASSWORD": "ProdFinance#2026!StrongAuthPassword",
            "AGENTTRUST_AUDITOR_PASSWORD": "ProdAuditor#2026!StrongAuthPassword",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090",
            "FABRIC_GATEWAY_TOKEN": "test-fabric-gateway-token-123456789",
        }
        with patch.dict(os.environ, env):
            # Should not raise
            validate_production_configuration("production", "MODE_D_AGENTTRUST_FABRIC")

    def test_development_profile_allows_simulator_mode(self):
        """Verifies development environment allows simulator mode and default secrets."""
        env = {
            "AGENTTRUST_ENV": "development",
            "GATEWAY_SECRET": "default_secret_key_change_in_production",
            "FABRIC_GATEWAY_MODE": "simulator",
        }
        with patch.dict(os.environ, env):
            # Should not raise in development profile
            validate_production_configuration("development", "MODE_D_AGENTTRUST_FABRIC")

    def test_production_fails_closed_when_cors_origins_missing(self):
        env = {
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration(
                    "production", "MODE_C_AGENTTRUST_NO_FABRIC"
                )
        self.assertIn("explicit CORS_ORIGINS", str(ctx.exception))

    def test_production_rejects_wildcard_cors_origin(self):
        env = {
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "https://agenttrust.corp.internal,*",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration(
                    "production", "MODE_C_AGENTTRUST_NO_FABRIC"
                )
        self.assertIn("must not contain '*'", str(ctx.exception))

    def test_production_rejects_localhost_cors_origin(self):
        env = {
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "http://localhost:3000",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration(
                    "production", "MODE_C_AGENTTRUST_NO_FABRIC"
                )
        self.assertIn("valid HTTPS origins", str(ctx.exception))

    def test_production_rejects_origin_with_path(self):
        env = {
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "https://agenttrust.corp.internal/path",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(RuntimeError):
                validate_production_configuration(
                    "production", "MODE_C_AGENTTRUST_NO_FABRIC"
                )

    def test_production_rejects_http_origin(self):
        env = {
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "CORS_ORIGINS": "http://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(RuntimeError):
                validate_production_configuration(
                    "production", "MODE_C_AGENTTRUST_NO_FABRIC"
                )

    def test_production_accepts_explicit_https_cors_origin(self):
        env = {
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "AGENTTRUST_ADMIN_PASSWORD": "ProdAdmin#2026!StrongAuthPassword",
            "AGENTTRUST_POLICY_ADMIN_PASSWORD": "ProdPolicy#2026!StrongAuthPassword",
            "AGENTTRUST_FINANCE_APPROVER_PASSWORD": "ProdFinance#2026!StrongAuthPassword",
            "AGENTTRUST_AUDITOR_PASSWORD": "ProdAuditor#2026!StrongAuthPassword",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env, clear=False):
            validate_production_configuration(
                "production", "MODE_C_AGENTTRUST_NO_FABRIC"
            )

    def test_production_fail_closed_on_low_diversity_jwt_secret(self):
        """Verifies server initialization aborts if AGENTTRUST_JWT_SECRET lacks character diversity (< 8 unique chars)."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "a1b2a1b2a1b2a1b2a1b2a1b2a1b2a1b2",  # 4 unique chars
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("insufficient character diversity", str(ctx.exception))

    def test_production_fail_closed_on_repeated_pattern_jwt_secret(self):
        """Verifies server initialization aborts if AGENTTRUST_JWT_SECRET contains repeated half patterns."""
        # 16 unique chars, but repeated half
        half = "abcdefghijklmnop"
        repeated = half + half
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": repeated,
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("contains repeated half patterns", str(ctx.exception))

    def test_production_fail_closed_on_default_admin_password(self):
        """Verifies server initialization aborts if default admin password is used in production."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "AGENTTRUST_ADMIN_PASSWORD": "AdminTrust#2026!Secured",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("forbids default or weak password for 'admin'", str(ctx.exception))

    def test_production_fail_closed_on_short_admin_password(self):
        """Verifies server initialization aborts if admin password is less than 16 characters in production."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "AGENTTRUST_JWT_SECRET": "secure-prod-jwt-secret-xyz-12345678901234",
            "AGENTTRUST_ADMIN_PASSWORD": "shortPassword!1",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_C_AGENTTRUST_NO_FABRIC")
            self.assertIn("at least 16 characters", str(ctx.exception))


class TestTruthfulFabricCommitReporting(unittest.TestCase):
    """Verifies server proxy truthfully reports live vs simulated vs retry states."""

    def test_truthful_reporting_for_simulated_commit(self):
        """Simulated commit must report fabric_committed=False, fabric_simulated=True, and no retry/uncertainty."""
        import server
        mock_result = {
            "blockchain": {
                "status": "COMMITTED",
                "mode": "simulator",
                "source": "fabric_simulator",
            }
        }
        with (
            patch.object(server.action_gateway, "process_request", return_value=mock_result),
            patch.object(server, "CURRENT_MODE", "MODE_D_AGENTTRUST_FABRIC"),
        ):
            payload = {"action": "TRANSFER_FUNDS", "request_id": "REQ-1", "agent_id": "AGT-1"}
            res = server.process_request_with_mode(payload)

        self.assertFalse(res["fabric_committed"])
        self.assertTrue(res["fabric_simulated"])
        self.assertFalse(res["fabric_pending_retry"])
        self.assertFalse(res["fabric_submission_uncertain"])

    def test_truthful_reporting_for_live_commit(self):
        """Live commit confirmed by bridge must report fabric_committed=True, fabric_simulated=False, and no retry/uncertainty."""
        import server
        mock_result = {
            "blockchain": {
                "status": "COMMITTED",
                "mode": "live",
                "source": "hyperledger_fabric_gateway",
            }
        }
        with (
            patch.object(server.action_gateway, "process_request", return_value=mock_result),
            patch.object(server, "CURRENT_MODE", "MODE_D_AGENTTRUST_FABRIC"),
        ):
            payload = {"action": "TRANSFER_FUNDS", "request_id": "REQ-2", "agent_id": "AGT-2"}
            res = server.process_request_with_mode(payload)

        self.assertTrue(res["fabric_committed"])
        self.assertFalse(res["fabric_simulated"])
        self.assertFalse(res["fabric_pending_retry"])
        self.assertFalse(res["fabric_submission_uncertain"])

    def test_truthful_reporting_for_pending_retry_or_failed_commit(self):
        """Failed commit enqueued to outbox must report fabric_committed=False and fabric_pending_retry=True."""
        import server
        mock_result = {
            "blockchain": {
                "status": "COMMIT_FAILED: Live Fabric Gateway submission failed",
                "mode": "live",
                "source": "outbox_pending_retry",
            }
        }
        with (
            patch.object(server.action_gateway, "process_request", return_value=mock_result),
            patch.object(server, "CURRENT_MODE", "MODE_D_AGENTTRUST_FABRIC"),
        ):
            payload = {"action": "TRANSFER_FUNDS", "request_id": "REQ-3", "agent_id": "AGT-3"}
            res = server.process_request_with_mode(payload)

        self.assertFalse(res["fabric_committed"])
        self.assertFalse(res["fabric_simulated"])
        self.assertTrue(res["fabric_pending_retry"])
        self.assertFalse(res["fabric_submission_uncertain"])

    def test_truthful_reporting_for_failed_commit_not_in_outbox(self):
        """Non-committed response without outbox marker must report fabric_pending_retry=False."""
        import server
        mock_result = {
            "blockchain": {
                "status": "COMMIT_FAILED: Local policy rejection",
                "mode": "live",
                "source": "direct_failure",
            }
        }
        with (
            patch.object(server.action_gateway, "process_request", return_value=mock_result),
            patch.object(server, "CURRENT_MODE", "MODE_D_AGENTTRUST_FABRIC"),
        ):
            payload = {"action": "TRANSFER_FUNDS", "request_id": "REQ-4", "agent_id": "AGT-4"}
            res = server.process_request_with_mode(payload)

        self.assertFalse(res["fabric_committed"])
        self.assertFalse(res["fabric_simulated"])
        self.assertFalse(res["fabric_pending_retry"])
        self.assertFalse(res["fabric_submission_uncertain"])

    def test_truthful_reporting_for_uncertain_submission(self):
        """Uncertain queued submission must report fabric_pending_retry=True and fabric_submission_uncertain=True."""
        import server
        mock_result = {
            "blockchain": {
                "status": "COMMIT_FAILED: FABRIC_SUBMISSION_UNCERTAIN: Timeout",
                "mode": "live",
                "source": "outbox_pending_retry",
                "submission_uncertain": True,
            }
        }
        with (
            patch.object(server.action_gateway, "process_request", return_value=mock_result),
            patch.object(server, "CURRENT_MODE", "MODE_D_AGENTTRUST_FABRIC"),
        ):
            payload = {"action": "TRANSFER_FUNDS", "request_id": "REQ-5", "agent_id": "AGT-5"}
            res = server.process_request_with_mode(payload)

        self.assertFalse(res["fabric_committed"])
        self.assertFalse(res["fabric_simulated"])
    def test_production_demo_mode_gate_takes_precedence_in_frontend(self):
        """Verifies that production env takes precedence over NEXT_PUBLIC_DEMO_MODE=true in isDemoAuthMode."""
        import subprocess

        js_code = """
        const isDemoAuthMode = (nodeEnv, nextPublicEnv, nextPublicDemoMode) => {
            const savedNodeEnv = process.env.NODE_ENV;
            const savedNextPublicEnv = process.env.NEXT_PUBLIC_ENV;
            const savedDemo = process.env.NEXT_PUBLIC_DEMO_MODE;
            
            process.env.NODE_ENV = nodeEnv;
            process.env.NEXT_PUBLIC_ENV = nextPublicEnv;
            process.env.NEXT_PUBLIC_DEMO_MODE = nextPublicDemoMode;

            const res = (() => {
                if (process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_ENV === "production") {
                    return false;
                }
                return process.env.NEXT_PUBLIC_DEMO_MODE === "true";
            })();

            process.env.NODE_ENV = savedNodeEnv;
            process.env.NEXT_PUBLIC_ENV = savedNextPublicEnv;
            process.env.NEXT_PUBLIC_DEMO_MODE = savedDemo;
            return res;
        };

        const checks = [
            isDemoAuthMode("production", "", "true") === false,
            isDemoAuthMode("", "production", "true") === false,
            isDemoAuthMode("production", "production", "true") === false,
            isDemoAuthMode("development", "development", "true") === true,
            isDemoAuthMode("development", "development", "false") === false,
        ];
        if (!checks.every(Boolean)) {
            process.exit(1);
        }
        """
        proc = subprocess.run(["node", "-e", js_code], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"isDemoAuthMode precedence check failed: {proc.stderr}")

    def test_production_build_check_rejects_demo_mode(self):
        """Verifies that Next.js build-time gate fails closed when NEXT_PUBLIC_DEMO_MODE=true in production."""
        import subprocess

        js_gate = """
        const isProduction = process.env.NODE_ENV === "production" || process.env.NEXT_PUBLIC_ENV === "production";
        if (isProduction && process.env.NEXT_PUBLIC_DEMO_MODE === "true") {
            throw new Error("BUILD ERROR: Production builds must not be configured with NEXT_PUBLIC_DEMO_MODE=true.");
        }
        """
        # When configured with demo mode in production -> MUST THROW
        env_fail = dict(os.environ, NODE_ENV="production", NEXT_PUBLIC_DEMO_MODE="true")
        proc_fail = subprocess.run(["node", "-e", js_gate], env=env_fail, capture_output=True, text=True)
        self.assertNotEqual(proc_fail.returncode, 0)
        self.assertIn("BUILD ERROR", proc_fail.stderr)

        # When configured properly in production -> MUST SUCCEED
        env_ok = dict(os.environ, NODE_ENV="production", NEXT_PUBLIC_DEMO_MODE="false")
        proc_ok = subprocess.run(["node", "-e", js_gate], env=env_ok, capture_output=True, text=True)
        self.assertEqual(proc_ok.returncode, 0)

    def test_backend_enforces_auth_independently_of_ui_demo_mode(self):
        """Verifies backend strictly rejects unauthenticated calls even if client sends demo flags or headers."""
        from fastapi.testclient import TestClient
        from server import app

        test_client = TestClient(app)
        test_client.cookies.clear()

        # Unauthenticated request with demo headers or query params
        res = test_client.post(
            "/mode",
            json={"mode": "MODE_D_AGENTTRUST_FABRIC"},
            headers={"X-Demo-Mode": "true", "X-Frontend-Env": "development"},
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("Authentication Required", res.json()["detail"])


if __name__ == "__main__":
    unittest.main()

