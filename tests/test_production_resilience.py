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
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_URL": "",
        }
        with patch.dict(os.environ, env):
            with self.assertRaises(RuntimeError) as ctx:
                validate_production_configuration("production", "MODE_D_AGENTTRUST_FABRIC")
            self.assertIn("requires explicit FABRIC_GATEWAY_URL", str(ctx.exception))

    def test_production_mode_d_succeeds_with_valid_configuration(self):
        """Verifies Mode D in production succeeds when live mode and gateway URL are configured."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "secure-prod-token-xyz-1234567890",
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090",
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
            "CORS_ORIGINS": "https://agenttrust.corp.internal",
        }
        with patch.dict(os.environ, env, clear=False):
            validate_production_configuration(
                "production", "MODE_C_AGENTTRUST_NO_FABRIC"
            )


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
        self.assertTrue(res["fabric_pending_retry"])
        self.assertTrue(res["fabric_submission_uncertain"])


if __name__ == "__main__":
    unittest.main()

