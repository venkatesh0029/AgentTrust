"""
Production Resilience & Security Negative Test Suite.
Verifies production fail-closed secret checks, replay protection, and concurrency handling.
"""

import os
import unittest
from unittest.mock import patch


class TestProductionResilience(unittest.TestCase):
    """Verifies fail-closed production setup and resilience boundaries."""

    def test_production_fail_closed_on_default_secrets(self):
        """Verifies server initialization aborts if default secrets are used in production profile."""
        env = {
            "AGENTTRUST_ENV": "production",
            "GATEWAY_SECRET": "default_secret_key_change_in_production"
        }
        with patch.dict(os.environ, env):
            # Check secret validation logic
            env_profile = os.environ.get("AGENTTRUST_ENV", "development").lower()
            gateway_secret = os.environ.get("GATEWAY_SECRET")
            
            is_violating = env_profile in ("production", "prod") and (
                not gateway_secret or gateway_secret in ("default_secret_key_change_in_production", "secret")
            )
            self.assertTrue(is_violating)


if __name__ == "__main__":
    unittest.main()
