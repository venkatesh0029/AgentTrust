import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from server import app, get_cors_origins


class TestCorsSecurity(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_default_origins_are_explicit(self):
        with patch.dict(os.environ, {}, clear=True):
            origins = get_cors_origins()

        self.assertEqual(
            origins,
            ["http://localhost:3000", "http://127.0.0.1:3000"],
        )
        self.assertNotIn("*", origins)

    def test_wildcard_origin_is_rejected(self):
        with patch.dict(
            os.environ,
            {"CORS_ORIGINS": "http://localhost:3000,*"},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                get_cors_origins()

    def test_empty_origin_configuration_is_rejected(self):
        with patch.dict(os.environ, {"CORS_ORIGINS": " , "}, clear=False):
            with self.assertRaises(RuntimeError):
                get_cors_origins()

    def test_allowed_origin_preflight(self):
        response = self.client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "http://localhost:3000",
        )
        self.assertEqual(
            response.headers.get("access-control-allow-credentials"),
            "true",
        )

    def test_untrusted_origin_preflight_is_not_allowed(self):
        response = self.client.options(
            "/api/health",
            headers={
                "Origin": "http://untrusted-attacker.com",
                "Access-Control-Request-Method": "GET",
            },
        )

        self.assertNotIn(
            "access-control-allow-origin",
            response.headers,
        )


if __name__ == "__main__":
    unittest.main()
