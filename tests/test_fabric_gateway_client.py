import os
import unittest
from unittest.mock import MagicMock, patch

import httpx

from fabric.fabric_client import FabricClient


class TestFabricClientGetEvent(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {"FABRIC_GATEWAY_MODE": "simulator"},
            clear=False,
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

        self.client = FabricClient()

    def test_simulator_mode_event_exists(self):
        expected = {
            "event_id": "EVT-1",
            "decision": "DENY",
            "reason": "Test event",
        }
        with patch.object(
            self.client.chaincode,
            "GetActionEvent",
            return_value=expected,
        ) as get_event:
            result = self.client.get_event("EVT-1")

        self.assertEqual(result, expected)
        get_event.assert_called_once_with("EVT-1")

    def test_simulator_mode_event_missing(self):
        with patch.object(
            self.client.chaincode,
            "GetActionEvent",
            return_value=None,
        ) as get_event:
            result = self.client.get_event("UNKNOWN-EVENT")

        self.assertIsNone(result)
        get_event.assert_called_once_with("UNKNOWN-EVENT")

    def test_live_mode_valid_response(self):
        expected = {"event_id": "EVT-1", "decision": "DENY"}
        response = MagicMock()
        response.json.return_value = {
            "status": "FOUND",
            "result": expected,
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "get", return_value=response) as get,
        ):
            response.raise_for_status.return_value = None
            result = self.client.get_event("EVT-1")

        self.assertEqual(result, expected)
        get.assert_called_once_with(
            "http://127.0.0.1:8090/v1/action-events/EVT-1"
        )

    def test_live_mode_http_502_error(self):
        response = MagicMock()
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Bad Gateway",
            request=httpx.Request(
                "GET", "http://127.0.0.1:8090/v1/action-events/EVT-1"
            ),
            response=httpx.Response(
                502,
                request=httpx.Request(
                    "GET", "http://127.0.0.1:8090/v1/action-events/EVT-1"
                ),
            ),
        )

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "get", return_value=response),
            self.assertRaises(RuntimeError),
        ):
            self.client.get_event("EVT-1")

    def test_live_mode_network_errors(self):
        errors = (
            httpx.ConnectError("connection failed"),
            httpx.ReadTimeout("request timed out"),
        )

        for error in errors:
            with self.subTest(error=type(error).__name__):
                with (
                    patch.dict(
                        os.environ, {"FABRIC_GATEWAY_MODE": "live"}
                    ),
                    patch.object(
                        httpx.Client, "get", side_effect=error
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    self.client.get_event("EVT-1")

    def test_live_mode_malformed_json(self):
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("invalid JSON")

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "get", return_value=response),
            self.assertRaises(RuntimeError),
        ):
            self.client.get_event("EVT-1")

    def test_live_mode_unsuccessful_or_non_dict_response(self):
        invalid_bodies = (
            [],
            {"status": "FABRIC_QUERY_FAILED"},
            {"status": "FOUND", "result": []},
        )

        for body in invalid_bodies:
            with self.subTest(body=body):
                response = MagicMock()
                response.raise_for_status.return_value = None
                response.json.return_value = body

                with (
                    patch.dict(
                        os.environ, {"FABRIC_GATEWAY_MODE": "live"}
                    ),
                    patch.object(
                        httpx.Client, "get", return_value=response
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    self.client.get_event("EVT-1")

    def test_live_mode_wrong_event_id(self):
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "status": "FOUND",
            "result": {"event_id": "EVT-OTHER"},
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "get", return_value=response),
            self.assertRaises(RuntimeError),
        ):
            self.client.get_event("EVT-1")

    def test_invalid_gateway_mode(self):
        with (
            patch.dict(
                os.environ, {"FABRIC_GATEWAY_MODE": "unsupported"}
            ),
            self.assertRaises(ValueError),
        ):
            self.client.get_event("EVT-1")


if __name__ == "__main__":
    unittest.main()
