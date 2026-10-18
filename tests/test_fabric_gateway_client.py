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


class TestFabricClientRecordActionEvent(unittest.TestCase):
    def setUp(self):
        self.client = FabricClient()
        self.sample_event = {
            "event_id": "EVT-AUDIT-100",
            "request_id": "REQ-AUDIT-100",
            "agent_id": "AGENT-001",
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "decision": "ALLOWED",
            "reason": "VALID_POLICY",
            "policy_id": "POL-FIN-01",
            "policy_version": "1.0",
            "evidence_reference": "EVID-100",
            "evidence_hash": "a" * 64,
        }

    def test_record_action_event_simulator_mode(self):
        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
            result = self.client.record_action_event(**self.sample_event)

        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(result["mode"], "simulator")
        self.assertEqual(result["source"], "fabric_simulator")
        self.assertIn("chaincode_result", result)

    def test_record_action_event_live_mode_success(self):
        expected_chaincode_result = {
            "docType": "action_event",
            "event_id": self.sample_event["event_id"],
            "decision": "ALLOWED",
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "status": "COMMITTED",
            "result": expected_chaincode_result,
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live", "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"}),
            patch.object(httpx.Client, "post", return_value=mock_response) as post_mock,
        ):
            result = self.client.record_action_event(**self.sample_event)

        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(result["mode"], "live")
        self.assertEqual(result["source"], "hyperledger_fabric_gateway")
        self.assertIsNone(result["block_index"])
        self.assertIsNone(result["block_hash"])
        self.assertEqual(result["chaincode_result"], expected_chaincode_result)
        post_mock.assert_called_once_with(
            "http://127.0.0.1:8090/v1/action-events",
            json=self.sample_event,
        )

    def test_record_action_event_live_mode_uncertain_502(self):
        mock_response = MagicMock()
        mock_response.status_code = 502
        mock_response.json.return_value = {
            "status": "FABRIC_SUBMISSION_UNCERTAIN",
            "error": "Fabric transaction was not confirmed; reconcile event_id before retrying",
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live", "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("uncertain", str(ctx.exception).lower())
        self.assertIn("reconcile event_id", str(ctx.exception).lower())

    def test_record_action_event_live_mode_network_failure(self):
        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "post", side_effect=httpx.ConnectError("Connection refused")),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))
        self.assertIn("reconcile event_id", str(ctx.exception).lower())

    def test_record_action_event_live_mode_timeout_raises_uncertain(self):
        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "post", side_effect=httpx.TimeoutException("Read timed out")),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))
        self.assertIn("reconcile event_id", str(ctx.exception).lower())

    def test_record_action_event_live_mode_missing_fields_validation(self):
        invalid_event = dict(self.sample_event)
        invalid_event["event_id"] = "   "

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            self.assertRaises(ValueError) as ctx,
        ):
            self.client.record_action_event(**invalid_event)

        self.assertIn("event_id must be a non-empty string", str(ctx.exception))

    def test_record_action_event_live_mode_http_400_rejected(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = '{"error": "Invalid action event payload"}'

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live", "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_REJECTED", str(ctx.exception))
        self.assertNotIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))

    def test_record_action_event_live_mode_http_500_uncertain(self):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live", "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))

    def test_record_action_event_live_mode_http_302_redirect_raises_uncertain(self):
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.json.return_value = {
            "status": "COMMITTED",
            "result": {"event_id": self.sample_event["event_id"]},
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live", "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))
        self.assertIn("reconcile event_id", str(ctx.exception).lower())

    def test_record_action_event_live_mode_unexpected_body_status_raises_uncertain(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "status": "SUBMITTED",
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))
        self.assertIn("reconcile event_id", str(ctx.exception).lower())

    def test_record_action_event_live_mode_non_dict_body_raises_uncertain(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = ["not", "a", "dict"]

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_SUBMISSION_UNCERTAIN", str(ctx.exception))
        self.assertIn("malformed", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()

