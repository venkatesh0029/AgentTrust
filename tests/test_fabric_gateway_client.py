import os
import unittest
from unittest.mock import MagicMock, patch

import httpx

from fabric.fabric_client import FabricClient


TEST_GATEWAY_TOKEN = "test_gateway_token_of_at_least_32_characters_12345"
TEST_AUTH_HEADERS = {"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"}


class TestFabricClientGetEvent(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {
                "FABRIC_GATEWAY_MODE": "simulator",
                "FABRIC_GATEWAY_TOKEN": TEST_GATEWAY_TOKEN,
            },
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
            "http://127.0.0.1:8090/v1/action-events/EVT-1",
            headers=TEST_AUTH_HEADERS,
        )

    def test_live_mode_definitive_not_found_returns_none(self):
        response = MagicMock()
        response.status_code = 404
        response.json.return_value = {
            "status": "NOT_FOUND",
            "error": "Action event not found",
        }
        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(
                httpx.Client, "get", return_value=response
            ) as get,
        ):
            result = self.client.get_event("EVENT-TEST-MISSING")
        self.assertIsNone(result)
        response.raise_for_status.assert_not_called()
        get.assert_called_once()

    def test_live_mode_404_without_not_found_status_stays_uncertain(self):
        url = "http://127.0.0.1:8090/v1/action-events/EVENT-TEST-MISSING"
        request = httpx.Request("GET", url)
        response_404 = httpx.Response(
            404,
            request=request,
            json={"status": "FABRIC_QUERY_FAILED"},
        )
        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}),
            patch.object(
                httpx.Client, "get", return_value=response_404
            ),
            self.assertRaises(RuntimeError),
        ):
            self.client.get_event("EVENT-TEST-MISSING")

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
        self.env_patch = patch.dict(
            os.environ,
            {"FABRIC_GATEWAY_TOKEN": TEST_GATEWAY_TOKEN},
            clear=False,
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

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
            headers=TEST_AUTH_HEADERS,
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

    def test_record_action_event_live_mode_pre_submission_failure(self):
        mock_response = MagicMock()
        mock_response.status_code = 409
        mock_response.json.return_value = {
            "status": "FABRIC_PRE_SUBMISSION_FAILURE",
            "error": "Fabric endorsement planning failed before transaction submission",
        }

        with (
            patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live", "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"}),
            patch.object(httpx.Client, "post", return_value=mock_response),
            self.assertRaises(RuntimeError) as ctx,
        ):
            self.client.record_action_event(**self.sample_event)

        self.assertIn("FABRIC_PRE_SUBMISSION_FAILURE", str(ctx.exception))

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


class TestFabricClientAuthentication(unittest.TestCase):
    def setUp(self):
        self.client = FabricClient()
        self.sample_event = {
            "event_id": "EVT-AUDIT-200",
            "request_id": "REQ-AUDIT-200",
            "agent_id": "AGENT-002",
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "decision": "ALLOWED",
            "reason": "VALID_POLICY",
            "policy_id": "POL-FIN-01",
            "policy_version": "1.0",
            "evidence_reference": "EVID-200",
            "evidence_hash": "b" * 64,
        }

    def test_missing_token_fails_before_http_request(self):
        for method_name in ("get_event", "record_action_event", "verify_evidence_hash"):
            with self.subTest(method=method_name):
                with (
                    patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}, clear=False),
                    patch.dict(os.environ, {"FABRIC_GATEWAY_TOKEN": ""}),
                    patch.object(httpx.Client, "get") as mock_get,
                    patch.object(httpx.Client, "post") as mock_post,
                    self.assertRaises(RuntimeError) as ctx,
                ):
                    if method_name == "get_event":
                        self.client.get_event("EVT-200")
                    elif method_name == "record_action_event":
                        self.client.record_action_event(**self.sample_event)
                    else:
                        self.client.verify_evidence_hash("EVID-200", "b" * 64)

                self.assertIn("FABRIC_GATEWAY_TOKEN must be configured", str(ctx.exception))
                mock_get.assert_not_called()
                mock_post.assert_not_called()

    def test_short_token_fails_before_http_request(self):
        short_token = "too_short_token_123"
        for method_name in ("get_event", "record_action_event", "verify_evidence_hash"):
            with self.subTest(method=method_name):
                with (
                    patch.dict(
                        os.environ,
                        {
                            "FABRIC_GATEWAY_MODE": "live",
                            "FABRIC_GATEWAY_TOKEN": short_token,
                        },
                        clear=False,
                    ),
                    patch.object(httpx.Client, "get") as mock_get,
                    patch.object(httpx.Client, "post") as mock_post,
                    self.assertRaises(RuntimeError) as ctx,
                ):
                    if method_name == "get_event":
                        self.client.get_event("EVT-200")
                    elif method_name == "record_action_event":
                        self.client.record_action_event(**self.sample_event)
                    else:
                        self.client.verify_evidence_hash("EVID-200", "b" * 64)

                self.assertIn("at least 32 characters", str(ctx.exception))
                mock_get.assert_not_called()
                mock_post.assert_not_called()

    def test_bearer_token_sent_on_all_live_calls(self):
        env = {
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090",
            "FABRIC_GATEWAY_TOKEN": TEST_GATEWAY_TOKEN,
        }

        # 1. Action-event write
        mock_post_event = MagicMock()
        mock_post_event.status_code = 200
        mock_post_event.json.return_value = {
            "status": "COMMITTED",
            "result": {"event_id": self.sample_event["event_id"]},
        }
        with (
            patch.dict(os.environ, env, clear=False),
            patch.object(httpx.Client, "post", return_value=mock_post_event) as post_mock,
        ):
            self.client.record_action_event(**self.sample_event)
            post_mock.assert_called_once_with(
                "http://127.0.0.1:8090/v1/action-events",
                json=self.sample_event,
                headers=TEST_AUTH_HEADERS,
            )

        # 2. Action-event reconciliation query
        mock_get_event = MagicMock()
        mock_get_event.status_code = 200
        mock_get_event.raise_for_status.return_value = None
        mock_get_event.json.return_value = {
            "status": "FOUND",
            "result": {"event_id": "EVT-200", "decision": "ALLOWED"},
        }
        with (
            patch.dict(os.environ, env, clear=False),
            patch.object(httpx.Client, "get", return_value=mock_get_event) as get_mock,
        ):
            self.client.get_event("EVT-200")
            get_mock.assert_called_once_with(
                "http://127.0.0.1:8090/v1/action-events/EVT-200",
                headers=TEST_AUTH_HEADERS,
            )

        # 3. Evidence verification query
        mock_verify = MagicMock()
        mock_verify.status_code = 200
        mock_verify.raise_for_status.return_value = None
        mock_verify.json.return_value = {
            "status": "SUCCESS",
            "result": {
                "found": True,
                "stored_hash": "b" * 64,
                "recalculated_hash": "b" * 64,
                "verified": True,
                "status": "VERIFIED",
            },
        }
        with (
            patch.dict(os.environ, env, clear=False),
            patch.object(httpx.Client, "post", return_value=mock_verify) as verify_mock,
        ):
            self.client.verify_evidence_hash("EVID-200", "b" * 64)
            verify_mock.assert_called_once_with(
                "http://127.0.0.1:8090/v1/evidence/verify",
                json={"evidence_ref": "EVID-200", "expected_hash": "b" * 64},
                headers=TEST_AUTH_HEADERS,
            )


if __name__ == "__main__":
    unittest.main()

