import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from action_gateway.retry_queue import RetryQueueManager
from fabric.persistent_db import PersistentStorageEngine


def make_payload(event_id="EVT-RECON-1"):
    return {
        "event_id": event_id,
        "request_id": "REQ-RECON-1",
        "agent_id": "AGENT-1",
        "action": "TRANSFER",
        "resource": "ACCOUNT-1",
        "decision": "DENY",
        "reason": "POLICY_BLOCK",
        "policy_id": "POLICY-1",
        "policy_version": "1",
        "evidence_reference": "EVID-1",
        "evidence_hash": "sha256:abc123",
    }


class TestRetryReconciliation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        db_path = os.path.join(self.temp_dir.name, "retry-tests.db")
        self.db = PersistentStorageEngine(db_path=db_path)
        self.manager = RetryQueueManager(persistent_db=self.db)
        self.payload = make_payload()

        self.manager.enqueue_failed_commit(
            event_id=self.payload["event_id"],
            request_id=self.payload["request_id"],
            payload=self.payload.copy(),
            error_msg="simulated submission uncertainty",
        )

    def make_client(self, mode="simulator"):
        client = MagicMock()
        client.get_event.return_value = None
        client.record_action_event.return_value = {"status": "COMMITTED"}
        return client

    def test_matching_existing_event_is_reconciled_without_write(self):
        client = self.make_client()
        client.get_event.return_value = self.payload.copy()

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )

        self.assertTrue(ok)
        self.assertEqual(message, "RETRY_SUCCESSFUL")
        client.get_event.assert_called_once_with(self.payload["event_id"])
        client.record_action_event.assert_not_called()
        self.assertEqual(self.manager.pending_count(), 0)
        self.assertEqual(self.db.list_pending_retries(), [])

    def test_conflicting_existing_event_is_not_overwritten(self):
        client = self.make_client()
        conflict = self.payload.copy()
        conflict["decision"] = "ALLOW"
        client.get_event.return_value = conflict

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )

        self.assertFalse(ok)
        self.assertIn("RECONCILIATION_CONFLICT", message)
        client.record_action_event.assert_not_called()
        self.assertEqual(self.manager.pending_count(), 0)

        persisted = self.db.list_pending_retries()
        self.assertEqual(persisted, [])

    def test_uncertain_event_lookup_keeps_record_pending(self):
        client = self.make_client()
        client.get_event.side_effect = RuntimeError("gateway unavailable")

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}):
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )

        self.assertFalse(ok)
        self.assertIn("RETRY_FAILED", message)
        client.record_action_event.assert_not_called()
        self.assertEqual(self.manager.pending_count(), 1)

        pending = self.db.list_pending_retries()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["status"], "PENDING_RETRY")

    def test_simulator_absent_event_uses_existing_retry_path(self):
        client = self.make_client()
        client.get_event.return_value = None

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )

        self.assertTrue(ok)
        self.assertEqual(message, "RETRY_SUCCESSFUL")
        client.record_action_event.assert_called_once()
        self.assertEqual(self.manager.pending_count(), 0)
        self.assertEqual(self.db.list_pending_retries(), [])

    def test_live_absent_event_does_not_blindly_resubmit(self):
        client = self.make_client()
        client.get_event.return_value = None

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}):
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )

        self.assertFalse(ok)
        self.assertIn("UNCERTAIN", message.upper())
        client.record_action_event.assert_not_called()
        self.assertEqual(self.manager.pending_count(), 1)

    def test_matching_event_comparison_includes_all_payload_fields(self):
        client = self.make_client()
        changed = self.payload.copy()
        changed["evidence_hash"] = "sha256:different"
        client.get_event.return_value = changed

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )

        self.assertFalse(ok)
        self.assertIn("RECONCILIATION_CONFLICT", message)
        client.record_action_event.assert_not_called()

    def test_dead_letter_record_survives_manager_restart(self):
        event_id = self.payload["event_id"]
        retry_count = 3
        # Persist a dead-letter record using the existing isolated test DB.
        self.db.update_retry_status(
            event_id=event_id,
            status="DEAD_LETTER_QUEUE",
            retry_count=retry_count,
        )
        # Recreate the manager to simulate a process restart.
        restarted_manager = RetryQueueManager(persistent_db=self.db)
        # Verify that valid dead-letter records are restored after manager restart.
        self.assertIn(
            event_id,
            restarted_manager._dead_letter_queue,
            "Dead-letter record was not restored after manager restart",
        )
        restored = restarted_manager._dead_letter_queue[event_id]
        self.assertEqual(restored.event_id, event_id)
        self.assertEqual(restored.request_id, self.payload["request_id"])
        self.assertEqual(restored.payload, self.payload)
        self.assertEqual(restored.retry_count, retry_count)
        self.assertEqual(restored.status, "DEAD_LETTER_QUEUE")
        self.assertEqual(restored.error_msg, "simulated submission uncertainty")
        self.assertNotIn(event_id, restarted_manager._pending_queue)
        # Construction must not submit anything to Fabric.
        client = self.make_client()
        client.record_action_event.assert_not_called()

    def test_corrupt_dead_letter_payload_remains_visible(self):
        event_id = self.payload["event_id"]
        self.db.update_retry_status(
            event_id=event_id,
            status="DEAD_LETTER_QUEUE",
            retry_count=3,
        )
        # Inject malformed JSON into the stored payload.
        with self.db._lock:
            conn = self.db._get_connection()
            try:
                conn.execute(
                    """
                    UPDATE reconciliation_queue
                    SET payload_json = ?
                    WHERE event_id = ?
                    """,
                    ("{invalid-json", event_id),
                )
                conn.commit()
            finally:
                conn.close()

        records = self.db.list_dead_letter_retries()
        self.assertEqual(len(records), 1)
        corrupt_record = records[0]
        self.assertEqual(corrupt_record["event_id"], event_id)
        self.assertTrue(corrupt_record["corrupt"])
        self.assertIsNone(corrupt_record["payload"])
        self.assertEqual(corrupt_record["raw_payload"], "{invalid-json")

        # Queue initialization must not crash or hydrate corrupt payloads.
        restarted_manager = RetryQueueManager(persistent_db=self.db)
        self.assertNotIn(event_id, restarted_manager._dead_letter_queue)
        self.assertNotIn(event_id, restarted_manager._pending_queue)


if __name__ == "__main__":
    unittest.main()
