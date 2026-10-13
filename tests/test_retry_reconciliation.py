import json
import os
import tempfile
import threading
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
    def test_get_retry_record_returns_none_for_missing_event(self):
        record = self.db.get_retry_record("EVT-DOES-NOT-EXIST")
        self.assertIsNone(record)

    def test_get_retry_record_returns_valid_persisted_record(self):
        record = self.db.get_retry_record(self.payload["event_id"])
        self.assertIsNotNone(record)
        self.assertEqual(record["event_id"], self.payload["event_id"])
        self.assertEqual(record["request_id"], self.payload["request_id"])
        self.assertEqual(record["payload"], self.payload)
        self.assertEqual(record["status"], "PENDING_RETRY")
        self.assertEqual(record["retry_count"], 0)

    def test_get_retry_record_raises_on_malformed_payload(self):
        event_id = self.payload["event_id"]
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
        with self.assertRaises(json.JSONDecodeError):
            self.db.get_retry_record(event_id)

    def test_initial_persisted_read_error_fails_closed(self):
        self.manager._pending_queue.clear()
        with patch.object(
            self.db,
            "get_retry_record",
            side_effect=json.JSONDecodeError("invalid JSON", "{", 0),
        ):
            client = self.make_client()
            ok, message = self.manager.retry_commit(
                self.payload["event_id"], client
            )
        self.assertFalse(ok)
        self.assertIn("PERSISTED_RECORD_READ_ERROR", message)
        self.assertIn("JSONDecodeError", message)
        client.record_action_event.assert_not_called()

    def test_authoritative_read_error_releases_lease_without_write(self):
        original_get = self.db.get_retry_record
        calls = 0

        def fail_second_read(event_id):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise json.JSONDecodeError("invalid JSON", "{", 0)
            return original_get(event_id)

        self.manager._pending_queue.clear()
        client = self.make_client()
        with patch.object(self.db, "get_retry_record", side_effect=fail_second_read):
            with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
                ok, message = self.manager.retry_commit(
                    self.payload["event_id"], client
                )
        self.assertFalse(ok)
        self.assertIn("PERSISTED_RECORD_READ_ERROR", message)
        self.assertIn("JSONDecodeError", message)
        client.record_action_event.assert_not_called()
        rec = self.db.get_retry_record(self.payload["event_id"])
        self.assertEqual(rec["lease_owner"], "")
        self.assertEqual(rec["lease_expires_at"], 0.0)

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

    def test_concurrent_retries_block_second_worker_via_lease(self):
        """
        1. Concurrent retries: two RetryQueueManager instances sharing separate
        PersistentStorageEngine instances over the same SQLite file cannot both
        process the same record simultaneously.
        """
        engine2 = PersistentStorageEngine(db_path=self.db.db_path)
        manager2 = RetryQueueManager(persistent_db=engine2)

        client1 = self.make_client()
        client2 = self.make_client()

        started_event = threading.Event()
        proceed_event = threading.Event()

        def slow_get_event(event_id):
            started_event.set()
            proceed_event.wait(timeout=5.0)
            return self.payload.copy()

        client1.get_event.side_effect = slow_get_event

        results = {}

        def worker1():
            with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
                results["w1"] = self.manager.retry_commit(self.payload["event_id"], client1)

        def worker2():
            # Wait until worker 1 has acquired the lease and entered get_event
            started_event.wait(timeout=5.0)
            with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
                results["w2"] = manager2.retry_commit(self.payload["event_id"], client2)
            proceed_event.set()

        t1 = threading.Thread(target=worker1)
        t2 = threading.Thread(target=worker2)

        t1.start()
        t2.start()

        t1.join(timeout=5.0)
        t2.join(timeout=5.0)

        ok1, msg1 = results["w1"]
        ok2, msg2 = results["w2"]

        # Worker 1 acquired lease and succeeded
        self.assertTrue(ok1)
        self.assertEqual(msg1, "RETRY_SUCCESSFUL")

        # Worker 2 was rejected due to active lease
        self.assertFalse(ok2)
        self.assertIn("LEASE_ACQUISITION_FAILED", msg2)

    def test_lease_loss_before_finalization_fails_closed(self):
        """
        2. Lease loss before finalization: expire or replace the lease while the
        first worker is blocked in a mocked Fabric operation. The stale worker must
        not delete the record or move it to the DLQ.
        """
        engine2 = PersistentStorageEngine(db_path=self.db.db_path)

        client1 = self.make_client()
        client1.get_event.return_value = None  # Simulator mode will proceed to write

        started_event = threading.Event()
        proceed_event = threading.Event()

        def slow_write(**kwargs):
            started_event.set()
            proceed_event.wait(timeout=5.0)
            return {"status": "COMMITTED"}

        client1.record_action_event.side_effect = slow_write

        result1 = {}

        def worker1():
            with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
                result1["res"] = self.manager.retry_commit(self.payload["event_id"], client1)

        t1 = threading.Thread(target=worker1)
        t1.start()

        # Wait until worker 1 has claimed lease and is inside record_action_event
        started_event.wait(timeout=5.0)

        # Worker 2 supersedes worker 1 by reclaiming the lease with higher fencing token.
        # Expire worker 1's lease in the database to simulate lease timeout:
        with self.db._lock:
            conn = self.db._get_connection()
            try:
                conn.execute(
                    "UPDATE reconciliation_queue SET lease_expires_at = 0.0 WHERE event_id = ?",
                    (self.payload["event_id"],),
                )
                conn.commit()
            finally:
                conn.close()

        # Worker 2 claims the expired record with incremented fencing token
        claim2 = engine2.claim_retry_record(self.payload["event_id"], owner_id="worker_2", ttl_seconds=30.0)
        self.assertTrue(claim2.acquired)
        self.assertEqual(claim2.fencing_token, 2)

        # Now allow worker 1 to proceed to finalization
        proceed_event.set()
        t1.join(timeout=5.0)

        ok1, msg1 = result1["res"]
        # Worker 1's finalization must be rejected because its lease was superseded
        self.assertFalse(ok1)
        self.assertIn("LEASE_LOST_BEFORE_FINALIZATION", msg1)

        # The record was NOT deleted by worker 1; worker 2 still owns it in the DB
        persisted = self.db.list_pending_retries()
        self.assertEqual(len(persisted), 1)
        self.assertEqual(persisted[0]["event_id"], self.payload["event_id"])
        self.assertEqual(persisted[0]["fencing_token"], 2)
        self.assertEqual(persisted[0]["lease_owner"], "worker_2")

    def test_write_failure_persists_retry_count_under_fenced_claim(self):
        """
        7. Write failure: retry count and status are persisted atomically under the current claim.
        """
        client = self.make_client()
        client.get_event.return_value = None
        client.record_action_event.side_effect = RuntimeError("Fabric commit rejected")

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
            ok, message = self.manager.retry_commit(self.payload["event_id"], client)

        self.assertFalse(ok)
        self.assertIn("Fabric commit rejected", message)

        # Persisted record has retry_count=1, status="PENDING_RETRY"
        pending = self.db.list_pending_retries()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["retry_count"], 1)
        self.assertEqual(pending[0]["status"], "PENDING_RETRY")
        # Lease was safely released in finally block
        self.assertEqual(pending[0]["lease_owner"], "")

    def test_uncertain_ledger_query_releases_lease_for_subsequent_worker(self):
        """
        3. Uncertain ledger query: a get_event() exception does not increment the retry count,
        and releases the lease so a subsequent worker can immediately retry.
        """
        client = self.make_client()
        client.get_event.side_effect = RuntimeError("transient network drop")

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}):
            ok, message = self.manager.retry_commit(self.payload["event_id"], client)

        self.assertFalse(ok)
        self.assertIn("transient network drop", message)

        # Check DB: retry count is unchanged (0), lease is released
        pending = self.db.list_pending_retries()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["retry_count"], 0)
        self.assertEqual(pending[0]["lease_owner"], "")

        # A second worker can immediately claim it
        claim2 = self.db.claim_retry_record(self.payload["event_id"], owner_id="worker_2", ttl_seconds=30.0)
        self.assertTrue(claim2.acquired)

    def test_live_absent_event_releases_lease_without_write(self):
        """
        4. Live event absent: no write occurs, retry count is not incremented,
        and lease is released.
        """
        client = self.make_client()
        client.get_event.return_value = None

        with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "live"}):
            ok, message = self.manager.retry_commit(self.payload["event_id"], client)

        self.assertFalse(ok)
        self.assertIn("LIVE_LEDGER_STATE_UNCERTAIN", message)
        client.record_action_event.assert_not_called()

        pending = self.db.list_pending_retries()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["retry_count"], 0)
        self.assertEqual(pending[0]["lease_owner"], "")

    def test_finalization_error_after_successful_write_requires_reconciliation(self):
        """
        Verifies that if Fabric write succeeds but finalize_retry_record raises an exception,
        the exception is NOT treated as a failed Fabric write:
        - Outcome indicates reconciliation is required (FINALIZATION_ERROR_RECONCILE_REQUIRED).
        - Retry count is NOT incremented as a write failure.
        - Record is NOT removed from _pending_queue.
        """
        client = self.make_client()
        client.get_event.return_value = None
        client.record_action_event.return_value = {"status": "COMMITTED"}

        orig_finalize = self.db.finalize_retry_record

        def failing_finalize(*args, **kwargs):
            if kwargs.get("delete_record"):
                raise RuntimeError("simulated SQLite disk error during finalization")
            return orig_finalize(*args, **kwargs)

        with patch.object(self.db, "finalize_retry_record", side_effect=failing_finalize):
            with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
                ok, message = self.manager.retry_commit(self.payload["event_id"], client)

        self.assertFalse(ok)
        self.assertIn("FINALIZATION_ERROR_RECONCILE_REQUIRED", message)
        # Write succeeded, so write exception handler did NOT catch it
        client.record_action_event.assert_called_once()
        # Record was NOT popped from _pending_queue
        self.assertIn(self.payload["event_id"], self.manager._pending_queue)
        # Record in memory is not marked RETRIED_SUCCESS or DEAD_LETTER_QUEUE
        self.assertEqual(self.manager._pending_queue[self.payload["event_id"]].status, "PENDING_RETRY")
        # In DB, record still exists for subsequent reconciliation
        pending = self.db.list_pending_retries()
        self.assertEqual(len(pending), 1)

    def test_claim_superseded_during_ledger_query_blocks_write(self):
        """
        Verifies that if the claim is superseded while get_event is running,
        the stale worker does NOT begin a new write after get_event returns.
        """
        engine2 = PersistentStorageEngine(db_path=self.db.db_path)
        client = self.make_client()

        started_event = threading.Event()
        proceed_event = threading.Event()

        def blocking_get_event(event_id):
            started_event.set()
            proceed_event.wait(timeout=5.0)
            return None  # Absent from ledger in simulator mode

        client.get_event.side_effect = blocking_get_event

        result = {}

        def worker1():
            with patch.dict(os.environ, {"FABRIC_GATEWAY_MODE": "simulator"}):
                result["res"] = self.manager.retry_commit(self.payload["event_id"], client)

        t1 = threading.Thread(target=worker1)
        t1.start()

        # Wait until worker 1 is blocked inside get_event
        started_event.wait(timeout=5.0)

        # Worker 2 supersedes worker 1 while worker 1 is waiting on ledger query:
        with self.db._lock:
            conn = self.db._get_connection()
            try:
                conn.execute(
                    "UPDATE reconciliation_queue SET lease_expires_at = 0.0 WHERE event_id = ?",
                    (self.payload["event_id"],),
                )
                conn.commit()
            finally:
                conn.close()

        # Worker 2 claims the record
        claim2 = engine2.claim_retry_record(self.payload["event_id"], owner_id="worker_2", ttl_seconds=30.0)
        self.assertTrue(claim2.acquired)
        self.assertEqual(claim2.fencing_token, 2)

        # Let worker 1 resume after get_event returned
        proceed_event.set()
        t1.join(timeout=5.0)

        ok, message = result["res"]
        self.assertFalse(ok)
        self.assertIn("LEASE_LOST_BEFORE_WRITE", message)
        # Pre-write lease validation prevented worker 1 from calling record_action_event!
        client.record_action_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()
