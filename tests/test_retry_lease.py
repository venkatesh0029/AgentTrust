"""
Focused tests for database retry lease primitives in PersistentStorageEngine.
Validates atomic claims, lease expiry, fencing tokens, stale/expired owner rejection,
and backward-compatible database migration.
"""

import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from fabric.persistent_db import PersistentStorageEngine


class TestRetryLeasePrimitives(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = os.path.join(self.temp_dir.name, "retry_lease_test.db")
        self.engine1 = PersistentStorageEngine(db_path=self.db_path)
        self.engine2 = PersistentStorageEngine(db_path=self.db_path)
        self.payload = {
            "event_id": "EVT-LEASE-1",
            "request_id": "REQ-LEASE-1",
            "agent_id": "AGENT-LEASE-1",
            "action": "TRANSFER",
            "resource": "VAULT-1",
            "decision": "DENY",
            "reason": "POLICY_BLOCK",
        }
        self.event_id = self.payload["event_id"]
        self.engine1.save_retry_record(
            event_id=self.event_id,
            request_id=self.payload["request_id"],
            payload=self.payload.copy(),
            error_msg="initial failure",
            status="PENDING_RETRY",
            retry_count=0,
        )

    def test_two_competing_workers_exactly_one_acquires_lease(self):
        """
        1. Two competing workers: exactly one acquires the active lease.
        Tests both sequential attempts and concurrent multi-thread attempts across
        separate engine instances on the same SQLite database file.
        """
        # Sequential check: worker 1 claims active lease
        res1 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_1", ttl_seconds=30.0)
        self.assertTrue(res1.acquired)
        self.assertEqual(res1.fencing_token, 1)
        self.assertEqual(res1.owner_id, "worker_1")

        # Worker 2 attempts while worker 1 holds active lease
        res2 = self.engine2.claim_retry_record(self.event_id, owner_id="worker_2", ttl_seconds=30.0)
        self.assertFalse(res2.acquired)
        self.assertEqual(res2.fencing_token, 1)
        self.assertEqual(res2.owner_id, "worker_1")

        # Concurrent race test with a new event
        race_event = "EVT-RACE-CONCURRENT"
        self.engine1.save_retry_record(
            event_id=race_event,
            request_id="REQ-RACE",
            payload={"test": "data"},
            error_msg="race test",
        )

        def attempt_claim(engine, worker_id):
            return engine.claim_retry_record(race_event, owner_id=worker_id, ttl_seconds=30.0)

        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(attempt_claim, self.engine1, "concurrent_w1")
            f2 = executor.submit(attempt_claim, self.engine2, "concurrent_w2")
            r1 = f1.result()
            r2 = f2.result()

        results = [r1, r2]
        acquired_count = sum(1 for r in results if r.acquired)
        self.assertEqual(acquired_count, 1, "Exactly one worker must acquire the active lease")

    def test_expired_lease_second_worker_acquires_with_higher_fencing_token(self):
        """
        2. Expired lease: a second worker acquires it with a higher fencing token.
        """
        # Worker 1 acquires with very short TTL
        res1 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_1", ttl_seconds=0.05)
        self.assertTrue(res1.acquired)
        self.assertEqual(res1.fencing_token, 1)
        self.assertEqual(res1.owner_id, "worker_1")

        # Wait for lease to expire
        time.sleep(0.08)

        # Worker 2 reclaims the expired record
        res2 = self.engine2.claim_retry_record(self.event_id, owner_id="worker_2", ttl_seconds=30.0)
        self.assertTrue(res2.acquired, "Second worker should reclaim expired lease")
        self.assertEqual(res2.fencing_token, 2, "Fencing token must be incremented upon reclamation")
        self.assertEqual(res2.owner_id, "worker_2")

    def test_stale_owner_validation_release_and_finalization_fail(self):
        """
        3. Stale owner: validation, release, and finalization fail after another worker takes over.
        """
        # Worker 1 acquires with short TTL
        res1 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_1", ttl_seconds=0.05)
        self.assertTrue(res1.acquired)
        self.assertEqual(res1.fencing_token, 1)

        # Worker 1 validates successfully while active
        self.assertTrue(self.engine1.validate_retry_claim(self.event_id, "worker_1", res1.fencing_token))

        # Lease expires
        time.sleep(0.08)

        # Worker 2 takes over
        res2 = self.engine2.claim_retry_record(self.event_id, owner_id="worker_2", ttl_seconds=30.0)
        self.assertTrue(res2.acquired)
        self.assertEqual(res2.fencing_token, 2)
        self.assertEqual(res2.owner_id, "worker_2")

        # Now worker 1 is stale (fencing_token=1, owner="worker_1")
        # 1. Validation fails
        self.assertFalse(
            self.engine1.validate_retry_claim(self.event_id, "worker_1", res1.fencing_token),
            "Stale worker claim validation must fail",
        )
        # 2. Release fails
        self.assertFalse(
            self.engine1.release_retry_claim(self.event_id, "worker_1", res1.fencing_token),
            "Stale worker release must fail",
        )
        # 3. Finalization (update status) fails
        self.assertFalse(
            self.engine1.finalize_retry_record(
                self.event_id, "worker_1", res1.fencing_token, status="COMPLETED"
            ),
            "Stale worker finalization (update) must fail",
        )
        # 4. Finalization (delete) fails
        self.assertFalse(
            self.engine1.finalize_retry_record(
                self.event_id, "worker_1", res1.fencing_token, delete_record=True
            ),
            "Stale worker finalization (delete) must fail",
        )

        # Verify Worker 2's lease is completely untouched and valid
        self.assertTrue(self.engine2.validate_retry_claim(self.event_id, "worker_2", res2.fencing_token))

    def test_expired_owner_finalization_fails_even_before_reclamation(self):
        """
        4. Expired owner: finalization fails even if nobody has reclaimed the lease yet.
        """
        # Worker 1 acquires with short TTL
        res1 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_1", ttl_seconds=0.05)
        self.assertTrue(res1.acquired)
        self.assertEqual(res1.fencing_token, 1)

        # Wait for lease expiry
        time.sleep(0.08)

        # Nobody else has reclaimed the lease yet.
        # Worker 1 tries to finalize:
        # a) finalize with update must fail
        self.assertFalse(
            self.engine1.finalize_retry_record(
                self.event_id, "worker_1", res1.fencing_token, status="DEAD_LETTER_QUEUE"
            ),
            "Expired worker must not be allowed to finalize record even before reclamation",
        )
        # b) finalize with delete must fail
        self.assertFalse(
            self.engine1.finalize_retry_record(
                self.event_id, "worker_1", res1.fencing_token, delete_record=True
            ),
            "Expired worker must not be allowed to delete record even before reclamation",
        )
        # c) release must also fail
        self.assertFalse(
            self.engine1.release_retry_claim(self.event_id, "worker_1", res1.fencing_token),
            "Expired worker must not be allowed to release expired lease",
        )

        # Verify record remains unchanged in database
        pending = self.engine1.list_pending_retries()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["event_id"], self.event_id)
        self.assertEqual(pending[0]["status"], "PENDING_RETRY")

    def test_missing_or_non_pending_event_claim_fails_safely(self):
        """
        5. Missing or non-pending event: claim fails safely.
        """
        # Missing event ID
        res_missing = self.engine1.claim_retry_record("NON-EXISTENT-EVENT-999", owner_id="worker_1")
        self.assertFalse(res_missing.acquired)
        self.assertEqual(res_missing.fencing_token, 0)
        self.assertEqual(res_missing.owner_id, "")

        # Record with status = 'DEAD_LETTER_QUEUE'
        dlq_event = "EVT-DLQ-1"
        self.engine1.save_retry_record(
            event_id=dlq_event,
            request_id="REQ-DLQ",
            payload={"error": "corrupt"},
            error_msg="dead letter",
            status="DEAD_LETTER_QUEUE",
        )
        res_dlq = self.engine1.claim_retry_record(dlq_event, owner_id="worker_1")
        self.assertFalse(res_dlq.acquired)
        self.assertEqual(res_dlq.owner_id, "")

        # Record with status = 'COMPLETED'
        completed_event = "EVT-COMPLETED-1"
        self.engine1.save_retry_record(
            event_id=completed_event,
            request_id="REQ-DONE",
            payload={"status": "done"},
            error_msg="",
            status="COMPLETED",
        )
        res_completed = self.engine1.claim_retry_record(completed_event, owner_id="worker_1")
        self.assertFalse(res_completed.acquired)

    def test_invalid_ttl_zero_and_negative_values_rejected(self):
        """
        6. Invalid TTL: zero and negative values are rejected.
        """
        with self.assertRaises(ValueError) as ctx_zero:
            self.engine1.claim_retry_record(self.event_id, ttl_seconds=0)
        self.assertIn("positive", str(ctx_zero.exception))

        with self.assertRaises(ValueError) as ctx_neg:
            self.engine1.claim_retry_record(self.event_id, ttl_seconds=-1.0)
        self.assertIn("positive", str(ctx_neg.exception))

        with self.assertRaises(ValueError):
            self.engine1.claim_retry_record(self.event_id, ttl_seconds=-0.0001)

    def test_legacy_database_migration_existing_records_survive_with_defaults(self):
        """
        7. Legacy database migration: existing records survive with unclaimed defaults.
        """
        legacy_db_path = os.path.join(self.temp_dir.name, "legacy_test.db")
        # Create legacy table manually without lease columns
        conn = sqlite3.connect(legacy_db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE reconciliation_queue (
                event_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                error_msg TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        legacy_event = "EVT-LEGACY-001"
        cursor.execute("""
            INSERT INTO reconciliation_queue (
                event_id, request_id, payload_json, error_msg, retry_count, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            legacy_event,
            "REQ-LEGACY",
            '{"action": "LEGACY_PAYLOAD"}',
            "legacy error",
            1,
            "PENDING_RETRY",
            "2026-01-01T00:00:00Z",
        ))
        conn.commit()
        conn.close()

        # Open legacy database with PersistentStorageEngine
        engine = PersistentStorageEngine(db_path=legacy_db_path)

        # Verify columns exist after migration
        conn = engine._get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(reconciliation_queue)")
        cols = {row["name"] for row in cursor.fetchall()}
        conn.close()
        self.assertIn("lease_owner", cols)
        self.assertIn("lease_expires_at", cols)
        self.assertIn("fencing_token", cols)

        # Verify existing record survived with default values
        pending = engine.list_pending_retries()
        self.assertEqual(len(pending), 1)
        rec = pending[0]
        self.assertEqual(rec["event_id"], legacy_event)
        self.assertEqual(rec["lease_owner"], "")
        self.assertEqual(rec["lease_expires_at"], 0.0)
        self.assertEqual(rec["fencing_token"], 0)
        self.assertEqual(rec["payload"]["action"], "LEGACY_PAYLOAD")

        # Claim the legacy record: should succeed with fencing token 1
        claim_res = engine.claim_retry_record(legacy_event, owner_id="legacy_worker", ttl_seconds=30.0)
        self.assertTrue(claim_res.acquired)
        self.assertEqual(claim_res.fencing_token, 1)
        self.assertEqual(claim_res.owner_id, "legacy_worker")

    def test_token_monotonicity_across_claim_expiry_reclaim_and_updates(self):
        """
        8. Token monotonicity: repeated claim expiry and reclamation never reset the token.
        Also verifies save_retry_record does not reset lease or fencing tokens.
        """
        # Claim 1: token 1
        res1 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_1", ttl_seconds=0.05)
        self.assertTrue(res1.acquired)
        self.assertEqual(res1.fencing_token, 1)

        # Expire
        time.sleep(0.08)

        # Claim 2 (reclaim): token 2
        res2 = self.engine2.claim_retry_record(self.event_id, owner_id="worker_2", ttl_seconds=0.05)
        self.assertTrue(res2.acquired)
        self.assertEqual(res2.fencing_token, 2)

        # Expire
        time.sleep(0.08)

        # Claim 3 (reclaim): token 3
        res3 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_3", ttl_seconds=30.0)
        self.assertTrue(res3.acquired)
        self.assertEqual(res3.fencing_token, 3)

        # Attempting save_retry_record while worker 3 holds active lease must be rejected
        with self.assertRaises(RuntimeError):
            self.engine1.save_retry_record(
                event_id=self.event_id,
                request_id="REQ-REJECTED",
                payload={"bad": True},
                error_msg="should fail",
            )

        # Worker 3 cleanly releases claim
        self.assertTrue(self.engine1.release_retry_claim(self.event_id, "worker_3", 3))

        # Ordinary record update via save_retry_record when unclaimed must not reset fencing token
        self.engine1.save_retry_record(
            event_id=self.event_id,
            request_id="REQ-UPDATED",
            payload={"updated": True},
            error_msg="transient error",
            status="PENDING_RETRY",
            retry_count=1,
        )
        pending = self.engine1.list_pending_retries()
        self.assertEqual(pending[0]["fencing_token"], 3)

        # Claim 4 after release and update: token 4 (monotonic)
        res4 = self.engine2.claim_retry_record(self.event_id, owner_id="worker_4", ttl_seconds=30.0)
        self.assertTrue(res4.acquired)
        self.assertEqual(res4.fencing_token, 4)

        # Worker 4 finalizes with retry update (leaves record in PENDING_RETRY, clears lease)
        self.assertTrue(
            self.engine2.finalize_retry_record(
                self.event_id,
                "worker_4",
                4,
                status="PENDING_RETRY",
                retry_count=2,
            )
        )

        # Claim 5 after finalize: token 5 (monotonic)
        res5 = self.engine1.claim_retry_record(self.event_id, owner_id="worker_5", ttl_seconds=30.0)
        self.assertTrue(res5.acquired)
        self.assertEqual(res5.fencing_token, 5)

        # Finalize by deleting record
        self.assertTrue(
            self.engine1.finalize_retry_record(
                self.event_id,
                "worker_5",
                5,
                delete_record=True,
            )
        )
        self.assertEqual(self.engine1.list_pending_retries(), [])

    def test_auto_generated_owner_id_when_none_provided(self):
        """Verifies that an owner ID is automatically generated when none is supplied."""
        event_id = "EVT-AUTO-OWNER"
        self.engine1.save_retry_record(
            event_id=event_id,
            request_id="REQ-AUTO",
            payload={"test": "auto"},
            error_msg="auto error",
        )
        res = self.engine1.claim_retry_record(event_id, owner_id=None, ttl_seconds=30.0)
        self.assertTrue(res.acquired)
        self.assertTrue(len(res.owner_id) > 0, "Generated owner ID must be non-empty")
        self.assertTrue(self.engine1.validate_retry_claim(event_id, res.owner_id, res.fencing_token))

    def test_save_retry_record_rejects_active_lease_and_allows_after_expiry(self):
        """
        Verifies that save_retry_record() rejects an update while the record has an active lease,
        raises RuntimeError, rolls back cleanly, and allows an update after the lease expires
        while preserving the fencing token.
        """
        event_id = "EVT-SAVE-GUARD"
        # 1. New event can be inserted normally
        self.engine1.save_retry_record(
            event_id=event_id,
            request_id="REQ-SG-1",
            payload={"initial": "data"},
            error_msg="initial error",
        )
        # 2. Worker 1 claims with short TTL
        claim_res = self.engine1.claim_retry_record(event_id, owner_id="worker_1", ttl_seconds=0.05)
        self.assertTrue(claim_res.acquired)
        self.assertEqual(claim_res.fencing_token, 1)

        # 3. Concurrent save while active lease held must raise RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            self.engine2.save_retry_record(
                event_id=event_id,
                request_id="REQ-SG-OVERWRITE",
                payload={"overwritten": True},
                error_msg="should be rejected",
            )
        self.assertIn("actively leased", str(ctx.exception))

        # 4. Verify record retry data was NOT overwritten
        pending = self.engine1.list_pending_retries()
        record = next(r for r in pending if r["event_id"] == event_id)
        self.assertEqual(record["request_id"], "REQ-SG-1")
        self.assertEqual(record["payload"], {"initial": "data"})
        self.assertEqual(record["fencing_token"], 1)
        self.assertEqual(record["lease_owner"], "worker_1")

        # 5. Wait for lease to expire
        time.sleep(0.08)

        # 6. Once expired, save_retry_record must succeed and preserve fencing token
        self.engine2.save_retry_record(
            event_id=event_id,
            request_id="REQ-SG-UPDATED",
            payload={"updated_after_expiry": True},
            error_msg="updated error",
            retry_count=1,
        )
        pending = self.engine1.list_pending_retries()
        record = next(r for r in pending if r["event_id"] == event_id)
        self.assertEqual(record["request_id"], "REQ-SG-UPDATED")
        self.assertEqual(record["payload"], {"updated_after_expiry": True})
        self.assertEqual(record["fencing_token"], 1, "Fencing token must be preserved after update")

        # 7. Next claim increments fencing token monotonically
        next_claim = self.engine1.claim_retry_record(event_id, owner_id="worker_2", ttl_seconds=30.0)
        self.assertTrue(next_claim.acquired)
        self.assertEqual(next_claim.fencing_token, 2)
        self.assertEqual(next_claim.owner_id, "worker_2")


if __name__ == "__main__":
    unittest.main()
