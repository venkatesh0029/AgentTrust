"""
Comprehensive Acceptance and Concurrency Test Suite for Work Package #5:
Crash-Safe Reconciliation & Monotonic Fencing.

Verifies the 6 key distributed systems criteria:
1. Lease expiration: Recover work from workers that terminate unexpectedly.
2. Monotonic fencing tokens: Ensure an old worker cannot execute after a newer worker acquires ownership.
   - Includes the critical test: Worker 1 obtains token 41, pauses, loses lease.
     Worker 2 obtains token 42 and completes operation. Downstream service rejects token 41.
3. Crash-safe reconciliation: Recover pending outbox events after application restart.
4. External side-effect idempotency: Prevent duplicate financial or Fabric operations during retries.
5. Uncertain commit resolution: Distinguish committed, pending, and failed external operations.
6. Recovery testing: Inject process termination / failure at different points in the execution lifecycle.
"""

import datetime
import multiprocessing as mp
import os
import sqlite3
import tempfile
import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from action_gateway.retry_queue import RetryQueueManager
from fabric.fabric_client import FabricClient
from fabric.persistent_db import PersistentStorageEngine
from protected_api.finance_api import ProtectedFinanceAPI


# Top-level helper function for multiprocessing worker (Windows spawn compatible)
def _mp_worker_fencing_execution(db_path: str, agent_id: str, idempotency_key: str, fencing_token: int, queue: Any):
    """Executes a downstream action in a separate OS process with a specific fencing token."""
    finance_api = ProtectedFinanceAPI(persistent_db_path=db_path)
    auth_headers = finance_api.create_gateway_auth_headers(f"REQ-MP-{fencing_token}")
    res = finance_api.execute_action(
        action="TRANSFER_FUNDS",
        parameters={"amount": 2500.0, "target_account": "ACC-CORP-99", "currency": "INR"},
        gateway_token=finance_api.gateway_secret,
        request_id=f"REQ-MP-{fencing_token}",
        agent_id=agent_id,
        auth_headers=auth_headers,
        idempotency_key=idempotency_key,
        fencing_token=fencing_token
    )
    queue.put(res)


@pytest.fixture
def temp_env():
    """Allocates an isolated temporary directory and SQLite database path."""
    temp_dir = tempfile.mkdtemp(prefix="agenttrust_wp5_")
    db_path = os.path.join(temp_dir, "wp5_reconciliation.db")
    yield {"temp_dir": temp_dir, "db_path": db_path}
    try:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


class TestCrashSafeReconciliationAndFencing:
    """Test suite validating Work Package #5 requirements."""

    def test_01_lease_expiration_work_recovery(self, temp_env):
        """
        Criterion 1: Lease expiration.
        Worker 1 claims a retry record with a short TTL (0.05s) and terminates or stalls.
        When the lease expires, Worker 2 reclaims the record with an incremented fencing token
        and completes the reconciliation.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)

        ev_id = "EVT-LEASE-EXPIRY-001"
        payload = {
            "event_id": ev_id,
            "request_id": "REQ-EXPIRY-01",
            "agent_id": "AGENT-EXPIRY-01",
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "decision": "ALLOWED",
            "reason": "VALID",
        }
        storage.save_retry_record(
            event_id=ev_id,
            request_id="REQ-EXPIRY-01",
            payload=payload,
            error_msg="initial network drop",
            status="PENDING_RETRY"
        )

        # Worker 1 claims with very short TTL
        w1_claim = storage.claim_retry_record(ev_id, owner_id="worker_alpha", ttl_seconds=0.06)
        assert w1_claim.acquired is True
        assert w1_claim.fencing_token == 1
        assert w1_claim.owner_id == "worker_alpha"

        # Worker 2 attempts while Worker 1's lease is still active -> rejected
        w2_attempt = storage.claim_retry_record(ev_id, owner_id="worker_beta", ttl_seconds=30.0)
        assert w2_attempt.acquired is False
        assert w2_attempt.owner_id == "worker_alpha"

        # Wait for Worker 1's lease to expire
        time.sleep(0.1)

        # Worker 2 attempts after expiration -> successfully reclaims with incremented fencing token (token 2)
        w2_reclaim = storage.claim_retry_record(ev_id, owner_id="worker_beta", ttl_seconds=30.0)
        assert w2_reclaim.acquired is True
        assert w2_reclaim.fencing_token == 2
        assert w2_reclaim.owner_id == "worker_beta"

        # Worker 2 successfully finalizes the work
        finalized = storage.finalize_retry_record(
            ev_id,
            owner_id="worker_beta",
            fencing_token=2,
            delete_record=True
        )
        assert finalized is True
        assert storage.get_retry_record(ev_id) is None

    def test_02_monotonic_fencing_token_enforcement_at_downstream_boundary(self, temp_env):
        """
        Criterion 2: Monotonic fencing tokens at resource boundary.
        Worker 1 obtains fencing token 41, pauses, and loses its lease.
        Worker 2 obtains token 42 and completes the operation.
        When Worker 1 resumes, the downstream service (ProtectedFinanceAPI) MUST reject token 41.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)
        finance_api = ProtectedFinanceAPI(persistent_db_path=db_path)

        agent_id = "AGENT-FENCING-001"
        idemp_key = "IDEMP-TOKEN-SPLIT-BRAIN-99"

        # 1. Worker 1 claims lock and is seeded/acquired with fencing token 41
        # Set up in_flight_locks row directly with token 40 so next acquisition yields 41
        now = datetime.datetime.now(datetime.UTC).timestamp()
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT INTO in_flight_locks (scoped_key, agent_id, idempotency_key, owner_id, fencing_token, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (f"{agent_id}:{idemp_key}", agent_id, idemp_key, "worker_1", 40, now - 100, now - 10))

        # Worker 1 acquires the expired lock -> fencing token increments to 41, with 0.08s TTL
        w1_res = storage.try_acquire_in_flight_lock(agent_id, idemp_key, owner_id="worker_1", ttl_seconds=0.08)
        assert w1_res.acquired is True
        assert w1_res.fencing_token == 41
        assert w1_res.owner_id == "worker_1"

        # 2. Worker 1 pauses (simulated thread stall / GC pause / network delay)
        time.sleep(0.12)  # Worker 1's lease expires!

        # 3. Worker 2 detects lease expiration and claims lock -> receives token 42
        w2_res = storage.try_acquire_in_flight_lock(agent_id, idemp_key, owner_id="worker_2", ttl_seconds=30.0)
        assert w2_res.acquired is True
        assert w2_res.fencing_token == 42
        assert w2_res.owner_id == "worker_2"

        # 4. Worker 2 executes the operation on the downstream service with token 42
        auth_headers_w2 = finance_api.create_gateway_auth_headers("REQ-W2-001")
        exec_w2 = finance_api.execute_action(
            action="TRANSFER_FUNDS",
            parameters={"amount": 5000.0, "target_account": "ACC-TREASURY-01", "currency": "INR"},
            gateway_token=finance_api.gateway_secret,
            request_id="REQ-W2-001",
            agent_id=agent_id,
            auth_headers=auth_headers_w2,
            idempotency_key=idemp_key,
            fencing_token=42
        )
        assert exec_w2.get("success") is True
        assert exec_w2.get("transaction_data", {}).get("status") in ("TRANSFERRED", "COMPLETED")

        # 5. Worker 1 resumes and attempts to execute the operation with STALE token 41
        auth_headers_w1 = finance_api.create_gateway_auth_headers("REQ-W1-STALE")
        exec_w1 = finance_api.execute_action(
            action="TRANSFER_FUNDS",
            parameters={"amount": 5000.0, "target_account": "ACC-TREASURY-01", "currency": "INR"},
            gateway_token=finance_api.gateway_secret,
            request_id="REQ-W1-STALE",
            agent_id=agent_id,
            auth_headers=auth_headers_w1,
            idempotency_key=idemp_key,
            fencing_token=41  # Stale token!
        )

        # 6. Verification: Downstream service MUST reject token 41!
        assert exec_w1.get("success") is False
        assert exec_w1.get("error") == "STALE_FENCING_TOKEN"
        assert "Side-effect rejected at downstream boundary" in exec_w1.get("message", "")
        assert "41" in exec_w1.get("message", "")
        assert "42" in exec_w1.get("message", "")

    def test_03_crash_safe_reconciliation_after_restart(self, temp_env):
        """
        Criterion 3: Crash-safe reconciliation.
        Simulates process crash immediately after the atomic financial commit + outbox enqueue.
        Upon application restart, the reconciliation manager recovers pending outbox records,
        claims them with a valid lease, commits them to Fabric and marks the intent COMMITTED.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)
        finance_api = ProtectedFinanceAPI(persistent_db_path=db_path)

        req_id = "REQ-CRASH-SAFE-001"
        agent_id = "AGENT-CRASH-SAFE"
        ev_id = "EVT-CRASH-SAFE-OUTBOX-99"

        # Simulate Phase 1: Gateway executes action which commits financial record
        # and atomic outbox record to SQLite in a single transaction
        auth_headers = finance_api.create_gateway_auth_headers(req_id)
        outbox_payload = {
            "event_id": ev_id,
            "request_id": req_id,
            "agent_id": agent_id,
            "action": "TRANSFER_FUNDS",
            "amount": 12000.0,
            "idempotency_key": "IDEMP-CRASH-01",
            "payload": {
                "event_id": ev_id,
                "request_id": req_id,
                "agent_id": agent_id,
                "action": "TRANSFER_FUNDS",
                "resource": "BANK_RESERVE_IN",
                "decision": "ALLOWED",
                "reason": "POLICY_ALLOW",
            }
        }

        # Save intent as AUTHORIZED_PENDING_EXECUTION
        storage.save_intent(
            request_id=req_id,
            agent_id=agent_id,
            action="TRANSFER_FUNDS",
            amount=12000.0,
            idempotency_key="IDEMP-CRASH-01",
            state="AUTHORIZED_PENDING_EXECUTION"
        )

        # Commit financial transaction + atomic outbox record
        res = finance_api.execute_action(
            action="TRANSFER_FUNDS",
            parameters={"amount": 12000.0, "target_account": "ACC-SUPPLIER-01", "currency": "INR"},
            gateway_token=finance_api.gateway_secret,
            request_id=req_id,
            agent_id=agent_id,
            auth_headers=auth_headers,
            idempotency_key="IDEMP-CRASH-01",
            fencing_token=1,
            outbox_record=outbox_payload
        )
        assert res.get("success") is True

        # Verify financial state committed
        intent = storage.get_intent(req_id)
        assert intent["state"] == "EXECUTED_PENDING_LEDGER"
        pending_outbox = storage.list_pending_retries()
        assert len(pending_outbox) == 1
        assert pending_outbox[0]["event_id"] == ev_id

        # SIMULATE SYSTEM CRASH: Tear down current runtime objects completely
        del finance_api
        del storage

        # SIMULATE RESTART: Fresh process initializes services from SQLite
        restarted_storage = PersistentStorageEngine(db_path=db_path)
        restarted_queue = RetryQueueManager(persistent_db=restarted_storage)
        restarted_fabric = FabricClient(db_path=db_path)

        assert restarted_queue.pending_count() == 1

        # Background worker runs reconciliation on recovered outbox record
        ok, msg = restarted_queue.retry_commit(ev_id, restarted_fabric)
        assert ok is True
        assert msg == "RETRY_SUCCESSFUL"

        # Outbox queue is now empty
        assert restarted_queue.pending_count() == 0
        assert restarted_storage.list_pending_retries() == []

        # Fabric received the committed event
        committed_ev = restarted_fabric.get_event(ev_id)
        assert committed_ev is not None
        assert committed_ev["event_id"] == ev_id

    def test_04_external_side_effect_idempotency_on_retry(self, temp_env):
        """
        Criterion 4: External side-effect idempotency.
        Verifies that retrying an already committed event does NOT invoke duplicate
        external Fabric ledger transactions or duplicate financial operations.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)
        retry_mgr = RetryQueueManager(persistent_db=storage)

        ev_id = "EVT-IDEMP-RETRY-004"
        event_payload = {
            "event_id": ev_id,
            "request_id": "REQ-IDEMP-04",
            "agent_id": "AGENT-04",
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "decision": "ALLOWED",
            "reason": "VALID",
            "policy_id": "FIN-POLICY-001",
            "policy_version": "1.0",
            "evidence_reference": "EVID-IDEMP-04",
            "evidence_hash": "hash-idemp-04"
        }
        storage.save_retry_record(
            event_id=ev_id,
            request_id="REQ-IDEMP-04",
            payload=event_payload,
            error_msg="uncertain submit",
            status="PENDING_RETRY"
        )

        # Mock FabricClient where event is ALREADY committed on ledger
        mock_fabric = MagicMock()
        mock_fabric.get_event.return_value = event_payload.copy()

        ok, msg = retry_mgr.retry_commit(ev_id, mock_fabric)
        assert ok is True
        assert msg == "RETRY_SUCCESSFUL"

        # Crucial check: record_action_event was NOT called because event was already committed!
        mock_fabric.get_event.assert_called_once_with(ev_id)
        mock_fabric.record_action_event.assert_not_called()

        # Record is successfully cleaned from queue
        assert storage.list_pending_retries() == []

    def test_05_uncertain_commit_resolution_distinguishes_outcomes(self, temp_env):
        """
        Criterion 5: Uncertain commit resolution.
        When external commit status is uncertain (e.g. gateway timeout or connection reset),
        the system preserves uncertainty without incrementing retry count or advancing to DLQ.
        When connectivity recovers, it reconciles cleanly.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)
        retry_mgr = RetryQueueManager(persistent_db=storage)

        ev_id = "EVT-UNCERTAIN-005"
        payload = {
            "event_id": ev_id,
            "request_id": "REQ-UNCERTAIN-05",
            "agent_id": "AGENT-05",
            "action": "CREATE_PURCHASE_ORDER",
            "resource": "PROCUREMENT_VAULT",
            "decision": "ALLOWED",
            "reason": "POLICY_ALLOW",
            "policy_id": "PROC-POLICY-001",
            "policy_version": "1.0",
            "evidence_reference": "EVID-05",
            "evidence_hash": "h05"
        }
        storage.save_retry_record(
            event_id=ev_id,
            request_id="REQ-UNCERTAIN-05",
            payload=payload,
            error_msg="socket reset by peer",
            status="PENDING_RETRY"
        )

        mock_fabric = MagicMock()
        # Query fails with timeout
        mock_fabric.get_event.side_effect = TimeoutError("Fabric query timed out")

        ok, msg = retry_mgr.retry_commit(ev_id, mock_fabric)
        assert ok is False
        assert "RETRY_FAILED" in msg

        # Preserves uncertainty: retry count remains 0, record remains PENDING_RETRY
        rec = storage.get_retry_record(ev_id)
        assert rec["status"] == "PENDING_RETRY"
        assert rec["retry_count"] == 0

        # Now Fabric connection recovers and reveals the event was recorded
        mock_fabric.get_event.side_effect = None
        mock_fabric.get_event.return_value = payload.copy()

        ok2, msg2 = retry_mgr.retry_commit(ev_id, mock_fabric)
        assert ok2 is True
        assert msg2 == "RETRY_SUCCESSFUL"
        assert storage.get_retry_record(ev_id) is None

    def test_06_lifecycle_crash_injection_matrix(self, temp_env):
        """
        Criterion 6: Lifecycle failure injection matrix.
        Injects failures at three distinct points in the execution lifecycle:
        Point A: Crash after intent creation before financial commit.
        Point B: Crash after atomic financial commit before blockchain dispatch.
        Point C: Crash while worker holds active retry lease.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)
        finance_api = ProtectedFinanceAPI(persistent_db_path=db_path)

        # --- Point A: Failure before financial commit ---
        req_a = "REQ-INJECT-A"
        storage.save_intent(
            request_id=req_a,
            agent_id="AGENT-A",
            action="TRANSFER_FUNDS",
            amount=500.0,
            idempotency_key="IDEMP-A",
            state="AUTHORIZED_PENDING_EXECUTION"
        )
        # Crash occurs before finance_api.execute_action
        intent_a = storage.get_intent(req_a)
        assert intent_a["state"] == "AUTHORIZED_PENDING_EXECUTION"
        # Financial tables have zero transactions for REQ-A
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM financial_fund_transfers WHERE request_id = ?", (req_a,))
            assert cursor.fetchone()[0] == 0

        # --- Point B: Failure after financial commit before blockchain dispatch ---
        req_b = "REQ-INJECT-B"
        auth_b = finance_api.create_gateway_auth_headers(req_b)
        outbox_b = {
            "event_id": "EVT-INJECT-B",
            "request_id": req_b,
            "agent_id": "AGENT-B",
            "action": "TRANSFER_FUNDS",
            "amount": 1000.0,
            "idempotency_key": "IDEMP-B",
            "payload": {"event_id": "EVT-INJECT-B", "request_id": req_b, "agent_id": "AGENT-B", "action": "TRANSFER_FUNDS"}
        }
        finance_api.execute_action(
            action="TRANSFER_FUNDS",
            parameters={"amount": 1000.0, "target_account": "ACC-B", "currency": "INR"},
            gateway_token=finance_api.gateway_secret,
            request_id=req_b,
            agent_id="AGENT-B",
            auth_headers=auth_b,
            idempotency_key="IDEMP-B",
            fencing_token=1,
            outbox_record=outbox_b
        )
        # Verify financial transaction exists and outbox row exists in SQLite
        intent_b = storage.get_intent(req_b)
        assert intent_b["state"] == "EXECUTED_PENDING_LEDGER"
        assert len(storage.list_pending_retries()) == 1

        # --- Point C: Crash while worker holds active retry lease ---
        ev_c = "EVT-INJECT-C"
        storage.save_retry_record(ev_c, "REQ-C", {"action": "TX"}, "error", "PENDING_RETRY")
        claim_c = storage.claim_retry_record(ev_c, owner_id="crashing_worker", ttl_seconds=0.05)
        assert claim_c.acquired is True
        # Crashing worker dies immediately without finalization or release
        time.sleep(0.08)
        # Recovery worker claims expired record
        recovery_claim = storage.claim_retry_record(ev_c, owner_id="recovery_worker", ttl_seconds=30.0)
        assert recovery_claim.acquired is True
        assert recovery_claim.fencing_token == 2
        assert recovery_claim.owner_id == "recovery_worker"

    def test_07_concurrent_worker_fencing_cross_process(self, temp_env):
        """
        Criterion 7: Multi-process fencing enforcement.
        Runs downstream execution in separate OS processes using spawn context,
        confirming that a stale worker with fencing token 10 is rejected
        after another process has committed with fencing token 11.
        """
        db_path = temp_env["db_path"]
        agent_id = "AGENT-MP-FENCING"
        idemp_key = "IDEMP-MP-FENCING-001"

        # Process 1 executes with fencing token 11
        ctx = mp.get_context("spawn")
        q1 = ctx.Queue()
        p1 = ctx.Process(target=_mp_worker_fencing_execution, args=(db_path, agent_id, idemp_key, 11, q1))
        p1.start()
        res1 = q1.get(timeout=25)
        p1.join(timeout=10)

        assert res1.get("success") is True
        assert res1.get("transaction_data", {}).get("status") in ("TRANSFERRED", "COMPLETED")

        # Now Process 2 attempts with stale fencing token 10
        q2 = ctx.Queue()
        p2 = ctx.Process(target=_mp_worker_fencing_execution, args=(db_path, agent_id, idemp_key, 10, q2))
        p2.start()
        res2 = q2.get(timeout=25)
        p2.join(timeout=10)

        # Verification: Stale token 10 MUST be rejected across process boundaries!
        assert res2.get("success") is False
        assert res2.get("error") == "STALE_FENCING_TOKEN"

    def test_08_stale_worker_finalization_rejected(self, temp_env):
        """
        Criterion 8: Stale worker finalization rejection.
        Ensures that if Worker 1 pauses and Worker 2 claims the lease,
        Worker 1 cannot delete or mutate the retry record in SQLite.
        """
        db_path = temp_env["db_path"]
        storage = PersistentStorageEngine(db_path=db_path)

        ev_id = "EVT-STALE-FINALIZE-008"
        storage.save_retry_record(ev_id, "REQ-08", {"action": "TEST"}, "err", "PENDING_RETRY")

        # Worker 1 claims with token 1 and short TTL
        w1_claim = storage.claim_retry_record(ev_id, owner_id="worker_1", ttl_seconds=0.05)
        assert w1_claim.acquired is True
        assert w1_claim.fencing_token == 1

        time.sleep(0.08)  # Lease expires

        # Worker 2 reclaims with token 2
        w2_claim = storage.claim_retry_record(ev_id, owner_id="worker_2", ttl_seconds=30.0)
        assert w2_claim.acquired is True
        assert w2_claim.fencing_token == 2

        # Worker 1 attempts to finalize with stale token 1 -> MUST BE REJECTED!
        stale_finalized = storage.finalize_retry_record(
            ev_id,
            owner_id="worker_1",
            fencing_token=1,
            delete_record=True
        )
        assert stale_finalized is False

        # Record is still intact in SQLite for Worker 2
        rec = storage.get_retry_record(ev_id)
        assert rec is not None
        assert rec["fencing_token"] == 2
        assert rec["lease_owner"] == "worker_2"
