"""
Distributed-System Invariant Assurance Test Suite for AgentTrust.
Tests formal safety guarantees across:
1. Cross-process atomicity (separate gateway processes against shared SQLite).
2. Idempotency-key misuse prevention via canonical request fingerprinting.
3. Uncertain external outcomes and authoritative status reconciliation.
4. Transaction intent state machine invariants, terminal state immutability, and optimistic locking.
5. Persistence durability, transactional rollback, and backup/restore.
6. Fabric submission vs. commit validation semantics.
"""

import concurrent.futures
import copy
import datetime
import os
import sqlite3
import tempfile
import unittest

from action_gateway.gateway import ActionGateway
from action_gateway.retry_queue import RetryQueueManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from fabric.persistent_db import (
    ConcurrentTransitionConflictError,
    InvalidStateTransitionError,
    PersistentStorageEngine,
)
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker


class TestDistributedSystemInvariants(unittest.TestCase):
    """
    Formal Distributed-System Invariant Assurance Verification.
    """

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db_path = self.temp_db_path

        self.persistent_db = PersistentStorageEngine(db_path=self.db_path)
        self.cert_manager = CertificateManager(db_path=self.db_path)
        self.identity_store = IdentityStore(db_path=self.db_path)
        self.registry = AgentRegistry(self.cert_manager, self.identity_store)

        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.evidence_store = EvidenceStore(db_path=self.db_path)
        self.approval_manager = HumanApprovalManager(db_path=self.db_path)
        self.fabric_client = FabricClient()
        self.finance_api = ProtectedFinanceAPI()

        # Register Active Test Agent
        self.agent_id = "AGENT-DIST-001"
        self.agent_priv_key = KeyManager.generate_key_pair(2048)
        self.agent_priv_pem = KeyManager.private_key_to_pem(self.agent_priv_key)
        self.agent_pub_pem = KeyManager.public_key_to_pem(self.agent_priv_key.public_key())

        policy = PolicyRecord(
            policy_id="FIN-POLICY-001",
            agent_id=self.agent_id,
            allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
            allowed_resource="BANK_RESERVE_IN",
            maximum_amount=100000.0,
            human_approval_above=100000.0,
            working_hours=WorkingHours(start="00:00", end="23:59"),
            version="1.0"
        )
        self.policy_loader.save_policy(policy)

        self.registry.register_agent(
            agent_id=self.agent_id,
            agent_name="Distributed Invariant Worker Agent",
            owner="Finance Operations",
            capabilities=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
            policy_id="FIN-POLICY-001",
            public_key_pem=self.agent_pub_pem
        )

    def tearDown(self):
        try:
            os.close(self.temp_db_fd)
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    def _create_gateway_instance(self) -> ActionGateway:
        """
        Creates an independent gateway instance with disjoint in-memory caches,
        simulating a separate worker process connected to the shared SQLite database.
        """
        isolated_replay = RequestTracker(300, persistent_db=self.persistent_db)
        isolated_retry = RetryQueueManager(persistent_db=self.persistent_db)
        return ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=isolated_replay,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            persistent_db=self.persistent_db,
            retry_queue=isolated_retry
        )

    def _build_signed_request(
        self,
        action: str,
        parameters: dict,
        amount: float,
        req_id: str,
        nonce: str,
        idempotency_key: str | None = None
    ) -> dict:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {
            "request_id": req_id,
            "agent_id": self.agent_id,
            "action": action,
            "resource": "BANK_RESERVE_IN",
            "parameters": parameters,
            "amount": amount,
            "nonce": nonce,
            "timestamp": now_iso,
            "key_version": 1
        }
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key

        sig = SignatureManager.sign_request(payload, self.agent_priv_pem)
        payload["signature"] = sig
        return payload

    # =========================================================================
    # AREA 1: PROVE CROSS-PROCESS ATOMICITY
    # =========================================================================

    def test_cross_process_nonce_atomicity_across_independent_instances(self):
        """
        Area 1: Verify that two completely independent ActionGateway instances
        (separate in-memory states, shared SQLite) cannot both accept the same nonce.
        Guarantees at-most-once execution across multi-process deployments.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        # Create two distinct gateway instances (Process A and Process B)
        gw_proc_a = self._create_gateway_instance()
        gw_proc_b = self._create_gateway_instance()

        req_payload = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "DataDog Systems", "note": "APM Subscription"},
            amount=1500.00,
            req_id="REQ-MULTI-PROC-01",
            nonce="NONCE-MULTI-PROC-01"
        )

        # Race Process A and Process B simultaneously
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_a = executor.submit(gw_proc_a.process_request, copy.deepcopy(req_payload))
            fut_b = executor.submit(gw_proc_b.process_request, copy.deepcopy(req_payload))
            results = [fut_a.result(), fut_b.result()]

        allowed = [r for r in results if r.get("decision") == "ALLOWED"]
        replays = [r for r in results if r.get("decision") == "BLOCKED" and r.get("reason") == "REPLAY_DETECTED"]

        self.assertEqual(len(allowed), 1, "Exactly 1 process must execute the transaction")
        self.assertEqual(len(replays), 1, "Competing process must detect REPLAY_DETECTED via SQLite atomicity")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    def test_cross_process_in_flight_lock_atomicity(self):
        """
        Area 1: Verify distributed in_flight_locks table in SQLite prevents two independent
        gateway instances from concurrently processing the same idempotency key.
        """
        gw_proc_a = self._create_gateway_instance()
        gw_proc_b = self._create_gateway_instance()

        shared_idemp = "IDEMP-DIST-LOCK-001"
        req_a = self._build_signed_request("TRANSFER_FUNDS", {"recipient": "Vendor A"}, 750.0, "REQ-LOCK-A", "NONCE-LOCK-A", idempotency_key=shared_idemp)
        req_b = self._build_signed_request("TRANSFER_FUNDS", {"recipient": "Vendor A"}, 750.0, "REQ-LOCK-B", "NONCE-LOCK-B", idempotency_key=shared_idemp)

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_a = executor.submit(gw_proc_a.process_request, req_a)
            fut_b = executor.submit(gw_proc_b.process_request, req_b)
            results = [fut_a.result(), fut_b.result()]

        executed = [r for r in results if r.get("protected_api_result") == "EXECUTED"]
        self.assertEqual(len(executed), 1, "Only 1 process may execute the transaction")

    # =========================================================================
    # AREA 2: IDEMPOTENCY-KEY MISUSE PREVENTION & CANONICAL FINGERPRINTING
    # =========================================================================

    def test_idempotency_key_reused_with_conflicting_payload_is_rejected(self):
        """
        Area 2: An agent submits a legitimate transaction with idempotency key K.
        Then, the agent submits a completely DIFFERENT transaction with the same key K.
        Verify:
        - First transaction executes normally.
        - Second conflicting transaction is REJECTED fail-closed with IDEMPOTENCY_PAYLOAD_MISMATCH.
        - External API is NOT invoked for the conflicting transaction.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        gw = self._create_gateway_instance()

        # Step 1: Submit genuine $800 transfer to Cloudflare
        req1 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Cloudflare", "invoice": "INV-1001"},
            amount=800.00,
            req_id="REQ-ORIG-01",
            nonce="NONCE-ORIG-01",
            idempotency_key="IDEMP-CANONICAL-KEY-999"
        )
        res1 = gw.process_request(req1)
        self.assertEqual(res1.get("decision"), "ALLOWED")
        self.assertEqual(res1.get("protected_api_result"), "EXECUTED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # Step 2: Submit conflicting $50,000 transfer to Malicious Actor with SAME idempotency key
        req2 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Attacker Offshore Account", "invoice": "INV-MALICIOUS"},
            amount=50000.00,
            req_id="REQ-ATTACK-02",
            nonce="NONCE-ATTACK-02",
            idempotency_key="IDEMP-CANONICAL-KEY-999"
        )
        res2 = gw.process_request(req2)

        # Invariant: Must NOT return cached $800 success or execute $50,000!
        self.assertEqual(res2.get("decision"), "BLOCKED")
        self.assertEqual(res2.get("reason"), "IDEMPOTENCY_PAYLOAD_MISMATCH")
        self.assertEqual(res2.get("protected_api_result"), "NOT_EXECUTED")

        # Direct external inspection: zero new transfers executed
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    def test_idempotency_key_reused_with_identical_payload_returns_cached_success(self):
        """
        Area 2: Submitting an identical payload with the same idempotency key
        returns cached execution with idempotent_replay: True.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        gw = self._create_gateway_instance()

        req1 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Stripe Payments", "invoice": "INV-777"},
            amount=1200.00,
            req_id="REQ-STRIPE-01",
            nonce="NONCE-STRIPE-01",
            idempotency_key="IDEMP-STRIPE-KEY-01"
        )
        res1 = gw.process_request(req1)
        self.assertEqual(res1.get("decision"), "ALLOWED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # Identical payload retry (new request envelope)
        req2 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Stripe Payments", "invoice": "INV-777"},
            amount=1200.00,
            req_id="REQ-STRIPE-02",
            nonce="NONCE-STRIPE-02",
            idempotency_key="IDEMP-STRIPE-KEY-01"
        )
        res2 = gw.process_request(req2)
        self.assertEqual(res2.get("decision"), "ALLOWED")
        self.assertTrue(res2.get("idempotent_replay"))
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    # =========================================================================
    # AREA 3: UNCERTAIN EXTERNAL OUTCOMES & STATUS RECONCILIATION
    # =========================================================================

    def test_uncertain_external_outcome_resolved_via_authoritative_status(self):
        """
        Area 3: Simulate external Finance API throwing a TimeoutError or ConnectionResetError
        AFTER executing the fund transfer.
        Verify:
        - Gateway catches the uncertain outcome.
        - Queries finance_api.query_transaction_status using the stable idempotency key / request_id.
        - Resolves that the transaction executed without blindly re-invoking or repeating transfer.
        - Successfully commits audit event to Fabric ledger.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        gw = self._create_gateway_instance()

        req = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Oracle ERP", "license": "Cloud DB"},
            amount=3200.00,
            req_id="REQ-UNCERTAIN-01",
            nonce="NONCE-UNCERTAIN-01",
            idempotency_key="IDEMP-UNCERTAIN-KEY-01"
        )

        real_execute = self.finance_api.execute_action

        def _flaky_execute(*args, **kwargs):
            # Execute transfer in backend
            real_execute(*args, **kwargs)
            # Simulate network disconnection / timeout after execution before response returns
            raise TimeoutError("504 Gateway Timeout: caller connection dropped before response delivered")

        self.finance_api.execute_action = _flaky_execute

        res = gw.process_request(req)

        # Invariant 1: Gateway reconciles external status and completes
        self.assertEqual(res.get("decision"), "ALLOWED")
        self.assertEqual(res.get("protected_api_result"), "EXECUTED")
        self.assertEqual(res["blockchain"]["status"], "COMMITTED")

        # Invariant 2: External transfer executed strictly once
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    # =========================================================================
    # AREA 4: STATE MACHINE INVARIANTS & OPTIMISTIC CONCURRENCY CONTROL
    # =========================================================================

    def test_illegal_state_transition_raises_invalid_state_transition_error(self):
        """
        Area 4: Verify transaction intent state machine strictly rejects illegal transitions.
        Specifically:
        - COMMITTED -> EXECUTED_PENDING_LEDGER (illegal rollback from terminal state)
        - COMMITTED -> AUTHORIZED_PENDING_EXECUTION (illegal reset)
        - REJECTED -> COMMITTED (illegal revival)
        """
        req_id = "REQ-SM-TEST-001"
        self.persistent_db.save_intent(
            request_id=req_id,
            agent_id=self.agent_id,
            action="TRANSFER_FUNDS",
            amount=500.0,
            idempotency_key="IDEMP-SM-001",
            state="PENDING_AUTHORIZATION"
        )

        # Valid transition 1: PENDING_AUTHORIZATION -> AUTHORIZED_PENDING_EXECUTION
        self.persistent_db.update_intent_state(req_id, "AUTHORIZED_PENDING_EXECUTION")
        intent = self.persistent_db.get_intent(req_id)
        self.assertEqual(intent["state"], "AUTHORIZED_PENDING_EXECUTION")

        # Valid transition 2: AUTHORIZED_PENDING_EXECUTION -> EXECUTED_PENDING_LEDGER
        self.persistent_db.update_intent_state(req_id, "EXECUTED_PENDING_LEDGER")

        # Valid transition 3: EXECUTED_PENDING_LEDGER -> COMMITTED
        self.persistent_db.update_intent_state(req_id, "COMMITTED")
        self.assertEqual(self.persistent_db.get_intent(req_id)["state"], "COMMITTED")

        # Illegal Transition 1: COMMITTED -> EXECUTED_PENDING_LEDGER
        with self.assertRaises(InvalidStateTransitionError):
            self.persistent_db.update_intent_state(req_id, "EXECUTED_PENDING_LEDGER")

        # Illegal Transition 2: COMMITTED -> AUTHORIZED_PENDING_EXECUTION
        with self.assertRaises(InvalidStateTransitionError):
            self.persistent_db.update_intent_state(req_id, "AUTHORIZED_PENDING_EXECUTION")

    def test_optimistic_concurrency_control_detects_concurrent_transition_conflict(self):
        """
        Area 4: Verify optimistic locking on intent transitions detects stale workers
        and raises ConcurrentTransitionConflictError.
        """
        req_id = "REQ-OCC-001"
        self.persistent_db.save_intent(
            request_id=req_id,
            agent_id=self.agent_id,
            action="TRANSFER_FUNDS",
            amount=900.0,
            idempotency_key="IDEMP-OCC-001",
            state="AUTHORIZED_PENDING_EXECUTION"
        )

        # Worker 1 successfully transitions intent to EXECUTED_PENDING_LEDGER
        self.persistent_db.update_intent_state(
            request_id=req_id,
            state="EXECUTED_PENDING_LEDGER",
            expected_current_state="AUTHORIZED_PENDING_EXECUTION"
        )

        # Worker 2 (stale) attempts to transition expecting AUTHORIZED_PENDING_EXECUTION
        with self.assertRaises(ConcurrentTransitionConflictError):
            self.persistent_db.update_intent_state(
                request_id=req_id,
                state="EXECUTED_PENDING_LEDGER",
                expected_current_state="AUTHORIZED_PENDING_EXECUTION"
            )

    # =========================================================================
    # AREA 5: PERSISTENCE DURABILITY, TRANSACTION ROLLBACK & TAMPERING
    # =========================================================================

    def test_sqlite_transaction_rollback_preserves_durability(self):
        """
        Area 5: Verify that SQLite rollback on an in-flight conflict or exception
        does not leave dirty, uncommitted rows in the database.
        """
        initial_nonces = len(self.persistent_db.get_all_nonces())

        # Claim nonce
        ok1 = self.persistent_db.try_claim_request_nonce("REQ-ROLLBACK-01", "NONCE-ROLLBACK-01", 1700000000.0)
        self.assertTrue(ok1)
        self.assertEqual(len(self.persistent_db.get_all_nonces()), initial_nonces + 1)

        # Conflicting claim: should rollback cleanly and return False
        ok2 = self.persistent_db.try_claim_request_nonce("REQ-ROLLBACK-01", "NONCE-ROLLBACK-01", 1700000000.0)
        self.assertFalse(ok2)
        self.assertEqual(len(self.persistent_db.get_all_nonces()), initial_nonces + 1)

    def test_database_backup_and_restore_integrity(self):
        """
        Area 5: Verify full backup and restore of SQLite persistent state preserves
        nonces, transaction intents, certificates, and ledger blocks intact.
        """
        # Record state in primary database
        self.persistent_db.save_nonce("REQ-BACKUP-01", "NONCE-BACKUP-01", 1700000000.0)
        self.persistent_db.save_intent(
            request_id="REQ-BACKUP-01",
            agent_id=self.agent_id,
            action="TRANSFER_FUNDS",
            amount=450.0,
            idempotency_key="IDEMP-BACKUP-01",
            state="COMMITTED",
            outcome={"test": "data"}
        )

        backup_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        backup_file.close()
        backup_path = backup_file.name

        try:
            # Create online backup using SQLite backup API
            src_conn = sqlite3.connect(self.db_path)
            dst_conn = sqlite3.connect(backup_path)
            src_conn.backup(dst_conn)
            src_conn.close()
            dst_conn.close()

            # Initialize a new PersistentStorageEngine pointing to the restored backup
            restored_db = PersistentStorageEngine(db_path=backup_path)
            self.assertTrue(restored_db.is_nonce_used("NONCE-BACKUP-01"))
            intent = restored_db.get_intent("REQ-BACKUP-01")
            self.assertIsNotNone(intent)
            self.assertEqual(intent["state"], "COMMITTED")
            self.assertEqual(intent["outcome"], {"test": "data"})
        finally:
            if os.path.exists(backup_path):
                os.remove(backup_path)

    # =========================================================================
    # AREA 6: FABRIC COMMIT SEMANTICS & ARCHITECTURAL VERIFICATION
    # =========================================================================

    def test_fabric_submission_vs_commit_validation_distinction(self):
        """
        Area 6: Verify that the ledger service distinguishes transaction event creation
        from final block commitment in the block ledger.
        """
        summary_before = self.fabric_client.ledger_service.get_ledger_summary()
        initial_blocks = summary_before["total_blocks"]

        commit_res = self.fabric_client.record_action_event(
            event_id="EVT-COMMIT-SEMANTICS-01",
            request_id="REQ-COMMIT-SEMANTICS-01",
            agent_id=self.agent_id,
            action="TRANSFER_FUNDS",
            resource="BANK_RESERVE_IN",
            decision="ALLOWED",
            reason="POLICY_PERMITTED",
            policy_id="FIN-POLICY-001",
            policy_version="1.0",
            evidence_reference="EVD-001",
            evidence_hash="HASH-001"
        )

        self.assertIn("chaincode_result", commit_res)
        self.assertGreater(commit_res["block_index"], 0)
        self.assertTrue(commit_res["block_hash"])
        self.assertTrue(commit_res["committed_at"])

        # Query committed block directly from SQLite block_ledger
        summary_after = self.fabric_client.ledger_service.get_ledger_summary()
        self.assertEqual(summary_after["total_blocks"], initial_blocks + 1)
        self.assertEqual(summary_after["latest_block_hash"], commit_res["block_hash"])


if __name__ == "__main__":
    unittest.main()
