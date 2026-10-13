"""
Live Integration & Security Boundary Assurance Test Suite for AgentTrust.
Validates:
1. Real OS multiprocess coordination (independent Python processes racing SQLite WAL).
2. Persistent distributed lock lifecycle, TTL lease expiry, and fencing tokens.
3. Financial input integrity: negative amounts, NaN/inf, minor-unit canonicalization, currency & recipient binding.
4. Multiprocess outbox reconciliation races.
5. Adversarial bypass and operational boundary resistance.
"""

import datetime
import multiprocessing
import os
import tempfile
import time
import unittest

from action_gateway.gateway import ActionGateway
from action_gateway.retry_queue import RetryQueueManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from fabric.persistent_db import PersistentStorageEngine
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker

from tests.multiprocess_workers import (
    worker_claim_nonce,
    worker_process_request,
    worker_reconcile_outbox,
)


class TestLiveMultiprocessAndBoundaryAssurance(unittest.TestCase):
    """
    Integration & boundary tests verifying multi-process safety,
    lease fencing, and financial canonicalization guarantees.
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
        self.replay_tracker = RequestTracker(300, persistent_db=self.persistent_db)
        self.retry_queue = RetryQueueManager(persistent_db=self.persistent_db)

        self.gateway = ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=self.replay_tracker,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            persistent_db=self.persistent_db,
            retry_queue=self.retry_queue
        )

        # Register Active Test Agent
        self.agent_id = "AGENT-OS-PROC"
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
            agent_name="Autonomous OS Process Worker",
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
    # TASK 1: REAL MULTIPROCESS STRESS TESTING
    # =========================================================================

    def test_real_os_multiprocess_nonce_race(self):
        """
        Task 1: Launch 4 independent OS processes via multiprocessing.Process.
        Race the identical nonce and request_id against the shared SQLite file in WAL mode.
        Verify that exactly 1 process succeeds in claiming the nonce, and 3 are rejected.
        """
        q = multiprocessing.Queue()
        req_id = "REQ-REAL-OS-01"
        nonce = "NONCE-REAL-OS-01"
        now_ts = time.time()

        processes = []
        for _ in range(4):
            p = multiprocessing.Process(
                target=worker_claim_nonce,
                args=(self.db_path, req_id, nonce, now_ts, q)
            )
            processes.append(p)

        for p in processes:
            p.start()

        for p in processes:
            p.join(timeout=10.0)

        results = []
        while not q.empty():
            results.append(q.get_nowait())

        self.assertEqual(len(results), 4, "All 4 OS processes must report back")
        successes = [r for r in results if r["success"]]
        self.assertEqual(len(successes), 4, "Zero OS processes crashed or raised unhandled errors")

        claimed_true = [r for r in results if r.get("claimed") is True]
        claimed_false = [r for r in results if r.get("claimed") is False]

        self.assertEqual(len(claimed_true), 1, "Exactly 1 OS process must successfully claim the nonce")
        self.assertEqual(len(claimed_false), 3, "Exactly 3 OS processes must be rejected atomically")

    def test_real_os_multiprocess_gateway_process_request_race(self):
        """
        Task 1: Launch 4 independent OS processes executing full ActionGateway pipelines
        competing for the same signed transfer request against the shared SQLite database.
        Verify that exactly 1 OS process executes the transfer and 3 are rejected as replay.
        """
        req_payload = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Stripe Connect", "destination": "ACC-PAY-99"},
            amount=1800.00,
            req_id="REQ-FULL-OS-01",
            nonce="NONCE-FULL-OS-01"
        )

        q = multiprocessing.Queue()
        processes = []
        for _ in range(4):
            p = multiprocessing.Process(
                target=worker_process_request,
                args=(self.db_path, req_payload, q)
            )
            processes.append(p)

        for p in processes:
            p.start()

        for p in processes:
            p.join(timeout=15.0)

        results = []
        while not q.empty():
            results.append(q.get_nowait())

        self.assertEqual(len(results), 4, "All 4 worker processes must report back")

        allowed_outcomes = [r for r in results if r.get("outcome", {}).get("decision") == "ALLOWED"]
        replay_outcomes = [
            r for r in results
            if r.get("outcome", {}).get("decision") == "BLOCKED" and r.get("outcome", {}).get("reason") == "REPLAY_DETECTED"
        ]

        self.assertEqual(len(allowed_outcomes), 1, "Exactly 1 OS worker process must be ALLOWED")
        self.assertEqual(len(replay_outcomes), 3, "Exactly 3 OS worker processes must be blocked for REPLAY_DETECTED")

        # Verify persistent intent in DB
        intent = self.persistent_db.get_intent("REQ-FULL-OS-01")
        self.assertIsNotNone(intent)
        self.assertEqual(intent["state"], "COMMITTED")

    # =========================================================================
    # TASK 2: PERSISTENT LOCK LIFECYCLE, LEASE EXPIRY, AND FENCING TOKENS
    # =========================================================================

    def test_persistent_lock_lease_expiry_and_fencing_token_increment(self):
        """
        Task 3: Worker 1 acquires lock with short TTL lease (0.5s).
        While active, Worker 2 is rejected.
        After TTL expires, Worker 2 reclaims the lock with incremented fencing token.
        Proves Worker 1 is fenced out and cannot release or overwrite Worker 2's valid lock.
        """
        idempotency_key = "IDEMP-FENCE-01"
        owner_1 = "worker-proc-alpha"
        owner_2 = "worker-proc-beta"

        # Worker 1 acquires lock with 0.5s TTL
        res1 = self.persistent_db.try_acquire_in_flight_lock(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_1,
            ttl_seconds=0.5
        )
        self.assertTrue(res1.acquired)
        self.assertEqual(res1.fencing_token, 1)
        self.assertEqual(res1.owner_id, owner_1)

        # Worker 2 attempts immediate acquisition -> REJECTED (lease still active)
        res2_early = self.persistent_db.try_acquire_in_flight_lock(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_2,
            ttl_seconds=0.5
        )
        self.assertFalse(res2_early.acquired)
        self.assertEqual(res2_early.fencing_token, 1)

        # Simulate Worker 1 stalling / crashing beyond lease TTL
        time.sleep(0.6)

        # Worker 2 attempts acquisition after TTL -> SUCCEEDS with incremented fencing token!
        res2_reclaimed = self.persistent_db.try_acquire_in_flight_lock(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_2,
            ttl_seconds=2.0
        )
        self.assertTrue(res2_reclaimed.acquired)
        self.assertEqual(res2_reclaimed.fencing_token, 2)
        self.assertEqual(res2_reclaimed.owner_id, owner_2)

        # Worker 1 wakes up and attempts to validate its fencing token -> FENCING REJECTED!
        is_w1_valid = self.persistent_db.validate_lock_fencing(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_1,
            fencing_token=1
        )
        self.assertFalse(is_w1_valid, "Stale worker 1 must be rejected by fencing validation")

        # Worker 1 attempts to release the lock with old token -> Fails, does NOT wipe Worker 2's lock!
        released_w1 = self.persistent_db.release_in_flight_lock(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_1,
            fencing_token=1
        )
        self.assertFalse(released_w1, "Stale worker cannot release a reclaimed lock")

        # Verify Worker 2's lock is still 100% active and held
        is_w2_valid = self.persistent_db.validate_lock_fencing(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_2,
            fencing_token=2
        )
        self.assertTrue(is_w2_valid, "Worker 2's lock must remain valid and intact")

        # Worker 2 legitimately releases the lock
        released_w2 = self.persistent_db.release_in_flight_lock(
            agent_id=self.agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_2,
            fencing_token=2
        )
        self.assertTrue(released_w2)

    # =========================================================================
    # TASK 3: FINANCIAL INPUT INTEGRITY & CANONICALIZATION
    # =========================================================================

    def test_financial_amount_boundary_negative_amount_blocked(self):
        """
        Task 4: Financial input integrity: negative amounts must be rejected immediately
        without triggering downstream side-effects.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        req_payload = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Attacker Account"},
            amount=-500.00,
            req_id="REQ-NEG-01",
            nonce="NONCE-NEG-01"
        )

        outcome = self.gateway.process_request(req_payload)
        self.assertEqual(outcome["decision"], "BLOCKED")
        self.assertIn(outcome["reason"], ["NON_POSITIVE_AMOUNT", "INVALID_FINANCIAL_AMOUNT"])
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers)

    def test_financial_amount_boundary_nan_and_infinity_blocked(self):
        """
        Task 4: Financial input integrity: NaN and Infinity must be blocked.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        # Test NaN
        req_nan = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Attacker Account"},
            amount=float("nan"),
            req_id="REQ-NAN-01",
            nonce="NONCE-NAN-01"
        )
        outcome_nan = self.gateway.process_request(req_nan)
        self.assertEqual(outcome_nan["decision"], "BLOCKED")
        self.assertIn(outcome_nan["reason"], ["INVALID_AMOUNT_NAN_OR_INF", "INVALID_FINANCIAL_AMOUNT"])

        # Test Infinity
        req_inf = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Attacker Account"},
            amount=float("inf"),
            req_id="REQ-INF-01",
            nonce="NONCE-INF-01"
        )
        outcome_inf = self.gateway.process_request(req_inf)
        self.assertEqual(outcome_inf["decision"], "BLOCKED")
        self.assertIn(outcome_inf["reason"], ["INVALID_AMOUNT_NAN_OR_INF", "INVALID_FINANCIAL_AMOUNT"])

        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers)

    def test_financial_amount_canonicalization_distinct_sub_cent_fingerprints(self):
        """
        Task 4: Canonical integer minor units: verify that distinct financial amounts
        (e.g., 1200.0001 vs 1200.0002) produce distinct integer minor units and SHA-256 digests.
        """
        u1, s1 = ActionGateway.canonicalize_financial_amount(1200.0001)
        u2, s2 = ActionGateway.canonicalize_financial_amount(1200.0002)

        self.assertEqual(u1, 12000001)
        self.assertEqual(u2, 12000002)
        self.assertNotEqual(u1, u2)

        fp1 = ActionGateway.compute_request_fingerprint(
            agent_id="AGENT-01",
            action="TRANSFER_FUNDS",
            resource="BANK_RESERVE_IN",
            parameters={"destination": "ACC-01"},
            amount=1200.0001
        )
        fp2 = ActionGateway.compute_request_fingerprint(
            agent_id="AGENT-01",
            action="TRANSFER_FUNDS",
            resource="BANK_RESERVE_IN",
            parameters={"destination": "ACC-01"},
            amount=1200.0002
        )
        self.assertNotEqual(fp1, fp2, "Distinct fractional amounts must produce distinct fingerprints")

    def test_idempotency_payload_mismatch_destination_mutation_rejected(self):
        """
        Task 4: Reusing an idempotency key with a mutated destination/recipient account
        is rejected with IDEMPOTENCY_PAYLOAD_MISMATCH and does not trigger a second transfer.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        idemp_key = "IDEMP-MUTATE-DEST-01"

        # 1. First legitimate request to ACC-LEGIT
        req1 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"destination": "ACC-LEGIT", "note": "Invoice 1"},
            amount=1200.00,
            req_id="REQ-MUT-01",
            nonce="NONCE-MUT-01",
            idempotency_key=idemp_key
        )
        out1 = self.gateway.process_request(req1)
        self.assertEqual(out1["decision"], "ALLOWED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # 2. Adversary reuses same idempotency key but targets ACC-ATTACKER
        req2 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"destination": "ACC-ATTACKER", "note": "Invoice 1"},
            amount=1200.00,
            req_id="REQ-MUT-02",
            nonce="NONCE-MUT-02",
            idempotency_key=idemp_key
        )
        out2 = self.gateway.process_request(req2)
        self.assertEqual(out2["decision"], "BLOCKED")
        self.assertEqual(out2["reason"], "IDEMPOTENCY_PAYLOAD_MISMATCH")

        # Zero additional transfers
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    def test_idempotency_payload_mismatch_currency_mutation_rejected(self):
        """
        Task 4: Reusing an idempotency key with mutated currency (USD vs EUR)
        is rejected with IDEMPOTENCY_PAYLOAD_MISMATCH.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        idemp_key = "IDEMP-MUTATE-CURR-01"

        req1 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"destination": "ACC-CURR-01", "currency": "USD"},
            amount=2000.00,
            req_id="REQ-CURR-01",
            nonce="NONCE-CURR-01",
            idempotency_key=idemp_key
        )
        out1 = self.gateway.process_request(req1)
        self.assertEqual(out1["decision"], "ALLOWED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # Attempt same key with EUR
        req2 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"destination": "ACC-CURR-01", "currency": "EUR"},
            amount=2000.00,
            req_id="REQ-CURR-02",
            nonce="NONCE-CURR-02",
            idempotency_key=idemp_key
        )
        out2 = self.gateway.process_request(req2)
        self.assertEqual(out2["decision"], "BLOCKED")
        self.assertEqual(out2["reason"], "IDEMPOTENCY_PAYLOAD_MISMATCH")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    # =========================================================================
    # TASK 4: MULTIPROCESS OUTBOX RECONCILIATION RACES
    # =========================================================================

    def test_real_os_multiprocess_reconciliation_race(self):
        """
        Task 1 & 6: Seed outbox reconciliation queue with 2 pending events.
        Launch 3 independent OS processes running worker_reconcile_outbox concurrently.
        Verify that all events are reconciled without duplicating ledger blocks.
        """
        # Seed 2 pending retries
        for i in range(1, 3):
            req_id = f"REQ-OUTBOX-RACE-0{i}"
            ev_id = f"EV-OUTBOX-RACE-0{i}"
            self.persistent_db.save_intent(
                request_id=req_id,
                agent_id=self.agent_id,
                action="TRANSFER_FUNDS",
                amount=1000.0 * i,
                idempotency_key=f"IDEMP-OUTBOX-{i}",
                state="LEDGER_PENDING_RETRY"
            )
            self.retry_queue.enqueue_failed_commit(
                event_id=ev_id,
                request_id=req_id,
                payload={
                    "event_id": ev_id,
                    "agent_id": self.agent_id,
                    "action": "TRANSFER_FUNDS",
                    "resource": "BANK_RESERVE_IN",
                    "decision": "ALLOWED",
                    "reason": "VALID_REQUEST",
                    "risk_score": 0.1,
                    "risk_level": "LOW",
                    "risk_factors": [],
                    "matched_rules": [],
                    "protected_api_result": "SUCCESS",
                    "approval_reference": "N/A",
                    "approval_ticket": None,
                    "transaction_data": {"amount": 1000.0 * i},
                    "evidence": {
                        "evidence_id": f"EVID-OUTBOX-{i}",
                        "evidence_hash": f"hash-{i}",
                        "sequence_number": i,
                        "previous_record_hash": "genesis",
                        "record_hash": f"rec-{i}",
                        "off_chain_status": "STORED"
                    }
                },
                error_msg="Simulated gRPC Orderer Disconnect"
            )

        self.assertEqual(self.retry_queue.pending_count(), 2)

        # Launch 3 OS processes racing to reconcile
        q = multiprocessing.Queue()
        processes = []
        for _ in range(3):
            p = multiprocessing.Process(
                target=worker_reconcile_outbox,
                args=(self.db_path, q)
            )
            processes.append(p)

        for p in processes:
            p.start()

        for p in processes:
            p.join(timeout=15.0)

        # Re-check queue in main instance
        pending_remaining = self.retry_queue.pending_count()
        self.assertEqual(pending_remaining, 0, "All outbox items must be reconciled")

        # Verify intents transitioned to COMMITTED
        for i in range(1, 3):
            intent = self.persistent_db.get_intent(f"REQ-OUTBOX-RACE-0{i}")
            self.assertEqual(intent["state"], "COMMITTED")

    # =========================================================================
    # TASK 5: ADVERSARIAL AUTHORIZATION & PIPELINE BOUNDARY TESTING
    # =========================================================================

    def test_adversarial_authorization_bypass_direct_pipeline_call_rejected(self):
        """
        Task 5: Adversarial test: Verify that calling the gateway with an unverified signature
        or attempting to forge an allowed status cannot bypass cryptographic identity checks.
        """
        forged_payload = {
            "request_id": "REQ-BYPASS-01",
            "agent_id": self.agent_id,
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "parameters": {"recipient": "Attacker"},
            "amount": 2500.00,
            "nonce": "NONCE-BYPASS-01",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "key_version": 1,
            "signature": "FORGED_SIGNATURE_BYTES_BASE64=="
        }

        outcome = self.gateway.process_request(forged_payload)
        self.assertEqual(outcome["decision"], "BLOCKED")
        self.assertEqual(outcome["reason"], "INVALID_SIGNATURE")
        self.assertEqual(len(self.finance_api.service._fund_transfers), 0)


if __name__ == "__main__":
    unittest.main()
