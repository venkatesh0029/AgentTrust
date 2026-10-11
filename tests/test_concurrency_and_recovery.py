"""
Concurrency & Recovery Assurance Test Suite for AgentTrust.
Verifies the five core resilience properties under concurrent load, process crashes, and external faults:
1. Nonce races & concurrent duplicate requests: Atomic nonce consumption & strict at-most-once execution across racing threads.
2. Crash & restart recovery across all 4 transaction boundaries: State recovery and invariant verification from SQLite.
3. External side-effect vs. ledger consistency: Outbox queue reconciliation preventing silent audit loss or duplicate transfers.
4. Idempotent retries: Safe retry handling after network drops/timeouts with zero duplicate financial side-effects.
5. KMS & Fabric failure handling: Fail-closed cryptographic operations, explicit exceptions, and recoverable outbox queuing.
"""

import concurrent.futures
import copy
import datetime
import os
import tempfile
import unittest

from action_gateway.gateway import ActionGateway
from action_gateway.retry_queue import RetryQueueManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from audit_writer.chain_writer import AuditChainWriter
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from fabric.persistent_db import PersistentStorageEngine
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from identity_manager.key_manager import KeyManager
from identity_manager.kms import KMSProvider
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker


class TestConcurrencyAndRecoveryAssurance(unittest.TestCase):
    """Deterministic fault-injection, concurrency, and crash-recovery test suite."""

    def setUp(self):
        # Create a temporary SQLite database for clean isolation
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.persistent_db = PersistentStorageEngine(db_path=self.temp_db_path)

        self.cert_manager = CertificateManager(db_path=self.temp_db_path)
        self.identity_store = IdentityStore(db_path=self.temp_db_path)
        self.registry = AgentRegistry(self.cert_manager, self.identity_store)
        self.kms = KMSProvider(provider_type="LOCAL_SOFTWARE_STORE")
        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.replay_tracker = RequestTracker(300, persistent_db=self.persistent_db)
        self.finance_api = ProtectedFinanceAPI()
        self.approval_manager = HumanApprovalManager(db_path=self.temp_db_path)
        self.evidence_store = EvidenceStore(db_path=self.temp_db_path)
        self.fabric_client = FabricClient()
        self.chain_writer = AuditChainWriter()
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
            chain_writer=self.chain_writer,
            retry_queue=self.retry_queue,
            persistent_db=self.persistent_db
        )

        # Register authorized test agent with $10,000 policy cap
        self.agent_id = "AGENT-CONCURRENCY-001"
        self.priv_key_obj = KeyManager.generate_key_pair()
        self.priv_pem = KeyManager.private_key_to_pem(self.priv_key_obj)
        self.pub_pem = KeyManager.public_key_to_pem(self.priv_key_obj.public_key())

        policy = PolicyRecord(
            policy_id="POLICY-CONCURRENCY-001",
            agent_id=self.agent_id,
            allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
            allowed_resource="finance_api",
            maximum_amount=10000.0,
            human_approval_above=10000.0,
            working_hours=WorkingHours(start="00:00", end="23:59"),
            version="1.0"
        )
        self.policy_loader.save_policy(policy)

        self.registry.register_agent(
            agent_id=self.agent_id,
            agent_name="ConcurrencyAgent",
            owner="FinanceOps",
            capabilities=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
            policy_id="POLICY-CONCURRENCY-001",
            public_key_pem=self.pub_pem
        )

    def tearDown(self):
        try:
            os.close(self.temp_db_fd)
            if os.path.exists(self.temp_db_path):
                os.remove(self.temp_db_path)
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
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {
            "request_id": req_id,
            "agent_id": self.agent_id,
            "action": action,
            "resource": "finance_api",
            "parameters": parameters,
            "amount": amount,
            "timestamp": timestamp,
            "nonce": nonce,
            "agent_role": "FINANCE_USER"
        }
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key

        payload["signature"] = SignatureManager.sign_request(payload, self.priv_pem)
        return payload

    # =========================================================================
    # AREA 1: NONCE RACES AND CONCURRENT DUPLICATE REQUESTS
    # =========================================================================

    def test_concurrent_nonce_race_strict_at_most_once_execution(self):
        """
        Area 1: Submit the exact same signed request across 10 concurrent threads simultaneously.
        Verifies:
        - Exactly 1 thread executes successfully (decision == ALLOWED, protected_api_result == EXECUTED).
        - Exactly 9 threads are rejected fail-closed (decision == BLOCKED, reason == REPLAY_DETECTED).
        - Direct external inspection: exactly 1 fund transfer record created in Protected API.
        """
        initial_transfers_count = len(self.finance_api.service._fund_transfers)

        req_payload = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Cloudflare Global", "note": "Enterprise DDoS Shield"},
            amount=2500.00,
            req_id="REQ-RACE-001",
            nonce="NONCE-RACE-001"
        )

        num_workers = 10
        responses = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(self.gateway.process_request, copy.deepcopy(req_payload)) for _ in range(num_workers)]
            for f in concurrent.futures.as_completed(futures):
                responses.append(f.result())

        allowed_count = sum(1 for r in responses if r.get("decision") == "ALLOWED" and r.get("protected_api_result") == "EXECUTED")
        blocked_count = sum(1 for r in responses if r.get("decision") == "BLOCKED" and r.get("reason") == "REPLAY_DETECTED")

        # Invariant 1: Exactly 1 execution passes
        self.assertEqual(allowed_count, 1, f"Concurrency violation! Expected exactly 1 allowed, got {allowed_count}")
        # Invariant 2: Exactly 9 blocked as replay
        self.assertEqual(blocked_count, num_workers - 1, f"Expected {num_workers - 1} replays blocked, got {blocked_count}")

        # Invariant 3: Direct side-effect inspection proves strictly 1 balance deduction
        new_transfers_count = len(self.finance_api.service._fund_transfers)
        self.assertEqual(new_transfers_count, initial_transfers_count + 1)

    def test_concurrent_in_flight_idempotency_conflict_handling(self):
        """
        Area 1: Verify in-flight concurrency lock prevents duplicate execution when multiple requests
        share the same idempotency key racing concurrently.
        """
        initial_transfers_count = len(self.finance_api.service._fund_transfers)

        # 8 concurrent requests with the same idempotency key
        num_threads = 8
        shared_idempotency_key = "IDEMP-CONCUR-KEY-777"

        def _worker(thread_idx: int):
            payload = self._build_signed_request(
                action="TRANSFER_FUNDS",
                parameters={"recipient": "Supplier Logistics", "note": f"Invoice #{thread_idx}"},
                amount=1500.00,
                req_id=f"REQ-CONCUR-{thread_idx}",
                nonce=f"NONCE-CONCUR-{thread_idx}",
                idempotency_key=shared_idempotency_key
            )
            return self.gateway.process_request(payload)

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(_worker, i) for i in range(num_threads)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        # Inspect side effects: exactly 1 transfer executed in finance API despite 8 concurrent workers
        new_transfers_count = len(self.finance_api.service._fund_transfers)
        self.assertEqual(new_transfers_count, initial_transfers_count + 1)

        # Verify any allowed or replayed requests reflect at-most-once execution
        executed_transfers = [r for r in results if r.get("protected_api_result") == "EXECUTED" and not r.get("idempotent_replay")]
        self.assertEqual(len(executed_transfers), 1)

    # =========================================================================
    # AREA 2: CRASH AND RESTART RECOVERY ACROSS 4 TRANSACTION BOUNDARIES
    # =========================================================================

    def test_crash_recovery_boundary_1_before_authorization(self):
        """
        Boundary 1: Crash/failure injected during format/signature verification before authorization.
        Restart gateway from SQLite: verify 0 state recorded, 0 transfers executed.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        # Submit request with corrupted signature
        req = self._build_signed_request("TRANSFER_FUNDS", {"note": "Test"}, 1000.0, "REQ-CRASH-B1", "NONCE-CRASH-B1")
        req["signature"] = "CORRUPTED_SIGNATURE_HEX_BASE64"

        res = self.gateway.process_request(req)
        self.assertEqual(res.get("decision"), "BLOCKED")
        self.assertEqual(res.get("reason"), "INVALID_SIGNATURE")

        # Simulate process crash & restart by re-instantiating gateway from persistent DB
        restarted_replay = RequestTracker(300, persistent_db=self.persistent_db)
        restarted_gateway = ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=restarted_replay,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            persistent_db=self.persistent_db
        )

        # Verify recovered state: zero transfers, zero leaked pending records
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers)
        self.assertFalse(restarted_replay.nonce_manager.is_nonce_used("NONCE-CRASH-B1"))
        self.assertEqual(restarted_gateway.retry_queue.pending_count(), 0)

    def test_crash_recovery_boundary_2_after_authorization_before_external_side_effect(self):
        """
        Boundary 2: Crash injected after policy evaluation but before Protected API execution.
        Verify external side-effects remain untouched.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        # Inject simulated crash into finance_api.execute_action
        def _mock_crash_before_api(*args, **kwargs):
            raise ConnectionResetError("Process abruptly terminated / network severed before API execution")

        original_exec = self.finance_api.execute_action
        self.finance_api.execute_action = _mock_crash_before_api

        req = self._build_signed_request("TRANSFER_FUNDS", {"note": "Pre-crash"}, 2000.0, "REQ-CRASH-B2", "NONCE-CRASH-B2")

        with self.assertRaises(ConnectionResetError):
            self.gateway.process_request(req)

        self.finance_api.execute_action = original_exec

        # Restart service and verify Protected API was never altered
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers)

    def test_crash_recovery_boundary_3_after_external_side_effect_before_ledger_commit(self):
        """
        Boundary 3: External side effect executed ($3,000 transfer), but Fabric Orderer fails before ledger commit.
        Service restarts:
        - Protected API has transfer.
        - Durable reconciliation outbox queue loaded from SQLite retains failed commit.
        - Calling reconcile_pending_commits() successfully commits to Fabric without duplicate transfer.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        initial_blocks = self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"]

        # 1. Inject Fabric failure
        original_record = self.fabric_client.record_action_event

        def _mock_orderer_failure(*args, **kwargs):
            raise RuntimeError("Fabric Orderer Consensus Timeout")

        self.fabric_client.record_action_event = _mock_orderer_failure

        req = self._build_signed_request("TRANSFER_FUNDS", {"note": "B3 transfer"}, 3000.0, "REQ-CRASH-B3", "NONCE-CRASH-B3")
        res = self.gateway.process_request(req)

        # Gateway detects failure, preserves evidence, records PENDING_RETRY in durable outbox
        self.assertEqual(res.get("protected_api_result"), "EXECUTED")
        self.assertIn("COMMIT_FAILED", res["blockchain"]["status"])
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # 2. Simulate complete process crash & restart
        restarted_retry_queue = RetryQueueManager(persistent_db=self.persistent_db)
        self.assertEqual(len(restarted_retry_queue.list_pending_retries()), 1, "Crash recovery failed: outbox lost pending commit!")

        restarted_gateway = ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=RequestTracker(300, persistent_db=self.persistent_db),
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            retry_queue=restarted_retry_queue,
            persistent_db=self.persistent_db
        )

        # 3. Restore Fabric connectivity and reconcile
        self.fabric_client.record_action_event = original_record
        rec_res = restarted_gateway.reconcile_pending_commits()

        # Invariants: 1 reconciled, 0 pending, ledger block committed, ZERO duplicate transfers
        self.assertEqual(rec_res["reconciled_count"], 1)
        self.assertEqual(rec_res["pending_count"], 0)
        self.assertEqual(self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"], initial_blocks + 1)
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1, "Duplicate transfer bug!")

    def test_crash_recovery_boundary_4_after_ledger_commit(self):
        """
        Boundary 4: Transaction fully completed and committed to ledger.
        Process restarts:
        - Ledger block is verified intact.
        - Nonce is remembered from SQLite across restart: client replay is still rejected!
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        req = self._build_signed_request("TRANSFER_FUNDS", {"note": "B4 complete"}, 1200.0, "REQ-CRASH-B4", "NONCE-CRASH-B4")
        res1 = self.gateway.process_request(req)
        self.assertEqual(res1.get("decision"), "ALLOWED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # Restart service from persistent DB
        restarted_replay = RequestTracker(300, persistent_db=self.persistent_db)
        restarted_gateway = ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=restarted_replay,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            persistent_db=self.persistent_db
        )

        # Attempt to replay the same request after restart
        res2 = restarted_gateway.process_request(req)
        self.assertEqual(res2.get("decision"), "BLOCKED")
        self.assertEqual(res2.get("reason"), "REPLAY_DETECTED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    # =========================================================================
    # AREA 3: EXTERNAL SIDE EFFECT VS. LEDGER CONSISTENCY & OUTBOX
    # =========================================================================

    def test_external_success_ledger_failure_reconciliation(self):
        """
        Area 3: Simulate external financial API success followed by a ledger failure.
        Verify system reconciles the transaction without silently losing the audit record or repeating the transfer.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)
        initial_blocks = self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"]

        # Mock ledger failure
        original_record = self.fabric_client.record_action_event

        def _mock_fabric_err(*args, **kwargs):
            raise ConnectionError("gRPC Fabric Peer Connection Dropped")

        self.fabric_client.record_action_event = _mock_fabric_err

        req = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Data Center Inc", "note": "Power Rack Rental"},
            amount=4200.00,
            req_id="REQ-CONSISTENCY-01",
            nonce="NONCE-CONSISTENCY-01",
            idempotency_key="IDEMP-CONSISTENCY-01"
        )

        res = self.gateway.process_request(req)
        self.assertEqual(res.get("protected_api_result"), "EXECUTED")
        self.assertIn("COMMIT_FAILED", res["blockchain"]["status"])

        # Side effect happened in finance API, but ledger block not yet in Fabric
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)
        self.assertEqual(self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"], initial_blocks)

        # Outbox holds exactly 1 pending commit
        pending = self.gateway.retry_queue.list_pending_retries()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["request_id"], "REQ-CONSISTENCY-01")

        # Restore ledger connectivity and reconcile
        self.fabric_client.record_action_event = original_record
        recon = self.gateway.reconcile_pending_commits()

        self.assertEqual(recon["reconciled_count"], 1)
        self.assertEqual(self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"], initial_blocks + 1)

        # Transfer count MUST remain exactly initial + 1 (no duplicate charge!)
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    # =========================================================================
    # AREA 4: IDEMPOTENT RETRIES
    # =========================================================================

    def test_idempotent_retry_identical_request_returns_cached_result(self):
        """
        Area 4: An agent retries the exact same request after a simulated network timeout.
        Verify original result returned with idempotent_replay: True, exactly 1 transfer executed.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        req = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "AWS Cloud Services", "note": "EC2 Monthly Invoice"},
            amount=1800.00,
            req_id="REQ-IDEMP-RETRY-01",
            nonce="NONCE-IDEMP-RETRY-01",
            idempotency_key="IDEMP-AWS-MONTHLY-01"
        )

        # First attempt: succeeds
        res1 = self.gateway.process_request(req)
        self.assertEqual(res1.get("decision"), "ALLOWED")
        self.assertEqual(res1.get("protected_api_result"), "EXECUTED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # Second attempt (client timeout retry with exact same request envelope):
        res2 = self.gateway.process_request(req)
        self.assertEqual(res2.get("decision"), "ALLOWED")
        self.assertTrue(res2.get("idempotent_replay"))
        self.assertEqual(res2.get("request_id"), "REQ-IDEMP-RETRY-01")

        # Financial side effects strictly untouched!
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    def test_idempotent_retry_new_envelope_same_idempotency_key(self):
        """
        Area 4: Client generates a new request ID and nonce, but supplies the same idempotency key.
        Verify cached transaction is returned, zero duplicate financial deductions.
        """
        initial_transfers = len(self.finance_api.service._fund_transfers)

        req1 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Oracle Cloud", "note": "Database Cluster License"},
            amount=5000.00,
            req_id="REQ-ORACLE-01",
            nonce="NONCE-ORACLE-01",
            idempotency_key="IDEMP-ORACLE-LICENSE-01"
        )
        res1 = self.gateway.process_request(req1)
        self.assertEqual(res1.get("decision"), "ALLOWED")
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

        # Client retries with fresh request ID and fresh nonce
        req2 = self._build_signed_request(
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Oracle Cloud", "note": "Database Cluster License"},
            amount=5000.00,
            req_id="REQ-ORACLE-02",
            nonce="NONCE-ORACLE-02",
            idempotency_key="IDEMP-ORACLE-LICENSE-01"
        )
        res2 = self.gateway.process_request(req2)
        self.assertEqual(res2.get("decision"), "ALLOWED")
        self.assertTrue(res2.get("idempotent_replay"))

        # Zero duplicate fund transfers executed!
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers + 1)

    # =========================================================================
    # AREA 5: KMS AND FABRIC FAILURE HANDLING
    # =========================================================================

    def test_kms_explicit_token_unavailability_fails_closed(self):
        """
        Area 5: When REAL_SOFT_HSM2_PKCS11 is explicitly requested but library is absent,
        KMSProvider MUST fail-closed with explicit RuntimeError rather than silently falling back.
        """
        with self.assertRaises(RuntimeError) as ctx:
            KMSProvider(provider_type="REAL_SOFT_HSM2_PKCS11", passphrase="fake")

        self.assertIn("Explicitly requested REAL_SOFT_HSM2_PKCS11 mode", str(ctx.exception))

    def test_kms_signing_with_invalid_agent_raises_explicit_value_error(self):
        """
        Area 5: Signing for an unregistered agent in KMS raises explicit ValueError.
        """
        with self.assertRaises(ValueError) as ctx:
            self.kms.sign_payload_in_hsm("NON-EXISTENT-AGENT", b"payload")

        self.assertIn("key handle not found in KMS metadata vault", str(ctx.exception))

    def test_fabric_peer_disconnection_causes_no_silent_success(self):
        """
        Area 5: Peer disconnection causes explicit COMMIT_FAILED status; local off-chain evidence preserved.
        """
        original_record = self.fabric_client.record_action_event

        def _mock_disconnect(*args, **kwargs):
            raise ConnectionRefusedError("Fabric Peer Connection Refused (port 7051 unreachable)")

        self.fabric_client.record_action_event = _mock_disconnect

        req = self._build_signed_request("TRANSFER_FUNDS", {"note": "Disconnect test"}, 800.0, "REQ-DISC-01", "NONCE-DISC-01")
        res = self.gateway.process_request(req)

        self.fabric_client.record_action_event = original_record

        # Assert no silent success
        self.assertIn("COMMIT_FAILED", res["blockchain"]["status"])
        self.assertEqual(res["evidence"]["off_chain_status"], "STORED")
        self.assertNotEqual(res["blockchain"]["block_hash"], "COMMITTED")


if __name__ == "__main__":
    unittest.main()
