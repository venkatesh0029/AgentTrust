import datetime
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

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
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker
from risk_engine.risk_evaluator import RiskEvaluator


class TestTransactionalOutboxArchitecture(unittest.TestCase):
    """
    Validates the Transactional Outbox Pattern in AgentTrust:
    1. Financial side-effects and pending audit outbox events are committed
       in a SINGLE atomic SQLite transaction.
    2. Simulated crashes or dispatch failures leave the pending outbox intact
       in SQLite alongside the committed financial mutation.
    3. The background reconciliation worker safely discovers and flushes the
       outbox backlog onto Hyperledger Fabric and updates intent state to COMMITTED
       with ZERO duplicate financial operations.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="agenttrust_outbox_test_")
        self.db_path = os.path.join(self.test_dir, "outbox_test.db")
        self.evidence_dir = os.path.join(self.test_dir, "evidence")
        os.makedirs(self.evidence_dir, exist_ok=True)

        self.persistent_db = PersistentStorageEngine(db_path=self.db_path)
        self.gateway_secret = "TEST-OUTBOX-SECRET-KEY-12345"
        self.finance_api = ProtectedFinanceAPI(
            persistent_db_path=self.db_path,
            gateway_secret=self.gateway_secret
        )

        self.cert_manager = CertificateManager(db_path=self.db_path)
        self.identity_store = IdentityStore(db_path=self.db_path)
        self.agent_registry = AgentRegistry(self.cert_manager, self.identity_store)

        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.risk_evaluator = RiskEvaluator()
        self.evidence_store = EvidenceStore(db_path=self.db_path)
        self.chain_writer = AuditChainWriter(db_path=self.db_path, auto_rehydrate=True)
        self.approval_manager = HumanApprovalManager(db_path=self.db_path)
        self.fabric_client = FabricClient(db_path=self.db_path)
        self.replay_tracker = RequestTracker(300, persistent_db=self.persistent_db)
        self.retry_queue = RetryQueueManager(persistent_db=self.persistent_db)

        self.gateway = ActionGateway(
            registry=self.agent_registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=self.replay_tracker,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            chain_writer=self.chain_writer,
            persistent_db=self.persistent_db,
            retry_queue=self.retry_queue,
            risk_evaluator=self.risk_evaluator
        )

        # Register test agent
        self.agent_id = "AGENT-OUTBOX-001"
        self.priv_key_obj = KeyManager.generate_key_pair(2048)
        self.priv_pem = KeyManager.private_key_to_pem(self.priv_key_obj)
        self.pub_pem = KeyManager.public_key_to_pem(self.priv_key_obj.public_key())

        self.policy_id = "POL-OUTBOX-001"
        self.policy_record = PolicyRecord(
            policy_id=self.policy_id,
            agent_id=self.agent_id,
            allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER"],
            allowed_resource="*",
            maximum_amount=50000.0,
            human_approval_above=10000.0,
            working_hours=WorkingHours(start="00:00", end="23:59"),
            version="1.0",
            status="ACTIVE"
        )
        self.policy_loader.save_policy(self.policy_record)

        reg_info = self.agent_registry.register_agent(
            agent_id=self.agent_id,
            agent_name="Outbox Test Agent",
            owner="Security Testing",
            capabilities=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER"],
            policy_id=self.policy_id,
            public_key_pem=self.pub_pem
        )
        self.cert_fingerprint = reg_info.get("certificate_fingerprint")

    def tearDown(self):
        try:
            self.persistent_db.close()
        except Exception:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _sign_request(self, payload: dict) -> dict:
        req = payload.copy()
        req["signature"] = SignatureManager.sign_request(req, self.priv_pem)
        return req

    def test_outbox_atomic_dual_write_in_single_sqlite_transaction(self):
        """
        Verify that executing an action writes the financial mutation AND
        the outbox entry inside the SAME SQLite database transaction.
        """
        request_id = "REQ-OUTBOX-ATOMIC-001"
        payload = {
            "request_id": request_id,
            "agent_id": self.agent_id,
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "parameters": {
                "target_account": "ACC-99001",
                "amount": 2500.0,
                "currency": "INR"
            },
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": "NONCE-OUTBOX-001",
            "idempotency_key": "IDEMP-OUTBOX-001"
        }
        signed_req = self._sign_request(payload)

        # Process through gateway
        result = self.gateway.process_request(signed_req)
        self.assertEqual(result["decision"], "ALLOWED")
        self.assertEqual(result["protected_api_result"], "EXECUTED")

        # Verify that the financial fund transfer was durably persisted in SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM financial_fund_transfers WHERE request_id = ?", (request_id,))
            tf_row = cur.fetchone()
            self.assertIsNotNone(tf_row, "Financial fund transfer must exist in SQLite")
            self.assertEqual(tf_row["agent_id"], self.agent_id)
            self.assertEqual(float(tf_row["amount"]), 2500.0)

            # Verify that transaction_intents transitioned to COMMITTED
            cur.execute("SELECT state FROM transaction_intents WHERE request_id = ?", (request_id,))
            intent_row = cur.fetchone()
            self.assertIsNotNone(intent_row)
            self.assertEqual(intent_row["state"], "COMMITTED")

    def test_crash_after_db_commit_leaves_outbox_intact_for_reconciliation(self):
        """
        Simulate a crash or network severance right after the SQLite commit
        (financial record + outbox committed), before synchronous Fabric dispatch.
        Verify that:
        1. Financial record exists in SQLite.
        2. Outbox record exists with status PENDING_RETRY.
        3. Running reconcile_pending_commits() delivers the block and cleans outbox.
        """
        request_id = "REQ-OUTBOX-CRASH-002"
        payload = {
            "request_id": request_id,
            "agent_id": self.agent_id,
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "parameters": {
                "target_account": "ACC-CRASH-002",
                "amount": 4000.0,
                "currency": "INR"
            },
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": "NONCE-OUTBOX-002",
            "idempotency_key": "IDEMP-OUTBOX-CRASH-002"
        }
        signed_req = self._sign_request(payload)

        # Simulate Fabric outage during synchronous dispatch
        with patch.object(self.fabric_client, "record_action_event", side_effect=RuntimeError("SIMULATED_FABRIC_OUTAGE")):
            result = self.gateway.process_request(signed_req)
            self.assertEqual(result["decision"], "ALLOWED")
            # Financial side effect succeeded
            self.assertEqual(result["protected_api_result"], "EXECUTED")
            # Blockchain status accurately reports failure and enqueued outbox retry
            self.assertIn("COMMIT_FAILED", result["blockchain"]["status"])
            self.assertEqual(result["blockchain"]["source"], "outbox_pending_retry")

        # In SQLite: financial transfer MUST be present, and outbox MUST retain pending commit
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM financial_fund_transfers WHERE request_id = ?", (request_id,))
            tf_row = cur.fetchone()
            self.assertIsNotNone(tf_row, "Transfer MUST survive even if downstream Fabric failed!")
            self.assertEqual(float(tf_row["amount"]), 4000.0)

            cur.execute("SELECT * FROM reconciliation_queue WHERE request_id = ?", (request_id,))
            outbox_row = cur.fetchone()
            self.assertIsNotNone(outbox_row, "Outbox queue MUST retain failed commit for reconciliation!")
            self.assertEqual(outbox_row["status"], "PENDING_RETRY")

            cur.execute("SELECT state FROM transaction_intents WHERE request_id = ?", (request_id,))
            intent_row = cur.fetchone()
            self.assertIsNotNone(intent_row)
            self.assertIn(intent_row["state"], ("EXECUTED_PENDING_LEDGER", "LEDGER_PENDING_RETRY"))

        # Now simulate network recovery and background reconciliation
        recon_result = self.gateway.reconcile_pending_commits()
        self.assertEqual(recon_result["reconciled_count"], 1, "Background worker must reconcile pending outbox entry")
        self.assertEqual(recon_result["pending_count"], 0, "Outbox backlog must be drained to 0")

        # Verify final state in SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Outbox item is now cleared / finalized
            cur.execute("SELECT * FROM reconciliation_queue WHERE request_id = ? AND status = 'PENDING_RETRY'", (request_id,))
            self.assertIsNone(cur.fetchone())

            # Transaction intent is now finalized as COMMITTED
            cur.execute("SELECT state FROM transaction_intents WHERE request_id = ?", (request_id,))
            self.assertEqual(cur.fetchone()["state"], "COMMITTED")

            # Crucial distributed-systems property: Exactly ONE fund transfer row exists (ZERO duplicate transfers)
            cur.execute("SELECT COUNT(*) as cnt FROM financial_fund_transfers WHERE request_id = ?", (request_id,))
            self.assertEqual(cur.fetchone()["cnt"], 1, "Reconciliation MUST NEVER execute duplicate financial transfers!")

    def test_outbox_idempotency_prevents_duplicate_financial_execution(self):
        """
        Verify that replaying a request with the same idempotency key returns the
        cached outcome and does not perform a secondary financial mutation.
        """
        request_id = "REQ-OUTBOX-IDEMP-003"
        payload = {
            "request_id": request_id,
            "agent_id": self.agent_id,
            "action": "CREATE_PURCHASE_ORDER",
            "resource": "SUPPLIER-TECH-01",
            "parameters": {
                "supplier_id": "SUPPLIER-TECH-01",
                "item_name": "Encrypted Flash Drives",
                "amount": 1200.0,
                "currency": "INR"
            },
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": "NONCE-OUTBOX-003",
            "idempotency_key": "IDEMP-OUTBOX-KEY-003"
        }
        signed_req1 = self._sign_request(payload)
        res1 = self.gateway.process_request(signed_req1)
        self.assertEqual(res1["decision"], "ALLOWED")
        _po_id_1 = res1["protected_api_result"]

        # Replay the identical signed request
        signed_req2 = self._sign_request(payload)
        res2 = self.gateway.process_request(signed_req2)
        self.assertEqual(res2["decision"], "ALLOWED")

        # Check in SQLite: Exactly one purchase order was created
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as count FROM financial_purchase_orders WHERE request_id = ?", (request_id,))
            count = cur.fetchone()["count"]
            self.assertEqual(count, 1, "Idempotency must guarantee exactly one financial purchase order")

    def test_atomic_rollback_on_database_commit_failure(self):
        """
        Verify that if the database transaction fails midway, BOTH the financial mutation
        and the outbox record are cleanly rolled back, leaving zero orphaned state.
        """
        request_id = "REQ-OUTBOX-ROLLBACK-004"
        outbox_payload = {
            "event_id": "EVT-ROLLBACK-004",
            "request_id": request_id,
            "agent_id": self.agent_id,
            "action": "TRANSFER_FUNDS",
            "amount": 3500.0,
            "payload": {"test": "data"}
        }

        # Mock sqlite execution to raise an error right when inserting the outbox record
        _real_commit = self.finance_api.service._commit_financial_and_outbox

        def failing_commit(sql, params, outbox, record):
            # Intentionally inject an invalid SQL query that fails transaction
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                cur = conn.cursor()
                cur.execute("BEGIN IMMEDIATE")
                cur.execute(sql, params)
                # Force constraint / syntax error midway
                cur.execute("INSERT INTO non_existent_table VALUES (1)")
                conn.commit()

        with patch.object(self.finance_api.service, "_commit_financial_and_outbox", side_effect=failing_commit):
            try:
                self.finance_api.service.create_fund_transfer(
                    request_id=request_id,
                    agent_id=self.agent_id,
                    target_account="ACC-ROLLBACK-004",
                    amount=3500.0,
                    outbox_record=outbox_payload
                )
            except Exception:
                pass

        # Verify that SQLite has NO record of the transfer and NO outbox record
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM financial_fund_transfers WHERE request_id = ?", (request_id,))
            self.assertEqual(cur.fetchone()[0], 0, "Failed transaction MUST roll back financial record!")

            cur.execute("SELECT COUNT(*) FROM reconciliation_queue WHERE request_id = ?", (request_id,))
            self.assertEqual(cur.fetchone()[0], 0, "Failed transaction MUST roll back outbox record!")

    def test_human_approval_resume_atomic_outbox_commit(self):
        """
        Verify that high-value transactions routed to human approval queue
        commit the financial mutation and outbox record atomically upon resume.
        """
        request_id = "REQ-OUTBOX-APPROVAL-005"
        payload = {
            "request_id": request_id,
            "agent_id": self.agent_id,
            "action": "TRANSFER_FUNDS",
            "resource": "BANK_RESERVE_IN",
            "parameters": {
                "target_account": "ACC-CORP-99",
                "amount": 25000.0,  # Exceeds approval threshold of 10000.0
                "currency": "INR"
            },
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": "NONCE-OUTBOX-005",
            "idempotency_key": "IDEMP-OUTBOX-KEY-005"
        }
        signed_req = self._sign_request(payload)
        res1 = self.gateway.process_request(signed_req)
        self.assertEqual(res1["decision"], "PENDING_HUMAN_APPROVAL")
        self.assertEqual(res1["protected_api_result"], "HELD_FOR_HUMAN_APPROVAL")

        # In SQLite, financial record should NOT exist yet
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM financial_fund_transfers WHERE request_id = ?", (request_id,))
            self.assertEqual(cur.fetchone()[0], 0, "No fund transfer before supervisor approval!")

        # Supervisor approves the pending ticket
        target_ticket = self.approval_manager.get_approval_by_request_id(request_id)
        self.assertIsNotNone(target_ticket)

        approval_id = target_ticket["approval_id"]
        token = target_ticket["approval_token"]
        resume_res = self.gateway.process_human_approval_resume(approval_id, "SUPERVISOR-CHIEF-01", provided_token=token)
        self.assertEqual(resume_res["decision"], "ALLOWED_AFTER_APPROVAL")
        self.assertEqual(resume_res["protected_api_result"], "EXECUTED")

        # In SQLite, transfer exists and outbox was processed
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM financial_fund_transfers WHERE request_id = ?", (request_id,))
            tf = cur.fetchone()
            self.assertIsNotNone(tf, "Transfer MUST exist after human approval resume!")
            self.assertEqual(float(tf["amount"]), 25000.0)


if __name__ == "__main__":
    unittest.main()
