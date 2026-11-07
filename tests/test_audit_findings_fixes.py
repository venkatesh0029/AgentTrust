"""
Automated Test Suite for the 6 Core Audit & Architectural Findings:
1. P0: Agent private keys are not persisted in SQLite (persists key_reference only).
2. P0: Remove hardcoded gateway secret (dynamic provisioning and rotation).
3. P0: Financial transactions are durably persisted in SQLite across service restarts.
4. P1: Audit-chain recovery and tamper detection after restart.
5. P1: Audit persistence failure propagation and in-memory rollback.
6. P1: Fabric simulator persistence across restart and live-mode commit verification.
"""

import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from audit_writer.chain_writer import AuditChainWriter, AuditPersistenceError
from fabric.fabric_client import FabricClient
from fabric.ledger_service import FabricLedgerService
from fabric.persistent_db import PersistentStorageEngine
from identity_manager.certificate_manager import CertificateManager
from protected_api.finance_api import ProcurementService, ProtectedFinanceAPI


class TestAuditFindingsFixes(unittest.TestCase):
    """Verifies fixes for the negative findings and architectural limitations."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.temp_dir.name, "test_agenttrust.db")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # Finding 1 (P0): Agent private keys not stored in SQLite
    # --------------------------------------------------------------------------
    def test_p0_agent_private_keys_not_persisted_in_sqlite(self):
        """
        Verify that agent registration generates keys and returns the private key
        to the registrant for one-time initialization, but DOES NOT persist the
        plaintext private key into SQLite. Only opaque key references and public
        certificates are persisted.
        """
        _storage = PersistentStorageEngine(db_path=self.db_path)
        cert_mgr = CertificateManager(db_path=self.db_path)
        id_store = IdentityStore(db_path=self.db_path)
        registry = AgentRegistry(cert_mgr, id_store)

        agent_id = "SECURE-AGENT-001"
        reg_result = registry.register_agent(
            agent_id=agent_id,
            agent_name="Secure Agent",
            owner="FinanceOps"
        )

        # 1. The registrant receives the one-time generated private key for client-side signing
        self.assertIn("private_key", reg_result)
        self.assertTrue(reg_result["private_key"].startswith("-----BEGIN"))

        # 2. Direct inspection of SQLite database 'agents' table
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT agent_id, public_key, certificate, key_reference, private_key FROM agents WHERE agent_id = ?", (agent_id,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        # Assert private_key column in SQLite is NULL / empty
        self.assertIsNone(row["private_key"], "Private key MUST NOT be stored in plaintext in SQLite agents table!")
        # Assert key_reference column contains an opaque KMS/HSM reference
        self.assertIsNotNone(row["key_reference"])
        self.assertTrue(row["key_reference"].startswith("kms://"))
        self.assertTrue(row["public_key"].startswith("-----BEGIN"))

        # 3. Reading through IdentityStore retrieves public profile with private_key omitted
        reloaded_store = IdentityStore(db_path=self.db_path)
        loaded_agent = reloaded_store.get_agent(agent_id)
        self.assertIsNotNone(loaded_agent)
        self.assertIsNone(loaded_agent.get("private_key"))

    # --------------------------------------------------------------------------
    # Finding 2 (P0): Remove hardcoded gateway secret
    # --------------------------------------------------------------------------
    def test_p0_gateway_secret_dynamic_provisioning_and_no_hardcoded_credentials(self):
        """
        Verify that ProtectedFinanceAPI does not use a fixed hardcoded secret,
        allows dynamic provisioning and rotation, and denies unauthorized calls.
        """
        custom_secret = "SECURE-PROVISIONED-GATEWAY-SECRET-XYZ-999"
        api = ProtectedFinanceAPI(persistent_db_path=self.db_path, gateway_secret=custom_secret)

        self.assertEqual(api.gateway_secret, custom_secret)

        # Generate gateway auth headers
        headers = api.create_gateway_auth_headers("REQ-SEC-001")
        self.assertEqual(headers["X-Gateway-Token"], custom_secret)

        # Attempt call with wrong gateway secret -> must be denied
        denied_res = api.execute_action(
            action="CREATE_PURCHASE_ORDER",
            parameters={"supplier_id": "SUP-101", "amount": 500.0},
            gateway_token="WRONG-UNAUTHORIZED-SECRET",
            request_id="REQ-SEC-001",
            agent_id="AGENT-01",
            auth_headers=headers
        )
        self.assertFalse(denied_res["success"])
        self.assertEqual(denied_res["error"], "DIRECT_ACCESS_DENIED")

        # Authorized call with matching provisioned secret -> succeeds
        allowed_res = api.execute_action(
            action="CREATE_PURCHASE_ORDER",
            parameters={"supplier_id": "SUP-101", "amount": 500.0},
            gateway_token=custom_secret,
            request_id="REQ-SEC-001",
            agent_id="AGENT-01",
            auth_headers=headers
        )
        self.assertTrue(allowed_res["success"])
        self.assertEqual(allowed_res["api_result"], "EXECUTED")

        # Dynamic high-entropy secret generation when unconfigured
        with patch.dict(os.environ, {}, clear=True):
            ProtectedFinanceAPI._active_secret = None
            fresh_api = ProtectedFinanceAPI(persistent_db_path=self.db_path)
            self.assertIsNotNone(fresh_api.gateway_secret)
            self.assertGreaterEqual(len(fresh_api.gateway_secret), 32)
            # Must not be the old fixed string
            self.assertNotEqual(fresh_api.gateway_secret, "AGT-GATEWAY-INTERNAL-SECRET-KEY-98765")

    # --------------------------------------------------------------------------
    # Finding 3 (P0): Financial transactions durably persisted
    # --------------------------------------------------------------------------
    def test_p0_financial_transactions_durable_sqlite_persistence(self):
        """
        Verify that purchase orders, fund transfers, and reimbursements are
        durably written to SQLite and survive backend restarts.
        """
        service1 = ProcurementService(db_path=self.db_path)

        po = service1.create_purchase_order(
            request_id="REQ-PO-1",
            agent_id="AGENT-FIN-1",
            supplier_id="SUP-GLOBAL-1",
            item_name="Server Hardware",
            amount=15000.0,
            currency="USD"
        )
        tf = service1.create_fund_transfer(
            request_id="REQ-TF-1",
            agent_id="AGENT-FIN-1",
            target_account="ACC-CORP-888",
            amount=25000.0,
            currency="USD"
        )
        rb = service1.create_reimbursement(
            request_id="REQ-RB-1",
            agent_id="AGENT-FIN-1",
            employee_id="EMP-999",
            amount=1200.0,
            currency="USD"
        )

        po_id = po["po_id"]
        tf_id = tf["transaction_id"]
        rb_id = rb["transaction_id"]

        # Simulate backend restart with a brand new ProcurementService instance
        service2 = ProcurementService(db_path=self.db_path)

        # Retrieve records across restart
        restored_po = service2.get_purchase_order(po_id)
        restored_tf = service2.get_fund_transfer(tf_id)
        restored_rb = service2.get_reimbursement(rb_id)

        self.assertIsNotNone(restored_po, "Purchase order must survive backend restart!")
        self.assertEqual(restored_po["amount"], 15000.0)
        self.assertEqual(restored_po["item_name"], "Server Hardware")

        self.assertIsNotNone(restored_tf, "Fund transfer must survive backend restart!")
        self.assertEqual(restored_tf["amount"], 25000.0)
        self.assertEqual(restored_tf["target_account"], "ACC-CORP-888")

        self.assertIsNotNone(restored_rb, "Reimbursement must survive backend restart!")
        self.assertEqual(restored_rb["amount"], 1200.0)
        self.assertEqual(restored_rb["employee_id"], "EMP-999")

        # Sequence counters must continue without collision
        next_po = service2.create_purchase_order(
            request_id="REQ-PO-2",
            agent_id="AGENT-FIN-1",
            supplier_id="SUP-GLOBAL-2",
            item_name="Office Supplies",
            amount=500.0
        )
        self.assertNotEqual(next_po["po_id"], po_id)
        self.assertGreater(int(next_po["po_id"].split("-")[1]), int(po_id.split("-")[1]))

    # --------------------------------------------------------------------------
    # Finding 4 (P1): Audit-chain recovery after restart
    # --------------------------------------------------------------------------
    def test_p1_audit_chain_recovery_and_tamper_detection_after_restart(self):
        """
        Verify that AuditChainWriter rebuilds the full in-memory chain from
        persisted SQLite records upon restart, maintains sequence continuity,
        and detects historical tampering.
        """
        # Session 1: Create chain and append events
        writer1 = AuditChainWriter(db_path=self.db_path)
        writer1.write_event(
            event_type="ACTION_EXECUTED",
            request_id="REQ-AUDIT-001",
            agent_id="AGENT-01",
            request_hash="hash-req-001",
            risk_score=2.5,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS"
        )
        writer1.write_event(
            event_type="ACTION_EXECUTED",
            request_id="REQ-AUDIT-002",
            agent_id="AGENT-01",
            request_hash="hash-req-002",
            risk_score=3.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS"
        )

        integrity1 = writer1.verify_chain_integrity()
        self.assertTrue(integrity1["valid"])
        self.assertEqual(integrity1["total_records"], 3)  # Genesis + 2 events

        # Session 2: Backend restart with fresh AuditChainWriter
        writer2 = AuditChainWriter(db_path=self.db_path, auto_rehydrate=True)
        chain2 = writer2.get_chain()
        self.assertEqual(len(chain2), 3, "Audit chain must rehydrate all historical records across restart!")

        integrity2 = writer2.verify_chain_integrity()
        self.assertTrue(integrity2["valid"], "Rehydrated chain must be cryptographically intact!")
        self.assertEqual(integrity2["status"], "VERIFIED_INTACT")

        # Append next event in Session 2: sequence must continue from 3
        ev3 = writer2.write_event(
            event_type="ACTION_EXECUTED",
            request_id="REQ-AUDIT-003",
            agent_id="AGENT-01",
            request_hash="hash-req-003",
            risk_score=1.0,
            policy_version="1.0",
            decision="ALLOWED",
            execution_result="SUCCESS"
        )
        self.assertEqual(ev3.sequence_number, 3)
        self.assertEqual(len(writer2.get_chain()), 4)

        # Session 3: Tampering with SQLite database directly
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Tamper with block #2 (sequence 1)
        cursor.execute("SELECT block_number, block_data_json FROM block_ledger WHERE block_number > 1 LIMIT 1")
        row = cursor.fetchone()
        b_num, b_data_str = row[0], row[1]
        b_data = json.loads(b_data_str)
        b_data["decision"] = "FORGED_TAMPERED_DECISION"
        cursor.execute("UPDATE block_ledger SET block_data_json = ? WHERE block_number = ?", (json.dumps(b_data), b_num))
        conn.commit()
        conn.close()

        # Rehydrate in Session 4: Tamper must be caught during rehydration
        writer4 = AuditChainWriter(db_path=self.db_path, auto_rehydrate=True)
        integrity4 = writer4.verify_chain_integrity()
        # Either rehydration flagged the mismatch or verify_chain_integrity detects it
        self.assertFalse(integrity4["valid"])

    # --------------------------------------------------------------------------
    # Finding 5 (P1): Stop silently ignoring audit persistence failures
    # --------------------------------------------------------------------------
    def test_p1_audit_persistence_error_propagation_and_rollback(self):
        """
        Verify that write_event() raises AuditPersistenceError when SQLite write fails,
        and atomically rolls back the in-memory chain append so it does not falsely
        report uncommitted events.
        """
        writer = AuditChainWriter(db_path=self.db_path)
        initial_records = len(writer.get_chain())
        initial_seq = writer._current_sequence

        # Mock PersistentStorageEngine.save_block to raise an IO error
        with patch.object(PersistentStorageEngine, "save_block", side_effect=sqlite3.OperationalError("disk I/O error")):
            with self.assertRaises(AuditPersistenceError) as ctx:
                writer.write_event(
                    event_type="TRANSFER_FUNDS",
                    request_id="REQ-FAIL-PERSIST-1",
                    agent_id="AGENT-01",
                    request_hash="hash-fail-1",
                    risk_score=5.0,
                    policy_version="1.0",
                    decision="ALLOWED",
                    execution_result="SUCCESS"
                )
            self.assertIn("Durable audit persistence failed", str(ctx.exception))

        # Verify rollback: in-memory chain was NOT modified
        self.assertEqual(len(writer.get_chain()), initial_records)
        self.assertEqual(writer._current_sequence, initial_seq)

    # --------------------------------------------------------------------------
    # Finding 6 (P1): Fabric simulator persistence and live commit verification
    # --------------------------------------------------------------------------
    def test_p1_fabric_simulator_block_persistence_and_live_mode_metadata(self):
        """
        Verify that FabricLedgerService durably commits blocks to SQLite so
        the simulator survives restarts, and verify live gateway commit metadata.
        """
        # 1. Simulator persistence across restarts
        fabric_svc1 = FabricLedgerService(db_path=self.db_path)
        res1 = fabric_svc1.record_audit_event(
            event_id="EV-FAB-101",
            request_id="REQ-FAB-101",
            agent_id="AGENT-01",
            action="TRANSFER_FUNDS",
            resource="ACC-01",
            decision="ALLOWED",
            reason="POLICY_OK",
            policy_id="POL-01",
            policy_version="1.0",
            evidence_reference="EV-REF-101",
            evidence_hash="HASH-101"
        )
        self.assertGreater(res1["block_index"], 0)
        self.assertTrue(res1["block_hash"])

        # Re-instantiate FabricLedgerService with the same database
        fabric_svc2 = FabricLedgerService(db_path=self.db_path)
        summary = fabric_svc2.get_ledger_summary()
        self.assertGreaterEqual(summary["total_blocks"], 2, "Fabric simulator blocks must persist across restarts!")
        self.assertEqual(summary["latest_block_hash"], res1["block_hash"])

        # 2. FabricClient live mode commit verification
        fc = FabricClient(db_path=self.db_path)
        with patch.dict(os.environ, {
            "FABRIC_GATEWAY_MODE": "live",
            "FABRIC_GATEWAY_TOKEN": "a" * 32,
            "FABRIC_GATEWAY_URL": "http://127.0.0.1:8090"
        }):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "status": "COMMITTED",
                "tx_id": "TX-FABRIC-LIVE-9999",
                "block_index": 42,
                "block_hash": "0xabc123fabriccommittedhash",
                "result": {"payload": "committed_ok"}
            }

            with patch("httpx.Client.post", return_value=mock_resp):
                live_res = fc.record_action_event(
                    event_id="EV-LIVE-001",
                    request_id="REQ-LIVE-001",
                    agent_id="AGENT-01",
                    action="TRANSFER_FUNDS",
                    resource="ACC-01",
                    decision="ALLOWED",
                    reason="POLICY_OK",
                    policy_id="POL-01",
                    policy_version="1.0",
                    evidence_reference="EV-REF-001",
                    evidence_hash="HASH-001"
                )
                self.assertEqual(live_res["status"], "COMMITTED")
                self.assertEqual(live_res["mode"], "live")
                self.assertEqual(live_res["tx_id"], "TX-FABRIC-LIVE-9999")
                self.assertEqual(live_res["block_index"], 42)
                self.assertEqual(live_res["block_hash"], "0xabc123fabriccommittedhash")


if __name__ == "__main__":
    unittest.main()
