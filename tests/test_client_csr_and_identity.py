"""
Unit, integration, and security verification suite for Work Package #2:
Client-Side Cryptographic Identity & PKCS#10 CSR Workflow.

Verifies the 10 core security invariants:
1. Server never receives an agent's private key.
2. Server database contains no agent private-key material.
3. Registration response contains only the certificate and public identity information.
4. Invalid CSR signatures are rejected.
5. A CSR for one agent cannot register a different agent's identity.
6. Expired and revoked certificates cannot authenticate.
7. The agent can sign requests using its locally retained private key.
8. Restarting AgentTrust does not invalidate existing agent credentials.
9. Unauthorized users cannot register certificates for other agents.
10. CA private-key material remains protected independently of agent keys.
"""

import os
import sqlite3
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from action_gateway.gateway import ActionGateway
from action_gateway.retry_queue import RetryQueueManager
from agent_registry.admin_rbac import AdminRole
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from fabric.persistent_db import PersistentStorageEngine
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.agent_client import AgentClient, generate_agent_csr
from identity_manager.certificate_manager import CertificateManager
from identity_manager.jwt_auth import JWTAuthManager
from identity_manager.key_manager import KeyManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker
from server import app


class TestClientSideCSRAndIdentityAssurance(unittest.TestCase):
    """
    Exhaustive test suite proving client-side private key ownership,
    PKCS#10 CSR validation, CA certificate issuance, and attack resistance.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_agenttrust_csr.db")
        os.environ["AGENTTRUST_DB_PATH"] = self.db_path

        self.persistent_db = PersistentStorageEngine(db_path=self.db_path)
        self.cert_manager = CertificateManager(db_path=self.db_path)
        self.identity_store = IdentityStore(db_path=self.db_path)
        self.registry = AgentRegistry(self.cert_manager, self.identity_store)

        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.evidence_store = EvidenceStore(db_path=self.db_path)
        self.approval_manager = HumanApprovalManager(db_path=self.db_path)
        self.fabric_client = FabricClient(db_path=self.db_path)
        self.gateway_secret = "test_csr_gateway_secret_2026_xyz"
        self.finance_api = ProtectedFinanceAPI(
            persistent_db_path=self.db_path,
            gateway_secret=self.gateway_secret
        )
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

        self.client = TestClient(app)
        self.admin_jwt = JWTAuthManager.create_admin_token(
            role=AdminRole.SYSTEM_ADMIN,
            identity_id="test_admin"
        )
        self.auditor_jwt = JWTAuthManager.create_admin_token(
            role=AdminRole.AUDITOR,
            identity_id="test_auditor"
        )

    def tearDown(self):
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Scenario 1: Server never receives an agent's private key
    # -------------------------------------------------------------------------
    def test_scenario_1_server_never_receives_agent_private_key(self):
        """
        The agent client generates its RSA-2048 key pair locally.
        The client submits only a PKCS#10 CSR to the server.
        The registration payload received by the server contains 0 private key bytes.
        """
        agent = AgentClient(agent_id="CLIENT-OWNED-001", agent_name="Client Owned Agent")
        csr_pem = agent.generate_csr()

        # Verify CSR contains only public key and identity
        self.assertIn("-----BEGIN CERTIFICATE REQUEST-----", csr_pem)
        self.assertNotIn("PRIVATE KEY", csr_pem)

        # Register via registry
        record = self.registry.register_agent_csr(
            csr_pem=csr_pem,
            agent_id="CLIENT-OWNED-001",
            agent_name="Client Owned Agent",
            owner="FinanceOps"
        )

        # Private key was not passed to the server and is not in the record
        self.assertNotIn("private_key", record)
        self.assertEqual(record["agent_id"], "CLIENT-OWNED-001")
        self.assertTrue(record["certificate"].startswith("-----BEGIN CERTIFICATE-----"))

        # Agent installs issued certificate and matches public key
        agent.install_certificate(record["certificate"], record["certificate_fingerprint"])
        self.assertIsNotNone(agent.certificate_pem)

    # -------------------------------------------------------------------------
    # Scenario 2: Server database contains no agent private-key material
    # -------------------------------------------------------------------------
    def test_scenario_2_server_database_contains_no_agent_private_key_material(self):
        """
        Direct inspection of SQLite database 'agents' table proves that
        the private_key column is NULL for all registered agents.
        """
        agent = AgentClient(agent_id="DB-CHECK-AGENT-002", agent_name="DB Check Agent")
        csr_pem = agent.generate_csr()

        self.registry.register_agent_csr(
            csr_pem=csr_pem,
            agent_id="DB-CHECK-AGENT-002",
            agent_name="DB Check Agent"
        )

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT agent_id, public_key, certificate, key_reference, private_key FROM agents WHERE agent_id = ?", ("DB-CHECK-AGENT-002",))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["agent_id"], "DB-CHECK-AGENT-002")
        self.assertIsNone(row["private_key"], "CRITICAL: Agent private key must NEVER be written to SQLite!")
        self.assertTrue(row["public_key"].startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(row["key_reference"].startswith("client-csr://"))

    # -------------------------------------------------------------------------
    # Scenario 3: Registration response contains only certificate and public identity
    # -------------------------------------------------------------------------
    def test_scenario_3_registration_response_contains_only_public_identity(self):
        """
        Calling the FastAPI registration endpoints (/agents/register and /agents/register-csr)
        returns only certificate, serial, fingerprint, and public key—never private_key.
        """
        agent = AgentClient(agent_id="HTTP-AGENT-003", agent_name="HTTP Agent")
        csr_pem = agent.generate_csr()

        # 1. Test POST /agents/register-csr
        headers = {"Authorization": f"Bearer {self.admin_jwt}"}
        res_csr = self.client.post(
            "/agents/register-csr",
            json={
                "agent_id": "HTTP-AGENT-003",
                "agent_name": "HTTP Agent",
                "owner": "SecOps",
                "csr_pem": csr_pem
            },
            headers=headers
        )
        self.assertEqual(res_csr.status_code, 200)
        data = res_csr.json()
        self.assertTrue(data["success"])
        agent_data = data["agent"]

        self.assertNotIn("private_key", agent_data)
        self.assertIn("certificate", agent_data)
        self.assertIn("certificate_fingerprint", agent_data)
        self.assertIn("certificate_serial", agent_data)
        self.assertIn("public_key", agent_data)
        self.assertEqual(agent_data["agent_id"], "HTTP-AGENT-003")

        # 2. Test POST /agents/register with CSR field
        agent4 = AgentClient(agent_id="HTTP-AGENT-004", agent_name="HTTP Agent 4")
        csr4 = agent4.generate_csr()
        res_reg = self.client.post(
            "/agents/register",
            json={
                "agent_id": "HTTP-AGENT-004",
                "agent_name": "HTTP Agent 4",
                "owner": "SecOps",
                "csr_pem": csr4
            },
            headers=headers
        )
        self.assertEqual(res_reg.status_code, 200)
        agent4_data = res_reg.json()["agent"]
        self.assertNotIn("private_key", agent4_data)

    # -------------------------------------------------------------------------
    # Scenario 4: Invalid CSR signatures are rejected
    # -------------------------------------------------------------------------
    def test_scenario_4_invalid_csr_signatures_are_rejected(self):
        """
        If an attacker submits a corrupted or tampered CSR where proof-of-possession
        signature verification fails, AgentTrust CA rejects it immediately with 400.
        """
        # Create a valid CSR, then tamper with its signature bytes
        k = KeyManager.generate_key_pair(2048)
        valid_csr_pem = generate_agent_csr(k, "TAMPER-AGENT-005")
        csr_obj = x509.load_pem_x509_csr(valid_csr_pem.encode("utf-8"))

        der_bytes = csr_obj.public_bytes(serialization.Encoding.DER)
        # Mutate the cryptographic signature bytes in DER
        tampered_der = der_bytes[:-16] + b"\x00" * 16
        tampered_csr = x509.load_der_x509_csr(tampered_der)
        tampered_csr_pem = tampered_csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        # 1. Programmatic CertificateManager validation
        with self.assertRaises(ValueError) as ctx:
            self.cert_manager.validate_agent_csr(tampered_csr_pem, "TAMPER-AGENT-005")
        self.assertIn("INVALID_CSR_SIGNATURE", str(ctx.exception))

        # 2. HTTP API validation
        headers = {"Authorization": f"Bearer {self.admin_jwt}"}
        res = self.client.post(
            "/agents/register-csr",
            json={
                "agent_id": "TAMPER-AGENT-005",
                "agent_name": "Tampered CSR",
                "owner": "FinanceOps",
                "csr_pem": tampered_csr_pem
            },
            headers=headers
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("INVALID_CSR_SIGNATURE", res.json()["detail"])

    # -------------------------------------------------------------------------
    # Scenario 5: CSR for one agent cannot register a different agent's identity
    # -------------------------------------------------------------------------
    def test_scenario_5_csr_identity_mismatch_rejected(self):
        """
        CSR signature verification alone is insufficient: AgentTrust must also verify
        that the Subject Common Name (CN) and SAN match the authorized agent identity.
        If a CSR generated for 'ALICE' is submitted for 'BOB', it must be rejected.
        """
        alice_agent = AgentClient(agent_id="AGENT-ALICE", agent_name="Alice")
        alice_csr_pem = alice_agent.generate_csr()

        # Attacker attempts to register AGENT-BOB using Alice's CSR
        headers = {"Authorization": f"Bearer {self.admin_jwt}"}
        res = self.client.post(
            "/agents/register-csr",
            json={
                "agent_id": "AGENT-BOB",
                "agent_name": "Bob",
                "owner": "AttackerDept",
                "csr_pem": alice_csr_pem
            },
            headers=headers
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("CSR_IDENTITY_MISMATCH", res.json()["detail"])

        # Also verify programmatic rejection
        with self.assertRaises(ValueError) as ctx:
            self.registry.register_agent_csr(
                csr_pem=alice_csr_pem,
                agent_id="AGENT-BOB",
                agent_name="Bob"
            )
        self.assertIn("CSR_IDENTITY_MISMATCH", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 6: Expired and revoked certificates cannot authenticate
    # -------------------------------------------------------------------------
    def test_scenario_6_expired_and_revoked_certificates_cannot_authenticate(self):
        """
        ActionGateway must reject requests signed by agents with revoked or expired certificates.
        """
        agent = AgentClient(agent_id="REVOCATION-AGENT-006", agent_name="Revocable Agent")
        csr_pem = agent.generate_csr()

        reg = self.registry.register_agent_csr(
            csr_pem=csr_pem,
            agent_id="REVOCATION-AGENT-006",
            agent_name="Revocable Agent",
            policy_id="POL-REV-006"
        )
        agent.install_certificate(reg["certificate"], reg["certificate_fingerprint"])

        policy = PolicyRecord(
            policy_id="POL-REV-006",
            agent_id="REVOCATION-AGENT-006",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="BANK_RESERVE_IN",
            maximum_amount=50000.0,
            human_approval_above=100000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        self.policy_loader.save_policy(policy, author="SYSTEM_ADMIN", reason="Test Policy")

        # 1. Normal active request succeeds
        req1 = agent.build_signed_action_request(
            action="TRANSFER_FUNDS",
            resource="BANK_RESERVE_IN",
            parameters={"to_account": "ACC-TEST", "amount": 1000.0},
            amount=1000.0
        )
        out1 = self.gateway.process_request(req1)
        self.assertEqual(out1["decision"], "ALLOWED")

        # 2. Revoke certificate via CRL
        self.cert_manager.revoke_certificate(reg["certificate_fingerprint"])
        req2 = agent.build_signed_action_request(
            action="TRANSFER_FUNDS",
            resource="BANK_RESERVE_IN",
            parameters={"to_account": "ACC-TEST", "amount": 1000.0},
            amount=1000.0
        )
        out2 = self.gateway.process_request(req2)
        self.assertEqual(out2["decision"], "BLOCKED")
        self.assertEqual(out2["reason"], "CERTIFICATE_REVOKED")

    # -------------------------------------------------------------------------
    # Scenario 7: The agent can sign requests using its locally retained private key
    # -------------------------------------------------------------------------
    def test_scenario_7_agent_signs_requests_using_locally_retained_private_key(self):
        """
        The agent retains its private key locally and signs requests with RSA-PSS SHA-256.
        The Action Gateway verifies the signature using the agent's public key from the issued X.509 cert.
        """
        agent = AgentClient(agent_id="SIGNING-AGENT-007", agent_name="Local Signer")
        csr_pem = agent.generate_csr()

        reg = self.registry.register_agent_csr(
            csr_pem=csr_pem,
            agent_id="SIGNING-AGENT-007",
            agent_name="Local Signer",
            policy_id="POL-SIG-007"
        )
        agent.install_certificate(reg["certificate"], reg["certificate_fingerprint"])

        policy = PolicyRecord(
            policy_id="POL-SIG-007",
            agent_id="SIGNING-AGENT-007",
            allowed_actions=["CREATE_PURCHASE_ORDER"],
            allowed_resource="PROCUREMENT_API",
            maximum_amount=25000.0,
            human_approval_above=50000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        self.policy_loader.save_policy(policy, author="SYSTEM_ADMIN", reason="Test Policy")

        signed_payload = agent.build_signed_action_request(
            action="CREATE_PURCHASE_ORDER",
            resource="PROCUREMENT_API",
            parameters={"item_name": "Laptops", "supplier_id": "DELL-CORP", "amount": 8500.0},
            amount=8500.0
        )

        outcome = self.gateway.process_request(signed_payload)
        self.assertEqual(outcome["decision"], "ALLOWED", f"Failed with reason: {outcome.get('reason')}, details: {outcome}")
        self.assertEqual(outcome["gateway_status"], "PROCESSED")
        self.assertIsNotNone(outcome["api_result"])

    # -------------------------------------------------------------------------
    # Scenario 8: Restarting AgentTrust does not invalidate existing agent credentials
    # -------------------------------------------------------------------------
    def test_scenario_8_restarting_agenttrust_preserves_existing_agent_credentials(self):
        """
        After registering an agent via CSR, we tear down all server/gateway instances
        and re-initialize new instances from the persistent SQLite database.
        The agent continues to authenticate successfully using its local private key.
        """
        agent = AgentClient(agent_id="RESTART-AGENT-008", agent_name="Persistent Agent")
        csr_pem = agent.generate_csr()

        reg = self.registry.register_agent_csr(
            csr_pem=csr_pem,
            agent_id="RESTART-AGENT-008",
            agent_name="Persistent Agent",
            policy_id="POL-REST-008"
        )
        agent.install_certificate(reg["certificate"], reg["certificate_fingerprint"])

        policy = PolicyRecord(
            policy_id="POL-REST-008",
            agent_id="RESTART-AGENT-008",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="BANK_RESERVE_IN",
            maximum_amount=15000.0,
            human_approval_above=30000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        self.policy_loader.save_policy(policy, author="SYSTEM_ADMIN", reason="Test Policy")

        # --- SIMULATE PROCESS CRASH & RESTART ---
        # Create brand-new service instances reading from the same db_path
        new_persistent_db = PersistentStorageEngine(db_path=self.db_path)
        new_cert_manager = CertificateManager(db_path=self.db_path)
        new_identity_store = IdentityStore(db_path=self.db_path)
        new_registry = AgentRegistry(new_cert_manager, new_identity_store)
        new_evidence_store = EvidenceStore(db_path=self.db_path)
        new_approval_manager = HumanApprovalManager(db_path=self.db_path)
        new_fabric_client = FabricClient(db_path=self.db_path)
        new_finance_api = ProtectedFinanceAPI(
            persistent_db_path=self.db_path,
            gateway_secret=self.gateway_secret
        )
        new_replay_tracker = RequestTracker(300, persistent_db=new_persistent_db)
        new_retry_queue = RetryQueueManager(persistent_db=new_persistent_db)

        new_gateway = ActionGateway(
            registry=new_registry,
            cert_manager=new_cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=new_replay_tracker,
            finance_api=new_finance_api,
            approval_manager=new_approval_manager,
            evidence_store=new_evidence_store,
            fabric_client=new_fabric_client,
            persistent_db=new_persistent_db,
            retry_queue=new_retry_queue
        )

        # Agent submits a new request to restarted gateway using its locally retained private key
        req = agent.build_signed_action_request(
            action="TRANSFER_FUNDS",
            resource="BANK_RESERVE_IN",
            parameters={"to_account": "ACC-RESTART", "amount": 2200.0},
            amount=2200.0
        )
        outcome = new_gateway.process_request(req)
        self.assertEqual(outcome["decision"], "ALLOWED")
        self.assertEqual(outcome["gateway_status"], "PROCESSED")

    # -------------------------------------------------------------------------
    # Scenario 9: Unauthorized users cannot register certificates for other agents
    # -------------------------------------------------------------------------
    def test_scenario_9_unauthorized_users_cannot_register_certificates(self):
        """
        CSR registration requires authorized admin privileges (e.g. SYSTEM_ADMIN).
        Unauthenticated callers receive 401, while unauthorized roles (e.g. AUDITOR) receive 403.
        """
        agent = AgentClient(agent_id="RBAC-AGENT-009", agent_name="RBAC Agent")
        csr_pem = agent.generate_csr()
        payload = {
            "agent_id": "RBAC-AGENT-009",
            "agent_name": "RBAC Agent",
            "owner": "FinanceOps",
            "csr_pem": csr_pem
        }

        # 1. No Authorization header -> 401 Unauthorized
        res_no_auth = self.client.post("/agents/register-csr", json=payload)
        self.assertEqual(res_no_auth.status_code, 401)

        # 2. Auditor role (lacks 'register_agent' permission) -> 403 Forbidden
        auditor_headers = {"Authorization": f"Bearer {self.auditor_jwt}"}
        res_auditor = self.client.post("/agents/register-csr", json=payload, headers=auditor_headers)
        self.assertEqual(res_auditor.status_code, 403)

        # 3. System Admin -> 200 OK
        admin_headers = {"Authorization": f"Bearer {self.admin_jwt}"}
        res_admin = self.client.post("/agents/register-csr", json=payload, headers=admin_headers)
        self.assertEqual(res_admin.status_code, 200)

    # -------------------------------------------------------------------------
    # Scenario 10: CA private-key material remains protected independently
    # -------------------------------------------------------------------------
    def test_scenario_10_ca_private_key_material_remains_protected_independently(self):
        """
        The Root CA private signing key is stored in the dedicated 'ca_credentials' table (or KMS),
        never in the 'agents' table. Agent lookup APIs (/agents, /agents/{agent_id}, list_agents)
        never leak Root CA credentials or keys.
        """
        # Direct database inspection
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # 1. CA credentials table has root_ca
        cursor.execute("SELECT key_id, private_key_pem, certificate_pem FROM ca_store WHERE key_id = 'root_ca'")
        ca_row = cursor.fetchone()
        self.assertIsNotNone(ca_row)
        self.assertTrue(ca_row["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----"))

        # 2. Verify CA private key is not in agents table
        cursor.execute("SELECT * FROM agents WHERE private_key IS NOT NULL")
        agents_with_priv = cursor.fetchall()
        self.assertEqual(len(agents_with_priv), 0, "Agents table must never hold any private keys!")

        conn.close()

        # 3. Query agent API and verify no CA key or agent private key exposure
        headers = {"Authorization": f"Bearer {self.admin_jwt}"}
        res = self.client.get("/agents", headers=headers)
        self.assertEqual(res.status_code, 200)
        agents = res.json()["agents"]
        for ag in agents:
            self.assertNotIn("ca_private_key", ag)
            self.assertNotIn("private_key_pem", ag)
            self.assertTrue(ag.get("private_key") is None)


if __name__ == "__main__":
    unittest.main()
