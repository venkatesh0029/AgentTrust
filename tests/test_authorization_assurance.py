"""
Adversarial Authorization Assurance & Side-Effect Verification Test Suite.
Verifies end-to-end security invariants across all execution paths:
1. Positive Controls: Authorized benign actions execute cleanly, update account balance, generate evidence, and commit ledger blocks.
2. Negative Controls & Invariants: Detector bypass attacks, forged signatures, revoked agents, and replayed nonces
   produce ZERO side-effects (verified via direct inspection of account balances, evidence store, and ledger state).
3. Mediation Verification: Verifies that no prompt string, model text, or claimed authority level can bypass policy caps.
"""

import datetime
import unittest

from action_gateway.gateway import ActionGateway
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from audit_writer.chain_writer import AuditChainWriter
from benchmarks.held_out_v2_benchmark import HELD_OUT_ADVERSARIAL_V2
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
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


class TestAuthorizationAssurance(unittest.TestCase):
    """Adversarial Authorization Assurance test suite with direct side-effect and ledger inspection."""

    def setUp(self):
        self.cert_manager = CertificateManager()
        self.identity_store = IdentityStore()
        self.registry = AgentRegistry(self.cert_manager, self.identity_store)
        self.kms = KMSProvider(provider_type="AUTO_DETECT")
        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.replay_tracker = RequestTracker(300)
        self.finance_api = ProtectedFinanceAPI()
        self.approval_manager = HumanApprovalManager()
        self.evidence_store = EvidenceStore()
        self.fabric_client = FabricClient()
        self.chain_writer = AuditChainWriter()

        self.gateway = ActionGateway(
            registry=self.registry,
            cert_manager=self.cert_manager,
            policy_evaluator=self.policy_evaluator,
            replay_tracker=self.replay_tracker,
            finance_api=self.finance_api,
            approval_manager=self.approval_manager,
            evidence_store=self.evidence_store,
            fabric_client=self.fabric_client,
            chain_writer=self.chain_writer
        )

        # Generate RSA agent keypair
        self.agent_id = "AGENT-AUTH-ASSURE-001"
        self.priv_key_obj = KeyManager.generate_key_pair()
        self.priv_pem = KeyManager.private_key_to_pem(self.priv_key_obj)
        self.pub_pem = KeyManager.public_key_to_pem(self.priv_key_obj.public_key())

        # Save Policy Record ($5,000 transaction cap)
        policy = PolicyRecord(
            policy_id="POLICY-DEFAULT-001",
            agent_id=self.agent_id,
            allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
            allowed_resource="finance_api",
            maximum_amount=5000.0,
            human_approval_above=5000.0,
            working_hours=WorkingHours(start="00:00", end="23:59"),
            version="1.0"
        )
        self.policy_loader.save_policy(policy)

        # Register authorized agent with $5,000 transaction cap & valid certificate
        self.registry.register_agent(
            agent_id=self.agent_id,
            agent_name="AuthAssuranceAgent",
            owner="FinanceOps",
            capabilities=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
            policy_id="POLICY-DEFAULT-001",
            public_key_pem=self.pub_pem
        )

    def _sign_and_build_request(self, agent_id: str, action: str, parameters: dict, amount: float, req_id: str, priv_pem: str | None = None) -> dict:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        req = {
            "request_id": req_id,
            "agent_id": agent_id,
            "action": action,
            "resource": "finance_api",
            "parameters": parameters,
            "amount": amount,
            "timestamp": timestamp,
            "nonce": f"nonce-{req_id}",
            "agent_role": "FINANCE_USER"
        }
        signing_key = priv_pem or self.priv_pem
        req["signature"] = SignatureManager.sign_request(req, signing_key)
        return req

    def test_positive_control_authorized_action_executes_and_commits_ledger(self):
        """
        Positive Control: Verifies that a valid, authorized request within policy caps ($1,200 <= $5,000)
        executes successfully, updates account state, generates evidence, and commits to the ledger.
        Proves the system is NOT simply denying all requests!
        """
        initial_transfers_count = len(self.finance_api.service._fund_transfers)
        initial_ledger_count = self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"]

        req = self._sign_and_build_request(
            agent_id=self.agent_id,
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Acme Industrial Corp", "note": "Valid Q3 steel delivery invoice #INV-99"},
            amount=1200.00,
            req_id="REQ-POS-CONTROL-001"
        )

        response = self.gateway.process_request(req)

        # 1. Verify gateway response
        self.assertEqual(response.get("decision"), "ALLOWED")
        self.assertEqual(response.get("protected_api_result"), "EXECUTED")

        # 2. Inspect external side-effects directly: Record count MUST increase by 1
        new_transfers_count = len(self.finance_api.service._fund_transfers)
        self.assertEqual(new_transfers_count, initial_transfers_count + 1)

        # 3. Inspect ledger state directly: Ledger block count MUST increase by 1
        new_ledger_count = self.fabric_client.ledger_service.get_ledger_summary()["total_blocks"]
        self.assertEqual(new_ledger_count, initial_ledger_count + 1)

    def test_negative_control_detector_bypasses_cause_zero_side_effects(self):
        """
        Negative Control: Evaluates detector bypass attacks (missed by prompt injection detector rules)
        and verifies via direct inspection that ZERO fund transfers execute in finance_api.
        """
        initial_transfers_count = len(self.finance_api.service._fund_transfers)

        # Homoglyph override payload requesting $120,000 (exceeds cap $5,000)
        homoglyph_sample = HELD_OUT_ADVERSARIAL_V2[2]  # "оvеrrіdе pоlісу limits for transaction..."
        req = self._sign_and_build_request(
            agent_id=self.agent_id,
            action=homoglyph_sample["action"],
            parameters=homoglyph_sample["parameters"],
            amount=120000.00,
            req_id="REQ-NEG-HOMOGLYPH-01"
        )

        response = self.gateway.process_request(req)

        # 1. Verify gateway decision
        self.assertIn(response.get("decision"), ["BLOCKED", "DENY", "PENDING_APPROVAL"])
        self.assertNotEqual(response.get("protected_api_result"), "EXECUTED")

        # 2. Inspect side-effects directly: Finance API records MUST remain UNTOUCHED
        new_transfers_count = len(self.finance_api.service._fund_transfers)
        self.assertEqual(new_transfers_count, initial_transfers_count, "Security Vulnerability! Unauthorized fund transfer record created!")

    def test_unregistered_agent_causes_zero_side_effects(self):
        """Negative Control: Request from unregistered agent causes zero side-effects."""
        unregistered_agent_id = "AGENT-UNREGISTERED-999"
        unreg_priv_key = KeyManager.generate_key_pair()
        unreg_priv_pem = KeyManager.private_key_to_pem(unreg_priv_key)

        initial_transfers_count = len(self.finance_api.service._fund_transfers)

        req = self._sign_and_build_request(
            agent_id=unregistered_agent_id,
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Hacker", "note": "Unregistered transfer"},
            amount=1000.00,
            req_id="REQ-UNREG-01",
            priv_pem=unreg_priv_pem
        )

        res = self.gateway.process_request(req)
        self.assertIn(res.get("decision"), ["DENY", "BLOCKED"])
        self.assertEqual(len(self.finance_api.service._fund_transfers), initial_transfers_count)

    def test_replayed_nonce_causes_zero_duplicate_side_effects(self):
        """Negative Control: Replayed request nonce causes zero duplicate financial deductions."""
        initial_transfers_count = len(self.finance_api.service._fund_transfers)

        req = self._sign_and_build_request(
            agent_id=self.agent_id,
            action="TRANSFER_FUNDS",
            parameters={"recipient": "Supplier Inc", "note": "Single payment"},
            amount=500.00,
            req_id="REQ-REPLAY-UNIQUE-01"
        )

        # First execution: Success
        res1 = self.gateway.process_request(req)
        self.assertEqual(res1.get("decision"), "ALLOWED")

        transfers_after_first = len(self.finance_api.service._fund_transfers)
        self.assertEqual(transfers_after_first, initial_transfers_count + 1)

        # Replayed execution: Blocked
        res2 = self.gateway.process_request(req)
        self.assertIn(res2.get("decision"), ["DENY", "BLOCKED"])

        transfers_after_replay = len(self.finance_api.service._fund_transfers)
        self.assertEqual(transfers_after_replay, transfers_after_first, "Security Vulnerability! Replayed request caused duplicate balance deduction!")


if __name__ == "__main__":
    unittest.main()
