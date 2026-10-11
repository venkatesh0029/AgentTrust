"""
Tests for Held-Out V3 Benchmark and Adversarial Authorization Assurance.
Verifies that:
1. PromptInjectionGuard evaluation on Held-Out V3 exhibits 100% precision and 0% false positives,
   while acknowledging the empirical detection gap on novel zero-day attack vectors.
2. Even when the heuristic guardrail misses an injection (false negative), the policy engine
   and security boundary block the unauthorized action with zero financial side effects.
"""

import os
import shutil
import tempfile
import unittest

from action_gateway.gateway import ActionGateway
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from audit_writer.chain_writer import AuditChainWriter
from benchmarks.held_out_v3_benchmark import HeldOutV3Benchmark
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


class TestHeldOutV3AndBoundaryAssurance(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_v3.db")
        self.persistent_db = PersistentStorageEngine(db_path=self.db_path)

        self.cert_manager = CertificateManager(db_path=self.db_path)
        self.identity_store = IdentityStore(db_path=self.db_path)
        self.registry = AgentRegistry(self.cert_manager, self.identity_store)
        self.policy_loader = PolicyLoader()
        self.policy_evaluator = PolicyEvaluator(self.policy_loader)
        self.replay_tracker = RequestTracker(300, persistent_db=self.persistent_db)
        self.finance_api = ProtectedFinanceAPI(persistent_db_path=os.path.join(self.test_dir, "fencing.db"))
        self.approval_manager = HumanApprovalManager(db_path=self.db_path)
        self.evidence_store = EvidenceStore(db_path=self.db_path)
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
            chain_writer=self.chain_writer,
            persistent_db=self.persistent_db
        )

        # Register constrained agent with $10,000 maximum limit
        self.agent_id = "AGENT-V3-TEST"
        self.priv_key = KeyManager.generate_key_pair(2048)
        self.pub_key_pem = KeyManager.public_key_to_pem(self.priv_key.public_key())
        self.priv_key_pem = KeyManager.private_key_to_pem(self.priv_key)

        policy = PolicyRecord(
            policy_id="POLICY-V3-CONSTRAINED",
            agent_id=self.agent_id,
            allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT"],
            allowed_resource="BANK_RESERVE_IN",
            maximum_amount=10000.0,
            human_approval_above=5000.0,
            working_hours=WorkingHours(start="00:00", end="23:59"),
            version="1.0"
        )
        self.policy_loader.save_policy(policy)

        self.registry.register_agent(
            agent_id=self.agent_id,
            agent_name="V3 Evaluation Agent",
            owner="SecOps",
            capabilities=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT"],
            policy_id="POLICY-V3-CONSTRAINED",
            public_key_pem=self.pub_key_pem
        )

    def tearDown(self):
        try:
            self.persistent_db.close()
        except Exception:
            pass
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_held_out_v3_benchmark_metrics(self):
        """Verifies statistical evaluation on Held-Out V3."""
        metrics = HeldOutV3Benchmark.evaluate()
        self.assertEqual(metrics["total_samples"], 30)
        self.assertEqual(metrics["adversarial_samples"], 15)
        self.assertEqual(metrics["benign_samples"], 15)
        # Precision must be 100% (zero false alarms on benign enterprise data)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        # Empirical gap: heuristics miss majority of novel semantic vectors
        self.assertLess(metrics["recall"], 0.5)

    def test_held_out_v3_missed_attacks_blocked_at_policy_boundary(self):
        """
        Critical security boundary test:
        Even when the prompt injection detector misses an adversarial sample in V3,
        the policy engine and security gateway must block the request (e.g. exceeding
        maximum authorized amounts or unauthorized params), producing zero side effects.
        """
        metrics = HeldOutV3Benchmark.evaluate()
        missed_samples = [r for r in metrics["adversarial_results"] if not r["detected"]]
        self.assertGreater(len(missed_samples), 0, "Expected missed attacks in Held-Out V3")

        for idx, item in enumerate(missed_samples):
            sample = item["sample"]
            req_id = f"REQ-V3-MISSED-{idx+1:03d}"
            payload = {
                "request_id": req_id,
                "agent_id": self.agent_id,
                "action": sample["action"],
                "resource": "BANK_RESERVE_IN",
                "amount": sample["parameters"].get("amount", 25000.0),
                "currency": sample["parameters"].get("currency", "USD"),
                "parameters": dict(sample["parameters"]),
                "timestamp": "2026-10-11T12:00:00Z",
                "nonce": f"NONCE-V3-{idx+1:03d}",
                "key_version": 1
            }
            sig = SignatureManager.sign_request(payload, self.priv_key_pem)
            payload["signature"] = sig

            outcome = self.gateway.process_request(payload)

            # Request must NOT execute side effects
            self.assertNotEqual(outcome.get("api_result"), "EXECUTED", f"Attack {item['id']} executed side effects!")
            self.assertIn(
                outcome.get("decision"),
                ["BLOCKED", "PENDING_HUMAN_APPROVAL"],
                f"Attack {item['id']} was not blocked or held!"
            )


if __name__ == "__main__":
    unittest.main()
