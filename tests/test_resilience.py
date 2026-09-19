import pytest
import datetime
import uuid
from identity_manager.certificate_manager import CertificateManager
from identity_manager.signature_manager import SignatureManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_models import PolicyRecord, WorkingHours, PolicyDecision
from replay_protection.request_tracker import RequestTracker
from protected_api.finance_api import ProtectedFinanceAPI
from human_approval.approval_manager import HumanApprovalManager
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway

@pytest.fixture
def resilience_setup():
    cm = CertificateManager()
    store = IdentityStore()
    reg = AgentRegistry(cm, store)
    loader = PolicyLoader()
    evaluator = PolicyEvaluator(loader)
    replay = RequestTracker(300)
    api = ProtectedFinanceAPI()
    approval = HumanApprovalManager()
    ev_store = EvidenceStore()
    fabric = FabricClient()

    gw = ActionGateway(reg, cm, evaluator, replay, api, approval, ev_store, fabric)
    agent_info = reg.register_agent("FINANCE-AGENT-001", "FinanceAgent", "Finance Dept", ["CREATE_REIMBURSEMENT"], "FIN-POLICY-001")

    p1 = PolicyRecord(
        policy_id="FIN-POLICY-001",
        agent_id="FINANCE-AGENT-001",
        allowed_actions=["CREATE_REIMBURSEMENT"],
        allowed_resource="FINANCE_API",
        maximum_amount=10000.0,
        human_approval_above=10000.0,
        working_hours=WorkingHours(start="00:00", end="23:59"),
        version="1.0"
    )
    loader.save_policy(p1)

    return {
        "gateway": gw,
        "loader": loader,
        "evaluator": evaluator,
        "api": api,
        "fabric": fabric,
        "ev_store": ev_store,
        "private_key": agent_info["private_key"]
    }

def test_direct_api_bypass_denial(resilience_setup):
    api = resilience_setup["api"]
    res = api.execute_action("CREATE_REIMBURSEMENT", {"amount": 5000}, "INVALID_TOKEN", "REQ-BYPASS", "ROGUE")
    assert res["success"] is False
    assert res["error"] == "DIRECT_ACCESS_DENIED"

def test_policy_conflict_resolution_most_restrictive(resilience_setup):
    evaluator = resilience_setup["evaluator"]
    loader = resilience_setup["loader"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    p2 = PolicyRecord(
        policy_id="FIN-POLICY-002",
        agent_id="FINANCE-AGENT-001",
        allowed_actions=["CREATE_REIMBURSEMENT"],
        allowed_resource="FINANCE_API",
        maximum_amount=5000.0,
        human_approval_above=5000.0,
        working_hours=WorkingHours(start="00:00", end="23:59"),
        version="1.0"
    )
    loader.save_policy(p2)

    dec, reason, ver = evaluator.resolve_conflicting_policies(
        ["FIN-POLICY-001", "FIN-POLICY-002"], "CREATE_REIMBURSEMENT", "FINANCE_API", 7500.0, now_iso
    )
    assert dec == PolicyDecision.BLOCKED

def test_policy_version_history_and_rollback(resilience_setup):
    loader = resilience_setup["loader"]

    pol_v1 = loader.get_policy("FIN-POLICY-001")

    # Create v2.0
    pol_v2 = pol_v1.model_copy(deep=True)
    pol_v2.maximum_amount = 5000.0
    pol_v2.version = "2.0"
    loader.save_policy(pol_v2, author="POLICY_ADMIN", reason="Lowered limit")

    current_pol = loader.get_policy("FIN-POLICY-001")
    assert current_pol.maximum_amount == 5000.0
    assert len(current_pol.version_history) == 1
    assert current_pol.version_history[0].version == "1.0"

    # Rollback to v1.0
    rolled_back = loader.rollback_policy("FIN-POLICY-001", "1.0", author="POLICY_ADMIN")
    assert rolled_back is not None
    assert rolled_back.maximum_amount == 10000.0
    assert rolled_back.version == "2.1"

def test_ledger_failure_recovery_handling(resilience_setup):
    gw = resilience_setup["gateway"]
    fabric = resilience_setup["fabric"]
    priv_key = resilience_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def mock_failing_record(*args, **kwargs):
        raise RuntimeError("Fabric Orderer Network Unavailable")

    fabric.record_action_event = mock_failing_record

    payload = {
        "request_id": f"REQ-FAIL-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-999", "amount": 3000.0},
        "nonce": f"N-FAIL-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)

    assert res["evidence"]["off_chain_status"] == "STORED"
    assert "COMMIT_FAILED" in res["blockchain"]["status"]
