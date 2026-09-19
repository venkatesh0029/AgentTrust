import pytest
import datetime
import uuid
from identity_manager.certificate_manager import CertificateManager
from identity_manager.signature_manager import SignatureManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_models import PolicyRecord, WorkingHours
from replay_protection.request_tracker import RequestTracker
from protected_api.finance_api import ProtectedFinanceAPI
from human_approval.approval_manager import HumanApprovalManager
from evidence_manager.evidence_store import EvidenceStore
from evidence_manager.hash_manager import HashManager
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway

@pytest.fixture
def gateway_setup():
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

    # Register default agent & policy
    agent_info = reg.register_agent("FINANCE-AGENT-001", "FinanceAgent", "Finance Dept", ["CREATE_REIMBURSEMENT"], "FIN-POLICY-001")
    policy = PolicyRecord(
        policy_id="FIN-POLICY-001",
        agent_id="FINANCE-AGENT-001",
        allowed_actions=["CREATE_REIMBURSEMENT"],
        allowed_resource="FINANCE_API",
        maximum_amount=10000.0,
        human_approval_above=10000.0,
        working_hours=WorkingHours(start="00:00", end="23:59"),
        version="1.0"
    )
    loader.save_policy(policy)

    return {
        "gateway": gw,
        "registry": reg,
        "policy_loader": loader,
        "evidence_store": ev_store,
        "fabric": fabric,
        "agent_info": agent_info,
        "private_key": agent_info["private_key"]
    }

def test_scenario_1_valid_low_value(gateway_setup):
    gw = gateway_setup["gateway"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-S1-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-001", "amount": 7500.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "ALLOWED"
    assert res["reason"] == "WITHIN_AUTHORITY_LIMIT"
    assert res["protected_api_result"] == "EXECUTED"
    assert res["blockchain"]["status"] == "COMMITTED"

def test_scenario_2_excessive_amount(gateway_setup):
    gw = gateway_setup["gateway"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-S2-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-002", "amount": 80000.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "AUTHORITY_LIMIT_EXCEEDED"
    assert res["protected_api_result"] == "NOT_EXECUTED"

def test_scenario_3_invalid_signature(gateway_setup):
    gw = gateway_setup["gateway"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-S3-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-003", "amount": 5000.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso,
        "signature": "FORGED-SIGNATURE-STRING"
    }

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_SIGNATURE"
    assert res["protected_api_result"] == "DENIED"

def test_scenario_4_unknown_agent(gateway_setup):
    gw = gateway_setup["gateway"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-S4-{uuid.uuid4().hex[:6]}",
        "agent_id": "UNKNOWN-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-004", "amount": 5000.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso,
        "signature": "DUMMY"
    }

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "UNKNOWN_AGENT"

def test_scenario_5_revoked_agent(gateway_setup):
    gw = gateway_setup["gateway"]
    reg = gateway_setup["registry"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    reg.revoke_agent("FINANCE-AGENT-001")
    payload = {
        "request_id": f"REQ-S5-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-005", "amount": 3000.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, gateway_setup["private_key"])

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "CERTIFICATE_REVOKED"

def test_scenario_6_unauthorized_resource(gateway_setup):
    gw = gateway_setup["gateway"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-S6-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "ACCESS_PAYROLL",
        "resource": "PAYROLL_DATABASE",
        "parameters": {"employee_id": "EMP-006", "amount": 0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "ACTION_NOT_PERMITTED"

def test_scenario_7_replay_attack(gateway_setup):
    gw = gateway_setup["gateway"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    req_id = f"REQ-S7-{uuid.uuid4().hex[:6]}"
    nonce = f"N-S7-{uuid.uuid4().hex[:6]}"
    payload = {
        "request_id": req_id,
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-007", "amount": 4500.0},
        "nonce": nonce,
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res1 = gw.process_request(payload)
    assert res1["decision"] == "ALLOWED"

    # Replay identical payload
    res2 = gw.process_request(payload)
    assert res2["decision"] == "BLOCKED"
    assert res2["reason"] == "REPLAY_DETECTED"

def test_scenario_8_and_9_high_risk_and_human_approval(gateway_setup):
    gw = gateway_setup["gateway"]
    loader = gateway_setup["policy_loader"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    pol = loader.get_policy("FIN-POLICY-001")
    pol.maximum_amount = 50000.0
    pol.human_approval_above = 10000.0
    loader.save_policy(pol)

    payload = {
        "request_id": f"REQ-S8-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-008", "amount": 25000.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "PENDING_HUMAN_APPROVAL"
    assert res["reason"] == "HIGH_VALUE_TRANSACTION"
    assert res["protected_api_result"] == "HELD_FOR_HUMAN_APPROVAL"

    ticket = res["approval_ticket"]
    assert ticket is not None

    # Test Scenario 9: Human Approves
    appr_res = gw.process_human_approval_resume(ticket["approval_id"], "HUMAN_SUPERVISOR_CFO")
    assert appr_res["decision"] == "ALLOWED_AFTER_APPROVAL"
    assert appr_res["protected_api_result"] == "EXECUTED"

def test_scenario_10_evidence_tampering(gateway_setup):
    gw = gateway_setup["gateway"]
    ev_store = gateway_setup["evidence_store"]
    fabric = gateway_setup["fabric"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-S10-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-010", "amount": 7500.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    evidence_id = res["evidence"]["evidence_id"]

    # Tamper with evidence off-chain
    ev_store.simulate_tamper(evidence_id, "amount", 75000.0)

    # Re-evaluate hash against Fabric ledger
    ev = ev_store.get_evidence(evidence_id)
    recalculated = HashManager.calculate_evidence_hash(ev)
    verify = fabric.verify_evidence_hash(evidence_id, recalculated)

    assert verify["verified"] is False
    assert verify["status"] == "TAMPERING_DETECTED"

def test_scenario_11_policy_versioning(gateway_setup):
    gw = gateway_setup["gateway"]
    loader = gateway_setup["policy_loader"]
    priv_key = gateway_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    pol = loader.get_policy("FIN-POLICY-001")
    pol.maximum_amount = 5000.0
    pol.version = "2.0"
    loader.save_policy(pol)

    payload = {
        "request_id": f"REQ-S11-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-011", "amount": 7500.0},
        "nonce": f"N-{uuid.uuid4().hex[:8]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "AUTHORITY_LIMIT_EXCEEDED"
