import pytest
import datetime
import uuid
import time
from identity_manager.certificate_manager import CertificateManager
from identity_manager.signature_manager import SignatureManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from agent_registry.admin_rbac import RBACManager, AdminRole
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_models import PolicyRecord, WorkingHours
from replay_protection.request_tracker import RequestTracker
from protected_api.finance_api import ProtectedFinanceAPI
from human_approval.approval_manager import HumanApprovalManager
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway

@pytest.fixture
def adv_setup():
    cm = CertificateManager()
    store = IdentityStore()
    reg = AgentRegistry(cm, store)
    loader = PolicyLoader()
    evaluator = PolicyEvaluator(loader)
    replay = RequestTracker(120)
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
        "registry": reg,
        "cert_manager": cm,
        "loader": loader,
        "api": api,
        "private_key": agent_info["private_key"]
    }

def test_adv_1_expired_certificate(adv_setup):
    gw = adv_setup["gateway"]
    cm = adv_setup["cert_manager"]
    reg = adv_setup["registry"]

    # Issue cert valid 10 days ago for 5 days (expired 5 days ago)
    cert_pem, priv_pem, _ = cm.issue_agent_certificate("EXP-AGENT-01", "ExpiredAgent", validity_days=5, start_offset_days=-10)
    reg.store.save_agent({
        "agent_id": "EXP-AGENT-01",
        "agent_name": "ExpiredAgent",
        "status": "ACTIVE",
        "certificate": cert_pem,
        "public_key": reg._extract_public_key_from_cert(cert_pem),
        "policy_id": "FIN-POLICY-001"
    })

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = {
        "request_id": f"REQ-EXP-{uuid.uuid4().hex[:6]}",
        "agent_id": "EXP-AGENT-01",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"amount": 1000},
        "nonce": f"N-EXP-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_pem)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert "EXPIRED" in res["reason"]

def test_adv_2_modified_request_parameters_after_signing(adv_setup):
    gw = adv_setup["gateway"]
    priv_key = adv_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-MOD-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-001", "amount": 1000.0},
        "nonce": f"N-MOD-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    sig = SignatureManager.sign_request(payload, priv_key)
    payload["signature"] = sig

    # Attacker alters amount to ₹9,000 without updating signature
    payload["parameters"]["amount"] = 9000.0

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_SIGNATURE"

def test_adv_3_modified_timestamp_after_signing(adv_setup):
    gw = adv_setup["gateway"]
    priv_key = adv_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "request_id": f"REQ-TS-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"amount": 1000.0},
        "nonce": f"N-TS-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    sig = SignatureManager.sign_request(payload, priv_key)
    payload["signature"] = sig

    # Modify timestamp
    payload["timestamp"] = "2020-01-01T00:00:00Z"

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_SIGNATURE"

def test_adv_4_expired_request_header(adv_setup):
    gw = adv_setup["gateway"]
    priv_key = adv_setup["private_key"]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    past_iso = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).isoformat()

    payload = {
        "request_id": f"REQ-EXPH-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"amount": 1000.0},
        "nonce": f"N-EXPH-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso,
        "expires_at": past_iso  # Expired header
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "EXPIRED_REQUEST"

def test_adv_5_future_timestamp_skew_attack(adv_setup):
    gw = adv_setup["gateway"]
    priv_key = adv_setup["private_key"]
    future_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5)).isoformat()

    payload = {
        "request_id": f"REQ-FUT-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"amount": 1000.0},
        "nonce": f"N-FUT-{uuid.uuid4().hex[:6]}",
        "timestamp": future_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "TIME_WINDOW_VIOLATION"

def test_adv_6_direct_api_forged_signature_header_denied(adv_setup):
    api = adv_setup["api"]

    fake_headers = {
        "X-Gateway-Service": "AgentTrust-ActionGateway-Service",
        "X-Gateway-Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "X-Gateway-Signature": "FORGED_SIGNATURE_STRING"
    }

    res = api.execute_action(
        "CREATE_REIMBURSEMENT", {"amount": 2000},
        ProtectedFinanceAPI.GATEWAY_SECRET, "REQ-FORGE", "FINANCE-AGENT-001",
        auth_headers=fake_headers
    )
    assert res["success"] is False
    assert res["error"] == "DIRECT_ACCESS_DENIED"

def test_adv_7_unauthorized_policy_update_rbac_denied():
    assert RBACManager.is_action_allowed(AdminRole.AUDITOR, "create_policy") is False
    assert RBACManager.is_action_allowed(AdminRole.FINANCE_APPROVER, "rollback_policy") is False

def test_adv_8_malformed_payload_missing_required_fields(adv_setup):
    gw = adv_setup["gateway"]

    payload = {
        "request_id": "REQ-BAD",
        # Missing agent_id, nonce, signature
        "action": "CREATE_REIMBURSEMENT"
    }

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_REQUEST_FORMAT"
