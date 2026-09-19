import pytest
import uuid
import datetime
from typing import Dict, Any

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
from audit_writer.chain_writer import AuditChainWriter
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway

@pytest.fixture
def inv_setup():
    cm = CertificateManager()
    store = IdentityStore()
    reg = AgentRegistry(cm, store)
    loader = PolicyLoader()
    evaluator = PolicyEvaluator(loader)
    replay = RequestTracker(300)
    api = ProtectedFinanceAPI()
    approval = HumanApprovalManager()
    ev_store = EvidenceStore()
    writer = AuditChainWriter()
    fabric = FabricClient()

    gw = ActionGateway(reg, cm, evaluator, replay, api, approval, ev_store, fabric, chain_writer=writer)

    agent_info = reg.register_agent(
        agent_id="INV-AGENT-01",
        agent_name="InvariantAgent",
        owner="Security Team",
        capabilities=["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS", "READ_ACCOUNT"],
        policy_id="INV-POLICY-01",
        organization="OrgA",
        role="procurement_agent"
    )

    policy = PolicyRecord(
        policy_id="INV-POLICY-01",
        agent_id="INV-AGENT-01",
        allowed_actions=["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS", "READ_ACCOUNT"],
        allowed_resource="*",
        maximum_amount=50000.0,
        human_approval_above=10000.0,
        working_hours=WorkingHours(start="00:00", end="23:59"),
        version="1.0"
    )
    loader.save_policy(policy)

    return {
        "gw": gw,
        "reg": reg,
        "priv_key": agent_info["private_key"],
        "pub_key": agent_info["public_key"],
        "api": api,
        "approval": approval,
        "ev_store": ev_store,
        "writer": writer,
        "fabric": fabric
    }

def build_payload(agent_id, action, resource, amount, priv_key, key_version=1):
    payload = {
        "request_id": f"REQ-{uuid.uuid4().hex[:6]}",
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "amount": amount,
        "parameters": {"amount": amount},
        "nonce": f"N-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "key_version": key_version
    }
    sig = SignatureManager.sign_request(payload, priv_key)
    payload["signature"] = sig
    return payload

def test_invariant_i1_unregistered_agent_denial(inv_setup):
    """I1: Unregistered agents cannot execute actions."""
    gw = inv_setup["gw"]
    payload = build_payload("UNREGISTERED-ROGUE-01", "CREATE_PURCHASE_ORDER", "SUP-01", 1000.0, inv_setup["priv_key"])
    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "UNKNOWN_AGENT"
    assert res["protected_api_result"] == "NOT_EXECUTED"

def test_invariant_i2_invalid_signature_denial(inv_setup):
    """I2: Invalid signatures cannot pass the gateway."""
    gw = inv_setup["gw"]
    payload = build_payload("INV-AGENT-01", "CREATE_PURCHASE_ORDER", "SUP-01", 1000.0, inv_setup["priv_key"])
    payload["signature"] = "INVALID_SIGNATURE_DATA"
    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_SIGNATURE"
    assert res["protected_api_result"] == "DENIED"

def test_invariant_i3_revoked_agent_denial(inv_setup):
    """I3: Revoked agents cannot execute actions."""
    reg = inv_setup["reg"]
    gw = inv_setup["gw"]
    reg.revoke_agent("INV-AGENT-01", "SECURITY_COMPROMISE")
    payload = build_payload("INV-AGENT-01", "CREATE_PURCHASE_ORDER", "SUP-01", 1000.0, inv_setup["priv_key"])
    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "CERTIFICATE_REVOKED"

def test_invariant_i4_replayed_request_prevention(inv_setup):
    """I4: Replayed requests cannot execute twice."""
    gw = inv_setup["gw"]
    payload = build_payload("INV-AGENT-01", "CREATE_PURCHASE_ORDER", "SUP-01", 1000.0, inv_setup["priv_key"])
    res1 = gw.process_request(payload)
    assert res1["decision"] == "ALLOWED"
    res2 = gw.process_request(payload)
    assert res2["decision"] == "BLOCKED"
    assert res2["reason"] == "REPLAY_DETECTED"

def test_invariant_i5_denied_actions_blocked_from_api(inv_setup):
    """I5: Denied actions cannot reach the business API."""
    gw = inv_setup["gw"]
    payload = build_payload("INV-AGENT-01", "DELETE_ACCOUNT", "ACC-01", 0.0, inv_setup["priv_key"])
    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["protected_api_result"] == "NOT_EXECUTED"

def test_invariant_i6_unapproved_high_risk_blocked(inv_setup):
    """I6: Unapproved high-risk actions cannot execute."""
    gw = inv_setup["gw"]
    payload = build_payload("INV-AGENT-01", "TRANSFER_FUNDS", "PAYROLL_DATABASE", 30000.0, inv_setup["priv_key"])
    res = gw.process_request(payload)
    assert res["decision"] == "PENDING_HUMAN_APPROVAL"
    assert res["protected_api_result"] == "HELD_FOR_HUMAN_APPROVAL"

def test_invariant_i7_modified_approved_request_fails(inv_setup):
    """I7: Modified approved requests cannot execute."""
    gw = inv_setup["gw"]
    payload = build_payload("INV-AGENT-01", "CREATE_PURCHASE_ORDER", "SUP-01", 20000.0, inv_setup["priv_key"])
    res = gw.process_request(payload)
    ticket = res["approval_ticket"]
    assert ticket is not None

    payload["amount"] = 999999.0
    payload_to_verify = payload.copy()
    payload_to_verify.pop("signature", None)
    valid = SignatureManager.verify_signature(payload_to_verify, payload["signature"], inv_setup["pub_key"])
    assert valid is False

def test_invariant_i8_client_supplied_risk_ignored(inv_setup):
    """I8: Client-supplied risk values cannot influence backend decisions."""
    gw = inv_setup["gw"]
    payload = {
        "request_id": f"REQ-{uuid.uuid4().hex[:6]}",
        "agent_id": "INV-AGENT-01",
        "action": "TRANSFER_FUNDS",
        "resource": "PAYROLL_DATABASE",
        "amount": 40000.0,
        "parameters": {"amount": 40000.0},
        "nonce": f"N-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "key_version": 1,
        "risk_score": 0.0,
        "risk_level": "LOW"
    }
    sig = SignatureManager.sign_request(payload, inv_setup["priv_key"])
    payload["signature"] = sig

    res = gw.process_request(payload)
    assert res["risk_score"] > 70.0
    assert res["decision"] == "PENDING_HUMAN_APPROVAL"

def test_invariant_i9_audit_tampering_detectable(inv_setup):
    """I9: Audit tampering is detectable via hash-chain and Fabric verification."""
    writer = inv_setup["writer"]
    writer.write_event("ACTION_ALLOWED", "REQ-INV-9", "INV-AGENT-01", "hash9", 10.0, "1.0", "ALLOWED", "SUCCESS")
    assert writer.verify_chain_integrity()["valid"] is True
    writer.simulate_tamper_record(1, "decision", "FORGED")
    assert writer.verify_chain_integrity()["valid"] is False

def test_invariant_i10_unauthorized_fabric_write_fails(inv_setup):
    """I10: Unauthorized users cannot write Fabric evidence."""
    fabric = inv_setup["fabric"]
    with pytest.raises(PermissionError):
        fabric.record_evidence("REQ-INV-10", "INV-AGENT-01", "hash", "ALLOWED", caller_org="UNAUTHORIZED_MSP")

def test_invariant_i11_failed_audit_writes_not_ignored(inv_setup):
    """I11: Failed audit writes cannot be silently ignored."""
    gw = inv_setup["gw"]
    # Mock fabric client to throw exception
    gw.fabric_client.record_action_event = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("Fabric Connection Refused"))
    payload = build_payload("INV-AGENT-01", "READ_ACCOUNT", "ACC-01", 0.0, inv_setup["priv_key"])
    res = gw.process_request(payload)
    assert "COMMIT_FAILED" in res["blockchain"]["status"]

def test_invariant_i12_duplicate_requests_no_duplicate_business_effect(inv_setup):
    """I12: Duplicate requests cannot cause duplicate business effects."""
    api = inv_setup["api"]
    headers1 = api.create_gateway_auth_headers("REQ-INV-12-A")
    res1 = api.execute_action("CREATE_PURCHASE_ORDER", {"supplier_id": "SUP-12", "amount": 1000.0}, ProtectedFinanceAPI.GATEWAY_SECRET, "REQ-INV-12-A", "INV-AGENT-01", auth_headers=headers1, idempotency_key="KEY-INV-12")

    headers2 = api.create_gateway_auth_headers("REQ-INV-12-B")
    res2 = api.execute_action("CREATE_PURCHASE_ORDER", {"supplier_id": "SUP-12", "amount": 1000.0}, ProtectedFinanceAPI.GATEWAY_SECRET, "REQ-INV-12-B", "INV-AGENT-01", auth_headers=headers2, idempotency_key="KEY-INV-12")
    assert res2["transaction_data"]["po_id"] == res1["transaction_data"]["po_id"]
    assert res2.get("idempotent_replay") is True
