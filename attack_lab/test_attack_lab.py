import pytest
import uuid
import datetime
import threading
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
from evidence_manager.hash_manager import HashManager
from audit_writer.chain_writer import AuditChainWriter
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway

@pytest.fixture
def test_setup():
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

    # Register default Procurement Agent
    agent_info = reg.register_agent(
        agent_id="PROCUREMENT-AGENT-001",
        agent_name="ProcurementAgent",
        owner="Procurement Dept",
        capabilities=["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS", "READ_ACCOUNT"],
        policy_id="PROC-POLICY-001",
        organization="OrgA",
        role="procurement_agent"
    )

    policy = PolicyRecord(
        policy_id="PROC-POLICY-001",
        agent_id="PROCUREMENT-AGENT-001",
        allowed_actions=["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS", "READ_ACCOUNT"],
        allowed_resource="*",
        maximum_amount=100000.0,
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

def build_signed_payload(agent_id, action, resource, amount, priv_key, key_version=1, request_id=None, nonce=None, timestamp=None, idempotency_key=None, extra_fields=None):
    now_iso = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
    req_id = request_id or f"REQ-{uuid.uuid4().hex[:6]}"
    n = nonce or f"NONCE-{uuid.uuid4().hex[:6]}"

    payload = {
        "request_id": req_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "amount": amount,
        "parameters": {"amount": amount},
        "nonce": n,
        "timestamp": now_iso,
        "key_version": key_version
    }
    if idempotency_key:
        payload["idempotency_key"] = idempotency_key

    if extra_fields:
        payload.update(extra_fields)

    sig = SignatureManager.sign_request(payload, priv_key)
    payload["signature"] = sig
    return payload


# --- 20 ATTACK SCENARIO TESTS ---

def test_attack_01_forged_signature(test_setup):
    """Attack #1: Forged digital signature must be rejected."""
    gw = test_setup["gw"]
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 5000.0, test_setup["priv_key"])
    payload["signature"] = "FORGED_SIGNATURE_STRING_AAA_BBB_CCC"

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_SIGNATURE"
    assert res["protected_api_result"] == "DENIED"

def test_attack_02_modified_signed_payload(test_setup):
    """Attack #2: Modifying payload after signing must invalidate signature verification."""
    gw = test_setup["gw"]
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 5000.0, test_setup["priv_key"])
    payload["amount"] = 95000.0  # Tampered amount after signing!

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_SIGNATURE"

def test_attack_03_replay_attack(test_setup):
    """Attack #3: Resubmitting identical request ID/nonce must be rejected."""
    gw = test_setup["gw"]
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 3000.0, test_setup["priv_key"])

    res1 = gw.process_request(payload)
    assert res1["decision"] == "ALLOWED"

    res2 = gw.process_request(payload)
    assert res2["decision"] == "BLOCKED"
    assert res2["reason"] == "REPLAY_DETECTED"

def test_attack_04_expired_request(test_setup):
    """Attack #4: Expired request outside freshness window must be rejected."""
    gw = test_setup["gw"]
    old_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=600)).isoformat()
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 2000.0, test_setup["priv_key"], timestamp=old_time)

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] in {"EXPIRED_REQUEST", "TIME_WINDOW_VIOLATION"}

def test_attack_05_duplicate_business_request_idempotency(test_setup):
    """Attack #5: Idempotency protection prevents duplicate purchase order execution."""
    api = test_setup["api"]
    headers1 = api.create_gateway_auth_headers("REQ-IDEMP-01")

    res1 = api.execute_action(
        action="CREATE_PURCHASE_ORDER",
        parameters={"supplier_id": "SUP-99", "amount": 4000.0},
        gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
        request_id="REQ-IDEMP-01",
        agent_id="PROCUREMENT-AGENT-001",
        auth_headers=headers1,
        idempotency_key="IDEMP-KEY-999"
    )
    assert res1["success"] is True

    headers2 = api.create_gateway_auth_headers("REQ-IDEMP-02")
    res2 = api.execute_action(
        action="CREATE_PURCHASE_ORDER",
        parameters={"supplier_id": "SUP-99", "amount": 4000.0},
        gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
        request_id="REQ-IDEMP-02",
        agent_id="PROCUREMENT-AGENT-001",
        auth_headers=headers2,
        idempotency_key="IDEMP-KEY-999"
    )
    assert res2["success"] is True
    assert res2.get("idempotent_replay") is True
    assert res2["transaction_data"]["po_id"] == res1["transaction_data"]["po_id"]

def test_attack_06_revoked_agent_request(test_setup):
    """Attack #6: Revoked agent cannot execute actions."""
    reg = test_setup["reg"]
    gw = test_setup["gw"]

    info = reg.register_agent("REV-AGENT-01", "RevokedAgent", "Security Ops", ["CREATE_PURCHASE_ORDER"], "PROC-POLICY-001")
    reg.revoke_agent("REV-AGENT-01", "COMPROMISED")

    payload = build_signed_payload("REV-AGENT-01", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 1000.0, info["private_key"])
    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "CERTIFICATE_REVOKED"

def test_attack_07_suspended_agent_request(test_setup):
    """Attack #7: Suspended agent cannot execute actions."""
    reg = test_setup["reg"]
    gw = test_setup["gw"]

    info = reg.register_agent("SUSP-AGENT-01", "SuspendedAgent", "Security Ops", ["CREATE_PURCHASE_ORDER"], "PROC-POLICY-001")
    reg.suspend_agent("SUSP-AGENT-01", "AUDIT_PENDING")

    payload = build_signed_payload("SUSP-AGENT-01", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 1000.0, info["private_key"])
    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "AGENT_SUSPENDED"

def test_attack_08_unauthorized_action(test_setup):
    """Attack #8: Unauthorized action (DELETE_ACCOUNT) is denied by default."""
    gw = test_setup["gw"]
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "DELETE_ACCOUNT", "ACC-101", 0.0, test_setup["priv_key"])

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "ACTION_NOT_PERMITTED"

def test_attack_09_policy_bypass_attempt(test_setup):
    """Attack #9: Attempting unauthorized resource access is denied."""
    gw = test_setup["gw"]
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "CREATE_PURCHASE_ORDER", "UNAUTHORIZED_VAULT", 500000.0, test_setup["priv_key"])

    res = gw.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert "AUTHORITY_LIMIT_EXCEEDED" in res["reason"] or "RESOURCE_NOT_PERMITTED" in res["reason"]

def test_attack_10_client_side_risk_score_manipulation(test_setup):
    """Attack #10: Client-side submitted risk score is ignored; backend computes true score."""
    gw = test_setup["gw"]
    payload = build_signed_payload(
        "PROCUREMENT-AGENT-001", "TRANSFER_FUNDS", "PAYROLL_DATABASE", 85000.0, test_setup["priv_key"],
        extra_fields={"risk_score": 0.0, "risk_level": "LOW"}
    )

    res = gw.process_request(payload)
    # Backend computes true risk score (>70 due to amount + sensitive resource)
    assert res["risk_score"] > 70.0
    assert res["risk_level"] == "HIGH"
    assert res["decision"] == "PENDING_HUMAN_APPROVAL"

def test_attack_11_client_side_approval_status_manipulation(test_setup):
    """Attack #11: Client-side setting 'approved'=True is ignored by Gateway."""
    gw = test_setup["gw"]
    payload = build_signed_payload(
        "PROCUREMENT-AGENT-001", "TRANSFER_FUNDS", "SUPPLIER-101", 25000.0, test_setup["priv_key"],
        extra_fields={"approved": True, "approval_reference": "FORGED-APPROVAL-REF"}
    )

    res = gw.process_request(payload)
    assert res["decision"] == "PENDING_HUMAN_APPROVAL"
    assert res["protected_api_result"] == "HELD_FOR_HUMAN_APPROVAL"

def test_attack_12_approval_token_replay(test_setup):
    """Attack #12: Single-use approval token cannot be reused a second time."""
    approval = test_setup["approval"]
    ticket = approval.create_approval_request("REQ-APP-01", "AGENT-01", "TRANSFER_FUNDS", "ACC-01", {"amount": 20000.0}, "HIGH_VAL", "PROC-POLICY-001")
    app_id = ticket["approval_id"]
    tok = ticket["approval_token"]

    ok1, rec1, msg1 = approval.approve_request(app_id, "SUPERVISOR-01", provided_token=tok)
    assert ok1 is True

    ok2, rec2, msg2 = approval.approve_request(app_id, "SUPERVISOR-01", provided_token=tok)
    assert ok2 is False
    assert "REQUEST_ALREADY_APPROVED" in msg2 or "TOKEN_ALREADY_USED" in msg2

def test_attack_13_approval_token_substitution(test_setup):
    """Attack #13: Approval token from another request fails validation."""
    approval = test_setup["approval"]
    ticket1 = approval.create_approval_request("REQ-APP-01", "AGENT-01", "TRANSFER_FUNDS", "ACC-01", {"amount": 20000.0}, "HIGH_VAL", "PROC-POLICY-001")
    ticket2 = approval.create_approval_request("REQ-APP-02", "AGENT-02", "TRANSFER_FUNDS", "ACC-02", {"amount": 30000.0}, "HIGH_VAL", "PROC-POLICY-001")

    ok, rec, msg = approval.approve_request(ticket1["approval_id"], "SUPERVISOR-01", provided_token=ticket2["approval_token"])
    assert ok is False
    assert msg == "INVALID_APPROVAL_TOKEN"

def test_attack_14_request_modification_after_approval(test_setup):
    """Attack #14: Modifying parameter after approval breaks signature validation upon execution."""
    gw = test_setup["gw"]
    payload = build_signed_payload("PROCUREMENT-AGENT-001", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 25000.0, test_setup["priv_key"])
    res = gw.process_request(payload)

    ticket = res["approval_ticket"]
    assert ticket is not None

    # Attacker tries to modify parameters in ticket before approval!
    ticket["parameters"]["amount"] = 900000.0
    payload["parameters"]["amount"] = 900000.0
    payload["amount"] = 900000.0

    # Execute approval resume with modified payload -> signature check fails
    payload_to_verify = payload.copy()
    payload_to_verify.pop("signature", None)
    valid = SignatureManager.verify_signature(payload_to_verify, payload["signature"], test_setup["pub_key"])
    assert valid is False

def test_attack_15_direct_protected_api_access(test_setup):
    """Attack #15: Direct invocation of protected API without gateway secret is rejected."""
    api = test_setup["api"]
    res = api.execute_action(
        action="CREATE_PURCHASE_ORDER",
        parameters={"supplier_id": "SUP-01", "amount": 1000.0},
        gateway_token="INVALID_ROGUE_TOKEN",
        request_id="REQ-DIRECT-01",
        agent_id="ROGUE-AGENT-99"
    )
    assert res["success"] is False
    assert res["error"] == "DIRECT_ACCESS_DENIED"

def test_attack_16_tampered_off_chain_evidence(test_setup):
    """Attack #16: Off-chain evidence tampering is detected during verification."""
    ev_store = test_setup["ev_store"]
    fabric = test_setup["fabric"]

    ev_record = {"evidence_id": "EV-TEST-16", "request_id": "REQ-16", "amount": 5000.0}
    stored_hash = ev_store.save_evidence(ev_record)
    fabric.record_evidence("REQ-16", "AGENT-01", stored_hash, "ALLOWED")

    # Simulate tampering
    ev_store.simulate_tamper("EV-TEST-16", "amount", 500000.0)

    recalculated = HashManager.calculate_evidence_hash(ev_store.get_evidence("EV-TEST-16"))
    res = fabric.verify_evidence("REQ-16", recalculated)

    assert res["found"] is True
    assert res["verified"] is False
    assert res["status"] == "TAMPERING_DETECTED"

def test_attack_17_tampered_hash_chain_record(test_setup):
    """Attack #17: Modifying an old record in the AuditChainWriter invalidates the entire hash chain."""
    writer = test_setup["writer"]
    writer.write_event("ACTION_ALLOWED", "REQ-CH-01", "AGENT-01", "hash1", 10.0, "1.0", "ALLOWED", "SUCCESS")
    writer.write_event("ACTION_ALLOWED", "REQ-CH-02", "AGENT-01", "hash2", 20.0, "1.0", "ALLOWED", "SUCCESS")
    writer.write_event("ACTION_ALLOWED", "REQ-CH-03", "AGENT-01", "hash3", 30.0, "1.0", "ALLOWED", "SUCCESS")

    assert writer.verify_chain_integrity()["valid"] is True

    # Simulate tampering with record sequence #1
    writer.simulate_tamper_record(1, "decision", "FORGED_ALLOWED")

    verify_res = writer.verify_chain_integrity()
    assert verify_res["valid"] is False
    assert verify_res["status"] == "TAMPERING_DETECTED"

def test_attack_18_unauthorized_fabric_write(test_setup):
    """Attack #18: Unauthorized Fabric write caller MSP is rejected."""
    fabric = test_setup["fabric"]
    with pytest.raises(PermissionError) as excinfo:
        fabric.record_evidence("REQ-AUTH-01", "AGENT-01", "hash", "ALLOWED", caller_org="UNAUTHORIZED_ROGUE_MSP")
    assert "Authorization Failure" in str(excinfo.value)

def test_attack_19_key_compromise_recovery(test_setup):
    """Attack #19: Old key fails after key rotation; new key succeeds."""
    reg = test_setup["reg"]
    gw = test_setup["gw"]

    info1 = reg.register_agent("ROTATE-AGENT-01", "RotateAgent", "Security", ["CREATE_PURCHASE_ORDER"], "PROC-POLICY-001")
    old_priv_key = info1["private_key"]

    # Rotate Key -> Key Version 2
    info2 = reg.rotate_key("ROTATE-AGENT-01")
    new_priv_key = info2["private_key"]
    assert info2["key_version"] == 2

    # Old key fails with key_version=2 or signed payload
    payload_old = build_signed_payload("ROTATE-AGENT-01", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 1000.0, old_priv_key, key_version=2)
    res_old = gw.process_request(payload_old)
    assert res_old["decision"] == "BLOCKED"
    assert res_old["reason"] == "INVALID_SIGNATURE"

    # New key succeeds
    payload_new = build_signed_payload("ROTATE-AGENT-01", "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 1000.0, new_priv_key, key_version=2)
    res_new = gw.process_request(payload_new)
    assert res_new["decision"] == "ALLOWED"

def test_attack_20_concurrent_audit_write_conflict(test_setup):
    """Attack #20: Simultaneous requests from multiple agents preserve atomic sequence numbers and chain integrity."""
    gw = test_setup["gw"]
    reg = test_setup["reg"]
    writer = test_setup["writer"]

    agents = []
    for i in range(10):
        ag_id = f"CONC-AGENT-{i:02d}"
        info = reg.register_agent(ag_id, f"ConcAgent{i}", "Dept", ["CREATE_PURCHASE_ORDER"], "PROC-POLICY-001")
        agents.append((ag_id, info["private_key"]))

    def send_req(ag_id, priv_key):
        payload = build_signed_payload(ag_id, "CREATE_PURCHASE_ORDER", "SUPPLIER-101", 500.0, priv_key)
        gw.process_request(payload)

    threads = []
    for ag_id, pk in agents:
        t = threading.Thread(target=send_req, args=(ag_id, pk))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    chain_ver = writer.verify_chain_integrity()
    assert chain_ver["valid"] is True
    assert chain_ver["total_records"] >= 11  # Genesis + 10 requests
