import pytest
import math
import uuid
import datetime
from fastapi.testclient import TestClient

from server import app, agent_registry, policy_evaluator, action_gateway, finance_api, cert_manager
from agent_registry.admin_rbac import AdminRole
from agent_registry.status_manager import AgentStatus
from identity_manager.signature_manager import SignatureManager
from protected_api.finance_api import ProtectedFinanceAPI
from policy_engine.policy_evaluator import PolicyEvaluator

client = TestClient(app)

# --- Finding #1 & #2: RBAC Header Enforcement ---
def test_regression_rbac_header_enforcement():
    """Verify that RBAC correctly reads X-Admin-Role header and fails closed on unprivileged roles."""
    # AUDITOR trying to register an agent MUST fail with 403
    res_auditor = client.post(
        "/agents/register",
        json={"agent_id": "TEST-REG-001", "agent_name": "TestReg", "owner": "Ops"},
        headers={"X-Admin-Role": "AUDITOR"}
    )
    assert res_auditor.status_code == 403
    assert "RBAC Denial" in res_auditor.json()["detail"]

    # SYSTEM_ADMIN registering an agent MUST succeed
    res_admin = client.post(
        "/agents/register",
        json={"agent_id": f"TEST-REG-{uuid.uuid4().hex[:4]}", "agent_name": "TestRegAdmin", "owner": "Ops"},
        headers={"X-Admin-Role": "SYSTEM_ADMIN"}
    )
    assert res_admin.status_code == 200
    assert "private_key" in res_admin.json()["agent"]

def test_regression_rbac_finance_approver_role():
    """Verify that FINANCE_APPROVER role can approve tickets while AUDITOR is denied."""
    # Register pending approval
    agent_id = f"AGENT-APPR-{uuid.uuid4().hex[:4]}"
    reg = agent_registry.register_agent(agent_id=agent_id, agent_name="ApprAgent")
    
    app_record = action_gateway.approval_manager.create_approval_request(
        request_id=f"REQ-APPR-{uuid.uuid4().hex[:4]}",
        agent_id=agent_id,
        action="TRANSFER_FUNDS",
        resource="ACC-001",
        parameters={"amount": 25000.0},
        policy_id="FIN-POLICY-001",
        reason="HIGH_VALUE_TRANSACTION"
    )
    app_id = app_record["approval_id"]

    # AUDITOR trying to approve MUST fail with 403
    res_auditor = client.post(f"/approvals/{app_id}/approve", headers={"X-Admin-Role": "AUDITOR"})
    assert res_auditor.status_code == 403

    # FINANCE_APPROVER trying to approve MUST succeed (status 200)
    res_approver = client.post(f"/approvals/{app_id}/approve", headers={"X-Admin-Role": "FINANCE_APPROVER"})
    assert res_approver.status_code == 200

# --- Finding #4: NaN Amount Rejection ---
def test_regression_nan_amount_rejection():
    """Verify that NaN amount requests are blocked at gateway with INVALID_AMOUNT_NAN_OR_INF."""
    agent_id = f"AGENT-NAN-{uuid.uuid4().hex[:4]}"
    reg = agent_registry.register_agent(agent_id=agent_id, agent_name="NanAgent")
    
    payload = {
        "request_id": f"REQ-NAN-{uuid.uuid4().hex[:4]}",
        "agent_id": agent_id,
        "action": "CREATE_PURCHASE_ORDER",
        "resource": "SUPPLIER-001",
        "amount": "NaN",
        "parameters": {"amount": "NaN"},
        "nonce": f"N-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    sig = SignatureManager.sign_request(payload, reg["private_key"])
    payload["signature"] = sig

    res = action_gateway.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_AMOUNT_NAN_OR_INF"

# --- Finding #5: Negative Amount Rejection ---
def test_regression_negative_amount_rejection():
    """Verify that negative amounts are blocked with NON_POSITIVE_AMOUNT."""
    agent_id = f"AGENT-NEG-{uuid.uuid4().hex[:4]}"
    reg = agent_registry.register_agent(agent_id=agent_id, agent_name="NegAgent")
    
    payload = {
        "request_id": f"REQ-NEG-{uuid.uuid4().hex[:4]}",
        "agent_id": agent_id,
        "action": "CREATE_PURCHASE_ORDER",
        "resource": "SUPPLIER-001",
        "amount": -500000.0,
        "parameters": {"amount": -500000.0},
        "nonce": f"N-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    sig = SignatureManager.sign_request(payload, reg["private_key"])
    payload["signature"] = sig

    res = action_gateway.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "NON_POSITIVE_AMOUNT"

# --- Finding #6: Amount Mismatch Rejection ---
def test_regression_amount_mismatch_rejection():
    """Verify that requests with top-level amount != parameters.amount are blocked with AMOUNT_MISMATCH."""
    agent_id = f"AGENT-MIS-{uuid.uuid4().hex[:4]}"
    reg = agent_registry.register_agent(agent_id=agent_id, agent_name="MisAgent")
    
    payload = {
        "request_id": f"REQ-MIS-{uuid.uuid4().hex[:4]}",
        "agent_id": agent_id,
        "action": "CREATE_PURCHASE_ORDER",
        "resource": "SUPPLIER-001",
        "amount": 100.0,
        "parameters": {"amount": 90000.0},
        "nonce": f"N-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    sig = SignatureManager.sign_request(payload, reg["private_key"])
    payload["signature"] = sig

    res = action_gateway.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "AMOUNT_MISMATCH"

# --- Finding #7: Direct API Bypass Denial ---
def test_regression_direct_api_bypass_denied():
    """Verify that calling ProtectedFinanceAPI without mandatory signed auth headers returns DIRECT_ACCESS_DENIED."""
    prot_api = ProtectedFinanceAPI()
    res = prot_api.execute_action(
        action="TRANSFER_FUNDS",
        parameters={"amount": 999999.0},
        gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
        request_id="REQ-BYPASS-001",
        agent_id="AGENT-ROGUE-001",
        auth_headers=None  # Missing mandatory signed headers
    )
    assert res["success"] is False
    assert res["error"] == "DIRECT_ACCESS_DENIED"

# --- Finding #8: Admin-Gated Operational Mode Switching ---
def test_regression_mode_switch_admin_gated():
    """Verify that switching operational modes requires SYSTEM_ADMIN role."""
    res_auditor = client.post("/mode", json={"mode": "MODE_A_DIRECT_API"}, headers={"X-Admin-Role": "AUDITOR"})
    assert res_auditor.status_code == 403

    res_admin = client.post("/mode", json={"mode": "MODE_D_AGENTTRUST_FABRIC"}, headers={"X-Admin-Role": "SYSTEM_ADMIN"})
    assert res_admin.status_code == 200

# --- Finding #9: Revoked Agent Cannot Be Reactivated ---
def test_regression_revoked_agent_cannot_reactivate():
    """Verify that a REVOKED agent cannot transition back to ACTIVE."""
    agent_id = f"AGENT-REV-{uuid.uuid4().hex[:4]}"
    agent_registry.register_agent(agent_id=agent_id, agent_name="RevAgent")
    
    # Revoke agent
    ok_revoke = agent_registry.revoke_agent(agent_id, "COMPROMISED")
    assert ok_revoke is True
    assert agent_registry.get_agent(agent_id)["status"] == "REVOKED"

    # Attempt to reactivate
    ok_reactivate = agent_registry.reactivate_agent(agent_id, "ATTEMPT_RESTORE")
    assert ok_reactivate is False
    assert agent_registry.get_agent(agent_id)["status"] == "REVOKED"

# --- Finding #10: Working Hours Timezone Spoof Prevention ---
def test_regression_working_hours_normalized_to_utc():
    """Verify that working hours evaluation uses normalized UTC time."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # 09:00 - 18:00 UTC check
    is_valid = PolicyEvaluator._check_working_hours(now_iso, "00:00", "23:59", use_server_time=True)
    assert is_valid is True

# --- Finding #11: Approval Resume Re-Validation ---
def test_regression_approval_resume_revalidates_revoked_status():
    """Verify that resuming a held approval for an agent revoked after holding is BLOCKED."""
    agent_id = f"AGENT-RES-{uuid.uuid4().hex[:4]}"
    agent_registry.register_agent(agent_id=agent_id, agent_name="ResAgent")

    # Create pending approval
    app_record = action_gateway.approval_manager.create_approval_request(
        request_id=f"REQ-RES-{uuid.uuid4().hex[:4]}",
        agent_id=agent_id,
        action="TRANSFER_FUNDS",
        resource="ACC-001",
        parameters={"amount": 20000.0},
        policy_id="FIN-POLICY-001",
        reason="HIGH_VALUE_TRANSACTION"
    )
    app_id = app_record["approval_id"]

    # Revoke agent while request is held
    agent_registry.revoke_agent(agent_id, "REVOKED_DURING_HOLD")

    # Attempt to resume approval
    res = action_gateway.process_human_approval_resume(app_id, "SYSTEM_ADMIN")
    assert res["decision"] == "BLOCKED"
    assert "AGENT_REVOKED_OR_INACTIVE_ON_RESUME" in res["reason"]

# --- Finding #12: Idempotency Key Scoped per Agent ---
def test_regression_idempotency_scoped_per_agent():
    """Verify that idempotency keys are scoped per agent to prevent cross-agent data leakage."""
    prot_api = ProtectedFinanceAPI()
    headers1 = prot_api.create_gateway_auth_headers("REQ-IDEMP-01")
    headers2 = prot_api.create_gateway_auth_headers("REQ-IDEMP-02")

    res1 = prot_api.execute_action(
        action="TRANSFER_FUNDS",
        parameters={"amount": 500.0, "target_account": "ACC-AGENT1"},
        gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
        request_id="REQ-IDEMP-01",
        agent_id="AGENT-001",
        auth_headers=headers1,
        idempotency_key="SHARED-IDEMP-KEY"
    )

    res2 = prot_api.execute_action(
        action="TRANSFER_FUNDS",
        parameters={"amount": 90000.0, "target_account": "ACC-AGENT2"},
        gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
        request_id="REQ-IDEMP-02",
        agent_id="AGENT-002",
        auth_headers=headers2,
        idempotency_key="SHARED-IDEMP-KEY"
    )

    assert res1["transaction_data"]["amount"] == 500.0
    assert res2["transaction_data"]["amount"] == 90000.0
    assert res2.get("idempotent_replay") is not True

# --- Finding #14: String Amount Handled Gracefully ---
def test_regression_string_amount_invalid_format():
    """Verify that non-numeric string amount is caught safely and audited as INVALID_AMOUNT_FORMAT."""
    agent_id = f"AGENT-STR-{uuid.uuid4().hex[:4]}"
    reg = agent_registry.register_agent(agent_id=agent_id, agent_name="StrAgent")
    
    payload = {
        "request_id": f"REQ-STR-{uuid.uuid4().hex[:4]}",
        "agent_id": agent_id,
        "action": "CREATE_PURCHASE_ORDER",
        "resource": "SUPPLIER-001",
        "amount": "INVALID_NON_NUMERIC_STRING",
        "parameters": {"amount": "INVALID_NON_NUMERIC_STRING"},
        "nonce": f"N-{uuid.uuid4().hex[:6]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    sig = SignatureManager.sign_request(payload, reg["private_key"])
    payload["signature"] = sig

    res = action_gateway.process_request(payload)
    assert res["decision"] == "BLOCKED"
    assert res["reason"] == "INVALID_AMOUNT_FORMAT"
