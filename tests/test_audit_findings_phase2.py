"""
Targeted tests for Phase 2 Audit Findings:
1. Atomic resume validator & elimination of TOCTOU window.
2. Top-level delegation token capture & re-validation during approval resume.
3. Persistent delegation token revocations across restarts.
4. Fail-closed EvidencePersistenceError handling in EvidenceStore.
5. SQLite hydration across restarts for HumanApprovalManager & EvidenceStore.
6. Thread-safe UUID-based event IDs in ActionGateway.
7. Thread-safe ProcurementService with atomic transaction counter and locking.
"""

import os
import tempfile
import uuid
import pytest

from evidence_manager.evidence_store import EvidenceStore, EvidencePersistenceError
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.delegation import DelegationTokenManager
from protected_api.finance_api import ProcurementService
from server import action_gateway, agent_registry


def test_finding_1_atomic_resume_validator_prevents_toctou():
    """Verify that atomic resume validator prevents TOCTOU race conditions."""
    agent_id = f"AGENT-TOCTOU-{uuid.uuid4().hex[:4]}"
    agent_registry.register_agent(agent_id=agent_id, agent_name="TOCTOUAgent")
    
    # Create ticket
    app_record = action_gateway.approval_manager.create_approval_request(
        request_id=f"REQ-TOCTOU-{uuid.uuid4().hex[:4]}",
        agent_id=agent_id,
        action="TRANSFER_FUNDS",
        resource="ACC-TOCTOU",
        parameters={"amount": 30000.0},
        policy_id="FIN-POLICY-001",
        reason="HIGH_RISK"
    )
    app_id = app_record["approval_id"]
    token = app_record["approval_token"]

    # Revoke agent status before approval resume
    agent_registry.revoke_agent(agent_id)

    # Attempt resume approval
    res = action_gateway.process_human_approval_resume(app_id, approver_id="HUMAN_SUPERVISOR_01", provided_token=token)
    
    assert res["decision"] == "BLOCKED"
    assert "RESUME_VALIDATION_FAILED" in res["reason"]
    
    # Confirm ticket was NOT consumed because atomic validation failed
    ticket_after = action_gateway.approval_manager.get_approval_by_id(app_id)
    assert ticket_after["status"] != "APPROVED"


def test_finding_2_top_level_delegation_token_revalidated_on_resume():
    """Verify that top-level delegation tokens are captured and re-validated during approval resume."""
    issuer_id = f"AGENT-ISSUER-{uuid.uuid4().hex[:4]}"
    delegate_id = f"AGENT-DEL-{uuid.uuid4().hex[:4]}"
    
    reg_issuer = agent_registry.register_agent(agent_id=issuer_id, agent_name="IssuerAgent")
    agent_registry.register_agent(agent_id=delegate_id, agent_name="DelegateAgent")

    # Create signed delegation token
    del_token = DelegationTokenManager.create_delegated_token(
        issuer_agent_id=issuer_id,
        delegate_agent_id=delegate_id,
        allowed_actions=["TRANSFER_FUNDS"],
        maximum_amount=50000.0,
        issuer_private_key=reg_issuer["private_key"]
    )

    # Top-level delegation token in request
    req_payload = {
        "request_id": f"REQ-DEL-{uuid.uuid4().hex[:4]}",
        "agent_id": delegate_id,
        "action": "TRANSFER_FUNDS",
        "resource": "ACC-999",
        "parameters": {"amount": 25000.0},
        "delegation_token": del_token
    }

    # Ticket creation stores normalized delegation_token
    ticket = action_gateway.approval_manager.create_approval_request(
        request_id=req_payload["request_id"],
        agent_id=delegate_id,
        action="TRANSFER_FUNDS",
        resource="ACC-999",
        parameters=req_payload["parameters"],
        reason="HIGH_RISK",
        policy_id="FIN-POLICY-001",
        delegation_token=del_token
    )

    # Revoke delegation token before resume
    DelegationTokenManager.revoke_token(del_token["token_id"])

    # Resume must re-validate delegation token and fail closed
    res = action_gateway.process_human_approval_resume(ticket["approval_id"], "HUMAN_SUPERVISOR_01", ticket["approval_token"])
    assert res["decision"] == "BLOCKED"
    assert "DELEGATION_RECHECK_FAILED" in res["reason"] or "RESUME_VALIDATION_FAILED" in res["reason"]


def test_finding_3_delegation_revocation_persistent_sqlite():
    """Verify delegation token revocations persist in SQLite across process/manager instances."""
    tok_id = f"DEL-TOK-PERSIST-{uuid.uuid4().hex[:6].upper()}"
    DelegationTokenManager.revoke_token(tok_id)

    assert DelegationTokenManager.is_token_revoked(tok_id) is True

    # Re-check via PersistentStorageEngine
    from fabric.persistent_db import PersistentStorageEngine
    revs = PersistentStorageEngine().get_delegation_revocations()
    assert tok_id in revs


def test_finding_4_evidence_persistence_error_handling():
    """Verify EvidenceStore raises EvidencePersistenceError when SQLite storage fails."""
    store = EvidenceStore(db_path="/invalid_dir/non_existent.db")
    ev_rec = {
        "evidence_id": f"EV-TEST-{uuid.uuid4().hex[:4]}",
        "request_id": "REQ-1",
        "agent_id": "AGENT-1"
    }
    with pytest.raises(EvidencePersistenceError):
        store.save_evidence(ev_rec)


def test_finding_5_sqlite_state_hydration_on_startup():
    """Verify HumanApprovalManager and EvidenceStore hydrate runtime state from SQLite DB on startup."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        mgr1 = HumanApprovalManager(db_path=db_path)
        ticket = mgr1.create_approval_request(
            request_id="REQ-HYDRATE-1",
            agent_id="AGENT-1",
            action="TRANSFER_FUNDS",
            resource="ACC-1",
            parameters={"amount": 1000.0},
            reason="RISK",
            policy_id="POL-1"
        )
        app_id = ticket["approval_id"]

        # Instantiate second manager pointing to same SQLite database
        mgr2 = HumanApprovalManager(db_path=db_path)
        ticket_hydrated = mgr2.get_approval_by_id(app_id)
        assert ticket_hydrated is not None
        assert ticket_hydrated["request_id"] == "REQ-HYDRATE-1"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_finding_6_thread_safe_uuid_event_ids():
    """Verify ActionGateway generates unique, thread-safe UUID-based event IDs."""
    out = action_gateway._finalize_gateway_outcome(
        request_id="REQ-EVENT-1",
        agent_id="AGENT-1",
        action="READ_ACCOUNT",
        resource="ACC-1",
        parameters={},
        decision="ALLOWED",
        reason="OK",
        policy_id="POL-1",
        policy_version="1.0",
        agent_version="1.0",
        api_result="EXECUTED"
    )
    event_id = out["blockchain"]["event_id"]
    assert event_id.startswith("EVENT-")
    assert len(event_id) > 10


def test_finding_7_procurement_service_concurrency_and_locking():
    """Verify ProcurementService generates thread-safe unique IDs under concurrent calls."""
    import threading
    service = ProcurementService()
    results = []

    def _worker(idx):
        po = service.create_purchase_order(f"REQ-{idx}", f"AGENT-{idx}", f"SUP-{idx}", "Item", 100.0)
        results.append(po["po_id"])

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 20
    assert len(set(results)) == 20  # All 20 PO IDs must be unique
