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
from fabric.fabric_client import FabricClient
from action_gateway.gateway import ActionGateway
from action_gateway.retry_queue import RetryQueueManager

def test_complete_8step_failure_recovery_sequence():
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
    retry_mgr = RetryQueueManager()

    gw = ActionGateway(reg, cm, evaluator, replay, api, approval, ev_store, fabric)
    agent_info = reg.register_agent("FINANCE-AGENT-001", "FinanceAgent", "Finance Dept", ["CREATE_REIMBURSEMENT"], "FIN-POLICY-001")
    priv_key = agent_info["private_key"]

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

    # 1. Process valid request while Orderer fails
    original_record_fn = fabric.record_action_event

    def mock_orderer_failure(*args, **kwargs):
        raise RuntimeError("Fabric Orderer Connection Timeout")

    fabric.record_action_event = mock_orderer_failure

    req_id = f"REQ-REC-{uuid.uuid4().hex[:6]}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = {
        "request_id": req_id,
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-REC", "amount": 3500.0},
        "nonce": f"N-REC-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)

    res = gw.process_request(payload)

    # 2. Confirm evidence preserved off-chain and commit marked failed
    assert res["evidence"]["off_chain_status"] == "STORED"
    assert "COMMIT_FAILED" in res["blockchain"]["status"]

    # Enqueue into retry queue
    event_id = res["blockchain"]["event_id"]
    retry_mgr.enqueue_failed_commit(
        event_id=event_id,
        request_id=req_id,
        payload={
            "event_id": event_id,
            "request_id": req_id,
            "agent_id": "FINANCE-AGENT-001",
            "action": "CREATE_REIMBURSEMENT",
            "resource": "FINANCE_API",
            "decision": "ALLOWED",
            "reason": "WITHIN_AUTHORITY_LIMIT",
            "policy_id": "FIN-POLICY-001",
            "policy_version": "1.0",
            "evidence_reference": res["evidence"]["evidence_id"],
            "evidence_hash": res["evidence"]["evidence_hash"]
        },
        error_msg="Orderer Connection Timeout"
    )

    assert len(retry_mgr.list_pending_retries()) == 1

    # 3. Restore Fabric Orderer Service
    fabric.record_action_event = original_record_fn

    # 4. Retry commitment safely
    ok, msg = retry_mgr.retry_commit(event_id, fabric)
    assert ok is True
    assert msg == "RETRY_SUCCESSFUL"

    # 5. Confirm exactly 1 final ledger event exists in Fabric
    events = fabric.query_by_agent("FINANCE-AGENT-001")
    matching_events = [e for e in events if e.get("request_id") == req_id]
    assert len(matching_events) == 1
