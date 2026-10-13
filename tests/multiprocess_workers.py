"""
Multiprocess Worker Functions for Live Cross-Process Stress Testing.
Module-level functions designed for Windows 'spawn' compatibility in multiprocessing.
"""

# ruff: noqa: E402
import copy
import os
import sys
from typing import Any

# Ensure workspace root is in sys.path
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from fabric.persistent_db import PersistentStorageEngine
from action_gateway.gateway import ActionGateway
from action_gateway.retry_queue import RetryQueueManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from policy_engine.policy_models import PolicyRecord, WorkingHours
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker


def worker_claim_nonce(db_path: str, request_id: str, nonce: str, ts: float, result_queue: Any) -> None:
    """Worker process claiming a nonce in persistent DB."""
    try:
        db = PersistentStorageEngine(db_path)
        claimed = db.try_claim_request_nonce(request_id, nonce, ts)
        result_queue.put({"success": True, "claimed": claimed, "pid": os.getpid()})
    except Exception as e:
        result_queue.put({"success": False, "error": str(e), "pid": os.getpid()})


def worker_acquire_lock(
    db_path: str,
    agent_id: str,
    idempotency_key: str,
    owner_id: str,
    ttl_seconds: float,
    result_queue: Any
) -> None:
    """Worker process attempting in-flight lock acquisition with leases and fencing tokens."""
    try:
        db = PersistentStorageEngine(db_path)
        res = db.try_acquire_in_flight_lock(
            agent_id=agent_id,
            idempotency_key=idempotency_key,
            owner_id=owner_id,
            ttl_seconds=ttl_seconds
        )
        result_queue.put({
            "success": True,
            "acquired": res.acquired,
            "fencing_token": res.fencing_token,
            "owner_id": res.owner_id,
            "pid": os.getpid()
        })
    except Exception as e:
        result_queue.put({"success": False, "error": str(e), "pid": os.getpid()})


def _build_worker_gateway(db_path: str) -> tuple[ActionGateway, ProtectedFinanceAPI]:
    """Constructs an independent ActionGateway instance bound to the shared SQLite DB."""
    persistent_db = PersistentStorageEngine(db_path=db_path)
    cert_manager = CertificateManager(db_path=db_path)
    identity_store = IdentityStore(db_path=db_path)
    registry = AgentRegistry(cert_manager, identity_store)

    policy_loader = PolicyLoader()
    policy = PolicyRecord(
        policy_id="FIN-POLICY-001",
        agent_id="AGENT-OS-PROC",
        allowed_actions=["TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "READ_ACCOUNT"],
        allowed_resource="BANK_RESERVE_IN",
        maximum_amount=100000.0,
        human_approval_above=100000.0,
        working_hours=WorkingHours(start="00:00", end="23:59"),
        version="1.0"
    )
    policy_loader.save_policy(policy)
    policy_evaluator = PolicyEvaluator(policy_loader)
    approval_manager = HumanApprovalManager(db_path=db_path)
    evidence_store = EvidenceStore(db_path=db_path)
    fabric_client = FabricClient()
    finance_api = ProtectedFinanceAPI()
    replay_tracker = RequestTracker(300, persistent_db=persistent_db)
    retry_queue = RetryQueueManager(persistent_db=persistent_db)

    gw = ActionGateway(
        registry=registry,
        cert_manager=cert_manager,
        policy_evaluator=policy_evaluator,
        replay_tracker=replay_tracker,
        finance_api=finance_api,
        approval_manager=approval_manager,
        evidence_store=evidence_store,
        fabric_client=fabric_client,
        persistent_db=persistent_db,
        retry_queue=retry_queue
    )
    return gw, finance_api


def worker_process_request(db_path: str, req_payload: dict[str, Any], result_queue: Any) -> None:
    """Independent worker process executing process_request on a signed request."""
    try:
        gw, finance_api = _build_worker_gateway(db_path)
        outcome = gw.process_request(copy.deepcopy(req_payload))
        result_queue.put({
            "success": True,
            "outcome": outcome,
            "transfers_count": len(finance_api.service._fund_transfers),
            "pid": os.getpid()
        })
    except Exception as e:
        result_queue.put({"success": False, "error": str(e), "pid": os.getpid()})


def worker_reconcile_outbox(db_path: str, result_queue: Any) -> None:
    """Independent worker process executing reconcile_pending_commits."""
    try:
        gw, _ = _build_worker_gateway(db_path)
        res = gw.reconcile_pending_commits()
        result_queue.put({"success": True, "reconcile_summary": res, "pid": os.getpid()})
    except Exception as e:
        result_queue.put({"success": False, "error": str(e), "pid": os.getpid()})
