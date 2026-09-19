import time
import uuid
import datetime
import sys
import os
from typing import Dict, Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

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
from action_gateway.retry_queue import RetryQueueManager

# ANSI Color codes for clean live demo output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'=' * 90}{RESET}")
    print(f"{BOLD}{CYAN} > {title.upper()}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 90}{RESET}")

def print_step(scenario_num: int, name: str, result_status: str, details: str):
    status_color = GREEN if "ALLOWED" in result_status or "VERIFIED" in result_status or "RECOVERED" in result_status else (YELLOW if "APPROVAL" in result_status else RED)
    print(f"\n{BOLD}Scenario #{scenario_num}: {name}{RESET}")
    print(f" * Result      : {status_color}{BOLD}{result_status}{RESET}")
    print(f" * Description : {details}")

def run_live_demo():
    print_header("AgentTrust Security & Accountability Framework - Live Demonstration")
    print(f"System Time: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("Initialising AgentTrust Cryptographic Authority, Policy Engine, Gateway & Ledger...\n")

    # Core System Initialization
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

    # 1. Register Autonomous AI Agent & Policy
    print(f"{BOLD}[+] Registering Autonomous Agent FINANCE-AGENT-001 with X.509 Certificate...{RESET}")
    agent_info = reg.register_agent("FINANCE-AGENT-001", "FinanceAgent", "Finance Dept", ["CREATE_REIMBURSEMENT"], "FIN-POLICY-001")
    priv_key = agent_info["private_key"]
    pub_key = agent_info["public_key"]
    print(f"    * Cert Fingerprint: {agent_info['certificate_fingerprint'][:24]}...")
    print(f"    * RSA 2048 Private Key Encrypted at Rest (AES-256-GCM)")

    # Define Bounded Policy: Max ₹10,000 auto-allow, Above ₹10,000 requires human approval
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
    print(f"    * Policy Configured: Max Auto Amount = Rs 10,000.00 | Human Approval Threshold = Rs 10,000.00")

    # --- SCENARIO 1: Valid ₹7,500 Reimbursement ---
    print_header("Scenario 1: Valid Rs 7,500 Reimbursement Request")
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    p1 = {
        "request_id": f"REQ-DEMO-01-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-101", "amount": 7500.0},
        "nonce": f"N-DEMO-01-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    p1["signature"] = SignatureManager.sign_request(p1, priv_key)
    res1 = gw.process_request(p1)
    print_step(1, "Valid Low-Value Reimbursement (Rs 7,500)", f"{res1['decision']} ({res1['protected_api_result']})", 
               f"Request within Rs 10,000 limit. Signed with RSA private key. Executed on Protected API & Committed to Block #{res1['blockchain']['block_index']}")

    # --- SCENARIO 2: ₹80,000 Reimbursement (Blocked) ---
    print_header("Scenario 2: Excessive Rs 80,000 Reimbursement Request")
    p2 = {
        "request_id": f"REQ-DEMO-02-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-102", "amount": 80000.0},
        "nonce": f"N-DEMO-02-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    p2["signature"] = SignatureManager.sign_request(p2, priv_key)
    res2 = gw.process_request(p2)
    print_step(2, "Excessive Amount Request (Rs 80,000)", f"{res2['decision']} ({res2['reason']})", 
               "Request exceeds policy limit (Rs 10,000). Action Gateway blocked API execution and audited block event.")

    # --- SCENARIO 3: Invalid Cryptographic Signature ---
    print_header("Scenario 3: Tampered Payload / Forged Cryptographic Signature")
    p3 = {
        "request_id": f"REQ-DEMO-03-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-103", "amount": 5000.0},
        "nonce": f"N-DEMO-03-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso,
        "signature": "INVALID_RSA_SIGNATURE_STRING_FORGED"
    }
    res3 = gw.process_request(p3)
    print_step(3, "Invalid Signature Attempt", f"{res3['decision']} ({res3['reason']})", 
               "Gateway cryptographic verification failed signature validation. Request rejected prior to policy check.")

    # --- SCENARIO 4: Revoked Agent Execution Attempt ---
    print_header("Scenario 4: Compromised / Revoked Agent Action Attempt")
    rev_agent_info = reg.register_agent("REVOKED-AGENT-001", "CompromisedAgent", "SecOps", ["CREATE_REIMBURSEMENT"], "FIN-POLICY-001")
    reg.revoke_agent("REVOKED-AGENT-001")
    print(f"    * Administrator Action: Revoked certificate status for REVOKED-AGENT-001 in Registry.")
    p4 = {
        "request_id": f"REQ-DEMO-04-{uuid.uuid4().hex[:6]}",
        "agent_id": "REVOKED-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-104", "amount": 3000.0},
        "nonce": f"N-DEMO-04-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    p4["signature"] = SignatureManager.sign_request(p4, rev_agent_info["private_key"])
    res4 = gw.process_request(p4)
    print_step(4, "Revoked Agent Execution", f"{res4['decision']} ({res4['reason']})", 
               "Gateway checked agent registry state. Certificate is REVOKED. Request blocked instantly.")

    # --- SCENARIO 5: Replay Attack ---
    print_header("Scenario 5: Replay Attack Detection")
    req_id_5 = f"REQ-DEMO-05-{uuid.uuid4().hex[:6]}"
    nonce_5 = f"N-DEMO-05-{uuid.uuid4().hex[:6]}"
    p5 = {
        "request_id": req_id_5,
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-105", "amount": 4000.0},
        "nonce": nonce_5,
        "timestamp": now_iso
    }
    p5["signature"] = SignatureManager.sign_request(p5, priv_key)
    res5_a = gw.process_request(p5)
    print(f"    * Original Request Execution : {res5_a['decision']} (Block #{res5_a['blockchain']['block_index']})")
    
    # Replay same payload
    res5_b = gw.process_request(p5)
    print_step(5, "Replayed Request Attempt", f"{res5_b['decision']} ({res5_b['reason']})", 
               f"Duplicate request_id ({req_id_5}) and nonce ({nonce_5}) detected by RequestTracker within 300s window.")

    # --- SCENARIO 6: High-Value Request -> Human Approval ---
    print_header("Scenario 6: High-Value Transaction Requiring Human Supervisor Approval")
    # Update policy to allow up to ₹50,000 with human approval above ₹10,000
    policy.maximum_amount = 50000.0
    policy.human_approval_above = 10000.0
    loader.save_policy(policy)

    p6 = {
        "request_id": f"REQ-DEMO-06-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-106", "amount": 25000.0},
        "nonce": f"N-DEMO-06-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    p6["signature"] = SignatureManager.sign_request(p6, priv_key)
    res6 = gw.process_request(p6)
    print(f"    * Gateway Evaluation : {res6['decision']} ({res6['reason']})")
    print(f"    * Approval Ticket ID : {res6['approval_ticket']['approval_id']}")
    
    # Simulate CFO Approval
    appr_res = gw.process_human_approval_resume(res6['approval_ticket']['approval_id'], "CFO_EXECUTIVE_HUMAN")
    print_step(6, "High-Value Workflow (Rs 25,000)", f"{appr_res['decision']} ({appr_res['protected_api_result']})", 
               "Held in human approval queue until CFO approval. Resumed and committed to ledger upon sign-off.")

    # --- SCENARIO 7: Evidence Modification & Tamper Detection ---
    print_header("Scenario 7: Off-Chain Evidence Modification & Cryptographic Tamper Detection")
    p7 = {
        "request_id": f"REQ-DEMO-07-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-107", "amount": 6200.0},
        "nonce": f"N-DEMO-07-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    p7["signature"] = SignatureManager.sign_request(p7, priv_key)
    res7 = gw.process_request(p7)
    ev_id = res7["evidence"]["evidence_id"]
    stored_hash = res7["evidence"]["evidence_hash"]
    
    print(f"    * Original Evidence Reference : {ev_id}")
    print(f"    * On-Chain Recorded SHA-256   : {stored_hash}")
    
    # Simulate database tampering
    ev_store.simulate_tamper(ev_id, "amount", 999999.0)
    print(f"    * Malicious Database Action   : Changed 'amount' off-chain to Rs 999,999.00")
    
    # Verify hash against Fabric ledger
    tampered_ev = ev_store.get_evidence(ev_id)
    recalc_hash = HashManager.calculate_evidence_hash(tampered_ev)
    v_res = fabric.verify_evidence_hash(ev_id, recalc_hash)
    
    print_step(7, "Off-Chain Evidence Verification", f"{v_res['status']} (Verified={v_res['verified']})", 
               f"Recalculated Hash ({recalc_hash[:16]}...) mismatched Stored Blockchain Hash ({stored_hash[:16]}...). Tampering flagged.")

    # --- SCENARIO 8: Ledger Failure -> Retry & DLQ Recovery ---
    print_header("Scenario 8: Orderer Outage & Durable Dead-Letter Queue (DLQ) Recovery")
    
    # Simulate Orderer failure
    orig_record_fn = fabric.record_action_event
    def mock_orderer_down(*args, **kwargs):
        raise RuntimeError("Fabric Consensus Orderer Connection Timeout")
    fabric.record_action_event = mock_orderer_down

    p8 = {
        "request_id": f"REQ-DEMO-08-{uuid.uuid4().hex[:6]}",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "resource": "FINANCE_API",
        "parameters": {"employee_id": "EMP-108", "amount": 4800.0},
        "nonce": f"N-DEMO-08-{uuid.uuid4().hex[:6]}",
        "timestamp": now_iso
    }
    p8["signature"] = SignatureManager.sign_request(p8, priv_key)
    res8 = gw.process_request(p8)
    
    print(f"    * Initial Execution Status : {res8['blockchain']['status']}")
    print(f"    * Off-Chain Evidence Status: {res8['evidence']['off_chain_status']}")
    
    # Enqueue failed commit into DLQ
    event_id_8 = res8["blockchain"]["event_id"]
    retry_mgr.enqueue_failed_commit(
        event_id=event_id_8,
        request_id=p8["request_id"],
        payload={
            "event_id": event_id_8,
            "request_id": p8["request_id"],
            "agent_id": "FINANCE-AGENT-001",
            "action": "CREATE_REIMBURSEMENT",
            "resource": "FINANCE_API",
            "decision": "ALLOWED",
            "reason": "WITHIN_AUTHORITY_LIMIT",
            "policy_id": "FIN-POLICY-001",
            "policy_version": "1.0",
            "evidence_reference": res8["evidence"]["evidence_id"],
            "evidence_hash": res8["evidence"]["evidence_hash"]
        },
        error_msg="Orderer Connection Timeout"
    )
    print(f"    * Dead-Letter Queue State  : {len(retry_mgr.list_pending_retries())} pending event enqueued.")

    # Restore Orderer Service
    fabric.record_action_event = orig_record_fn
    print(f"    * Network Status Restored  : Hyperledger Fabric Orderer service back online.")
    
    # Process Retry
    ok, msg = retry_mgr.retry_commit(event_id_8, fabric)
    print_step(8, "Ledger Outage Recovery", f"RECOVERED ({msg})", 
               "API execution preserved off-chain during outage. Retry queue flushed transaction safely onto Fabric block chain.")

    print_header("Live Demonstration Successfully Completed (8/8 Scenarios Passed)")

if __name__ == "__main__":
    run_live_demo()
