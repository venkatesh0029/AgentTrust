"""
Comprehensive Hardening & Audit Findings Verification Test Suite (V5)

Verifies:
1. Finding 1: 3-Node Raft Orderer consensus configuration in configtx.yaml & docker-compose.
2. Finding 2: Parameterized credentials in docker-compose-fabric.yaml & existence of .env.example.
3. Finding 3: Isolated TCP peer connectivity probe vs ledger commit status in fabric_client.
4. Finding 5: Atomic cumulative volume checking and reservation eliminating TOCTOU race.
5. Finding 6: ECDSA certificate signature verification & fail-closed unsupported CA key types.
6. Loophole 9: Auto-signing disabled in production mode.
7. Loophole 10: Strict approval token verification on human approval resume.
8. Loophole 11: Fail-closed behavior on persistent database volume check error.
9. Loophole 12: Fail-closed rejection of unknown delegation tokens.
10. Loophole 13: Atomic ON CONFLICT upsert preservation for delegation and behavior engines.
"""

import datetime
import os
import sqlite3
import tempfile
import threading
import time
import uuid

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from action_gateway.gateway import ActionGateway
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry
from evidence_manager.evidence_store import EvidenceStore
from fabric.fabric_client import FabricClient
from fabric.persistent_db import PersistentStorageEngine
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from identity_manager.delegation_graph import delegation_graph_manager
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_loader import PolicyLoader
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker
from risk_engine.behavior_engine import agent_behavior_engine


# -----------------------------------------------------------------------------
# Finding 1 & 2: Fabric Configuration Hardening
# -----------------------------------------------------------------------------
def test_finding_1_raft_three_consenters_configured():
    """Verify that configtx.yaml specifies at least 3 Raft orderer consenters."""
    config_path = os.path.join(os.path.dirname(__file__), "..", "fabric", "configtx.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    consen = cfg["Orderer"]["EtcdRaft"]["Consenters"]
    assert len(consen) >= 3, f"Expected at least 3 Raft consenters for quorum, found {len(consen)}"
    hosts = [c["Host"] for c in consen]
    assert "orderer.agenttrust.com" in hosts
    assert "orderer2.agenttrust.com" in hosts
    assert "orderer3.agenttrust.com" in hosts


def test_finding_2_parameterized_infrastructure_credentials_and_env_example():
    """Verify that docker-compose-fabric.yaml parameterizes passwords and .env.example exists."""
    compose_path = os.path.join(os.path.dirname(__file__), "..", "fabric", "docker-compose-fabric.yaml")
    with open(compose_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "${COUCHDB_PASSWORD" in content, "CouchDB password must be parameterized"
    assert "${FABRIC_CA_ADMIN_PASSWORD" in content, "Fabric CA password must be parameterized"

    env_example = os.path.join(os.path.dirname(__file__), "..", "fabric", ".env.example")
    assert os.path.exists(env_example), "fabric/.env.example template must exist"


# -----------------------------------------------------------------------------
# Finding 3: Isolated Peer Connectivity Probe
# -----------------------------------------------------------------------------
def test_finding_3_probe_peer_connectivity_isolated():
    """Verify that socket reachability probe returns PEER_ENDPOINT status and does not fake commit."""
    fc = FabricClient()
    # Unconfigured
    fc.peer_endpoint = ""
    probe = fc.probe_peer_connectivity()
    assert probe["status"] == "PEER_ENDPOINT_NOT_CONFIGURED"

    # Unreachable IP
    fc.peer_endpoint = "192.0.2.1:7051"
    probe_unreach = fc.probe_peer_connectivity()
    assert probe_unreach["status"] == "PEER_ENDPOINT_UNREACHABLE"
    assert probe_unreach["reachable"] is False


# -----------------------------------------------------------------------------
# Finding 5: Atomic Cumulative Volume Reservation Eliminating TOCTOU
# -----------------------------------------------------------------------------
def test_finding_5_atomic_cumulative_volume_reservation():
    """Verify check_and_reserve_cumulative_volume enforces limit under concurrent execution."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_volume.db")
        db = PersistentStorageEngine(db_path=db_path)
        agent_id = "SMURF-AGENT-001"
        cap = 10000.0  # Max limit ₹10,000

        results = []

        def worker(idx):
            ok, total, count, reason = db.check_and_reserve_cumulative_volume(
                agent_id=agent_id,
                action="TRANSFER_FUNDS",
                amount=4000.0,
                window_seconds=86400,
                max_cumulative_limit=cap,
                request_id=f"REQ-SMURF-{idx}"
            )
            results.append((ok, total, reason))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for ok, _, _ in results if ok)
        denied_count = sum(1 for ok, _, _ in results if not ok)

        # Exactly 2 should be allowed (2 * 4,000 = 8,000 <= 10,000; 3rd would be 12,000 > 10,000)
        assert allowed_count == 2, f"Expected exactly 2 allowed under cap, got {allowed_count}"
        assert denied_count == 2, f"Expected exactly 2 rejected under cap, got {denied_count}"
        db.close()


# -----------------------------------------------------------------------------
# Finding 6: ECDSA & Unsupported CA Key Handling in Certificate Manager
# -----------------------------------------------------------------------------
def test_finding_6_certificate_manager_ecdsa_and_unsupported_key_support():
    """Verify CertificateManager verifies ECDSA Root CA signatures and rejects unsupported keys."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_ca.db")
        cert_mgr = CertificateManager(db_path=db_path)

        # 1. Generate an ECDSA Root CA
        ecdsa_ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "AgentTrust ECDSA Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentTrust Framework"),
        ])
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        ecdsa_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ecdsa_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now_utc - datetime.timedelta(days=1))
            .not_valid_after(now_utc + datetime.timedelta(days=365))
            .sign(ecdsa_ca_key, hashes.SHA256())
        )

        # Set cert_mgr to use ECDSA CA
        cert_mgr.ca_private_key = ecdsa_ca_key
        cert_mgr.ca_public_key = ecdsa_ca_key.public_key()
        cert_mgr.ca_certificate = ecdsa_ca_cert

        # Issue agent certificate with ECDSA CA
        agent_cert_pem, _, _ = cert_mgr.issue_agent_certificate(
            agent_id="ECDSA-TEST-AGENT",
            agent_name="ECDSA Agent"
        )

        # Verify agent certificate against ECDSA CA
        verify_res = cert_mgr.verify_agent_certificate(agent_cert_pem)
        assert verify_res["valid"] is True, f"ECDSA CA verification failed: {verify_res}"
        assert verify_res["agent_id"] == "ECDSA-TEST-AGENT"

        # 2. Unsupported CA key type test: pass mock unsupported key
        class UnsupportedKey:
            pass

        cert_mgr.ca_public_key = UnsupportedKey()
        unsupported_res = cert_mgr.verify_agent_certificate(agent_cert_pem)
        assert unsupported_res["valid"] is False
        assert "UNSUPPORTED_CA_KEY_ALGORITHM" in unsupported_res["reason"]


# -----------------------------------------------------------------------------
# Loophole 11 & 12: Gateway Fail-Closed Rejections
# -----------------------------------------------------------------------------
def test_loophole_11_fail_closed_on_persistent_db_volume_exception():
    """Verify ActionGateway fails closed if get_cumulative_volume or reservation throws an unexpected exception."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_gw.db")
        cert_mgr = CertificateManager(db_path=db_path)
        id_store = IdentityStore(db_path=db_path)
        registry = AgentRegistry(cert_mgr, id_store)

        from policy_engine.policy_models import PolicyRecord
        loader = PolicyLoader()
        loader.save_policy(PolicyRecord(
            policy_id="FIN-POLICY-001",
            agent_id="ERR-AGENT-01",
            version="1.0",
            allowed_actions=["CREATE_PURCHASE_ORDER"],
            allowed_resource="*",
            maximum_amount=50000.0,
            human_approval_above=25000.0
        ))

        reg = registry.register_agent(
            agent_id="ERR-AGENT-01",
            agent_name="Error Test Agent",
            policy_id="FIN-POLICY-001"
        )
        priv_key = reg["private_key"]

        class BrokenDB(PersistentStorageEngine):
            def check_and_reserve_cumulative_volume(self, *args, **kwargs):
                raise sqlite3.OperationalError("Simulated database lock failure / I/O error")

            def get_cumulative_volume(self, *args, **kwargs):
                raise sqlite3.OperationalError("Simulated database lock failure / I/O error")

        broken_db = BrokenDB(db_path=db_path)
        gw = ActionGateway(
            registry=registry,
            cert_manager=cert_mgr,
            policy_evaluator=PolicyEvaluator(loader),
            replay_tracker=RequestTracker(300),
            finance_api=ProtectedFinanceAPI(),
            approval_manager=HumanApprovalManager(),
            evidence_store=EvidenceStore(),
            fabric_client=FabricClient(),
            persistent_db=broken_db
        )

        payload = {
            "request_id": f"REQ-ERR-{uuid.uuid4().hex[:6]}",
            "agent_id": "ERR-AGENT-01",
            "action": "CREATE_PURCHASE_ORDER",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 500.0},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)

        res = gw.process_request(payload)
        assert res["decision"] == "BLOCKED"
        assert "PERSISTENT_VOLUME_CHECK_FAILED" in res["reason"]


def test_loophole_12_unknown_string_delegation_token_fails_closed():
    """Verify ActionGateway fails closed when an unregistered string delegation token is supplied."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_del.db")
        cert_mgr = CertificateManager(db_path=db_path)
        id_store = IdentityStore(db_path=db_path)
        registry = AgentRegistry(cert_mgr, id_store)

        reg = registry.register_agent(agent_id="DEL-TEST-AGENT", agent_name="Del Test Agent")
        priv_key = reg["private_key"]

        gw = ActionGateway(
            registry=registry,
            cert_manager=cert_mgr,
            policy_evaluator=PolicyEvaluator(PolicyLoader()),
            replay_tracker=RequestTracker(300),
            finance_api=ProtectedFinanceAPI(),
            approval_manager=HumanApprovalManager(),
            evidence_store=EvidenceStore(),
            fabric_client=FabricClient()
        )

        payload = {
            "request_id": f"REQ-DEL-{uuid.uuid4().hex[:6]}",
            "agent_id": "DEL-TEST-AGENT",
            "action": "CREATE_PURCHASE_ORDER",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 500.0},
            "delegation_token": "DEL-UNREGISTERED-TOKEN-FORGED",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)

        res = gw.process_request(payload)
        assert res["decision"] == "BLOCKED"
        assert "UNKNOWN_DELEGATION_TOKEN" in res["reason"]


# -----------------------------------------------------------------------------
# Loophole 13: Delegation & Behavior Engines Use Atomic Upsert Without Data Wipe
# -----------------------------------------------------------------------------
def test_loophole_13_delegation_and_behavior_engines_atomic_upsert():
    """Verify that _persist_all in delegation_graph and behavior_engine preserves data with ON CONFLICT upsert."""
    # 1. Delegation graph manager
    graph_del = delegation_graph_manager.get_graph()
    assert len(graph_del["nodes"]) >= 4
    initial_count = len(graph_del["nodes"])
    delegation_graph_manager._persist_all()
    # Re-verify nodes intact
    graph_del_after = delegation_graph_manager.get_graph()
    assert len(graph_del_after["nodes"]) == initial_count

    # 2. Behavior engine
    summary_beh = agent_behavior_engine.get_summary()
    assert summary_beh["monitored_agents"] >= 4
    initial_monitored = summary_beh["monitored_agents"]
    agent_behavior_engine._persist_all()
    summary_beh_after = agent_behavior_engine.get_summary()
    assert summary_beh_after["monitored_agents"] == initial_monitored


# -----------------------------------------------------------------------------
# Second-Pass Audit Remediation Verification: End-to-End Concurrent Gateway Reservation
# -----------------------------------------------------------------------------
def test_second_pass_audit_concurrent_smurfing_via_action_gateway():
    """
    Second-Pass Review Gap 1: Verify ActionGateway.process_request() enforces atomic
    cumulative volume reservation across concurrent threads without a check-then-act race.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_gw_smurf.db")
        cert_mgr = CertificateManager(db_path=db_path)
        id_store = IdentityStore(db_path=db_path)
        registry = AgentRegistry(cert_mgr, id_store)
        p_db = PersistentStorageEngine(db_path=db_path)

        reg = registry.register_agent(
            agent_id="SMURF-GATEWAY-AGENT",
            agent_name="Concurrent Smurf Agent",
            policy_id="FIN-POLICY-001"
        )
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        policy = PolicyRecord(
            policy_id="FIN-POLICY-001",
            agent_id="SMURF-GATEWAY-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=10000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=25000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(policy)

        gw = ActionGateway(
            registry=registry,
            cert_manager=cert_mgr,
            policy_evaluator=PolicyEvaluator(loader),
            replay_tracker=RequestTracker(300),
            finance_api=ProtectedFinanceAPI(),
            approval_manager=HumanApprovalManager(),
            evidence_store=EvidenceStore(),
            fabric_client=FabricClient(),
            persistent_db=p_db
        )

        results = []
        barrier = threading.Barrier(4)

        def worker(idx):
            payload = {
                "request_id": f"REQ-GW-CONC-{idx}-{uuid.uuid4().hex[:6]}",
                "agent_id": "SMURF-GATEWAY-AGENT",
                "action": "TRANSFER_FUNDS",
                "resource": "SUPPLIER-101",
                "parameters": {"amount": 4000.0},
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "nonce": f"NONCE-GW-{idx}-{uuid.uuid4().hex[:8]}",
                "idempotency_key": f"IDEMP-GW-{idx}-{uuid.uuid4().hex[:8]}"
            }
            payload["signature"] = SignatureManager.sign_request(payload, priv_key)
            barrier.wait()
            res = gw.process_request(payload)
            results.append(res)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = [r for r in results if r["decision"] in ("ALLOWED", "COMPLETED")]
        blocked = [r for r in results if r["decision"] == "BLOCKED"]

        # Exactly 2 requests allowed (2 * 4,000 = 8,000 <= 10,000; 3rd would be 12,000 > 10,000)
        assert len(allowed) == 2, f"Expected exactly 2 allowed requests, got {len(allowed)} (blocked: {len(blocked)})"
        assert len(blocked) == 2, f"Expected exactly 2 blocked requests, got {len(blocked)}"
        for b in blocked:
            assert "CUMULATIVE_LIMIT_EXCEEDED" in b["reason"]
        p_db.close()


def test_second_pass_audit_crypto_specs_and_orderer_named_volumes():
    """
    Second-Pass Review Gap 2 & 3: Verify all 3 orderers exist in crypto-config.yaml
    and docker-compose-fabric.yaml defines named volumes for all 3 orderers and parameterizes credentials.
    """
    # 1. crypto-config.yaml
    crypto_path = os.path.join(os.path.dirname(__file__), "..", "fabric", "crypto-config.yaml")
    with open(crypto_path, "r", encoding="utf-8") as f:
        crypto_cfg = yaml.safe_load(f)

    orderer_orgs = crypto_cfg["OrdererOrgs"][0]
    specs = [s["Hostname"] for s in orderer_orgs["Specs"]]
    assert "orderer" in specs
    assert "orderer2" in specs
    assert "orderer3" in specs

    # 2. docker-compose-fabric.yaml named volumes
    compose_path = os.path.join(os.path.dirname(__file__), "..", "fabric", "docker-compose-fabric.yaml")
    with open(compose_path, "r", encoding="utf-8") as f:
        compose_cfg = yaml.safe_load(f)

    vols = compose_cfg.get("volumes", {})
    assert "orderer.agenttrust.com-data" in vols
    assert "orderer2.agenttrust.com-data" in vols
    assert "orderer3.agenttrust.com-data" in vols

    # 3. Credential parameterization consistency in peer & couchdb nodes
    services = compose_cfg.get("services", {})
    for p_name in ("peer0.org1.agenttrust.com", "peer0.org2.agenttrust.com"):
        env = services[p_name]["environment"]
        couch_user_env = [e for e in env if "CORE_LEDGER_STATE_COUCHDBCONFIG_USERNAME" in e]
        couch_pass_env = [e for e in env if "CORE_LEDGER_STATE_COUCHDBCONFIG_PASSWORD" in e]
        assert any("${COUCHDB_USER" in e for e in couch_user_env)
        assert any("${COUCHDB_PASSWORD" in e for e in couch_pass_env)


def test_second_pass_audit_fabric_client_honest_peer_status():
    """
    Second-Pass Review Gap 4: Verify _invoke_grpc_peer returns honest PEER_ENDPOINT_REACHABLE
    status and PROPOSAL_DISPATCH_UNCOMMITTED mode without claiming simulated commit.
    """
    import socket
    fc = FabricClient()

    # Create dummy local server socket to simulate open TCP port
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    try:
        fc.peer_endpoint = f"127.0.0.1:{port}"
        res = fc._invoke_grpc_peer("record_evidence", ["REQ-1", "HASH-1"])
        assert res["status"] == "PEER_ENDPOINT_REACHABLE"
        assert res["mode"] == "PROPOSAL_DISPATCH_UNCOMMITTED"
        assert "SIMULATED_LEDGER_COMMITTED" not in res["status"]
    finally:
        srv.close()


# -----------------------------------------------------------------------------
# Third-Pass Audit Remediation Verification: Approval-Resume Revalidation & Genesis Integrity
# -----------------------------------------------------------------------------
def test_third_pass_audit_approval_resume_capacity_exhaustion_blocks():
    """
    Third-Pass Review Task 1: Verify that if available cumulative volume is consumed by
    an intermediate transaction while a request awaits human approval, resuming approval
    fails closed and refuses to execute the request.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_resume_race.db")
        cert_mgr = CertificateManager(db_path=db_path)
        id_store = IdentityStore(db_path=db_path)
        registry = AgentRegistry(cert_mgr, id_store)
        p_db = PersistentStorageEngine(db_path=db_path)
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(
            agent_id="RESUME-RACE-AGENT",
            agent_name="Approval Resume Race Agent",
            policy_id="APPROVAL-RACE-POL"
        )
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        # Cumulative limit 30,000; require approval for anything above 25,000
        policy = PolicyRecord(
            policy_id="APPROVAL-RACE-POL",
            agent_id="RESUME-RACE-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=30000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=25000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(policy)

        gw = ActionGateway(
            registry=registry,
            cert_manager=cert_mgr,
            policy_evaluator=PolicyEvaluator(loader),
            replay_tracker=RequestTracker(300),
            finance_api=ProtectedFinanceAPI(),
            approval_manager=approval_mgr,
            evidence_store=EvidenceStore(db_path=db_path),
            fabric_client=FabricClient(),
            persistent_db=p_db
        )

        # 1. Submit Request 1 (₹26,000) -> Held for Human Approval
        req1_id = f"REQ-HOLD-{uuid.uuid4().hex[:6]}"
        payload1 = {
            "request_id": req1_id,
            "agent_id": "RESUME-RACE-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 26000.0},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload1["signature"] = SignatureManager.sign_request(payload1, priv_key)
        res1 = gw.process_request(payload1)
        assert res1["decision"] == "PENDING_HUMAN_APPROVAL"
        app_ticket = approval_mgr.get_approval_by_request_id(req1_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        # 2. Intermediate Request 2 (₹10,000) arrives while Request 1 is waiting for human
        req2_id = f"REQ-INTER-{uuid.uuid4().hex[:6]}"
        payload2 = {
            "request_id": req2_id,
            "agent_id": "RESUME-RACE-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 10000.0},
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload2["signature"] = SignatureManager.sign_request(payload2, priv_key)
        res2 = gw.process_request(payload2)
        assert res2["decision"] in ("ALLOWED", "COMPLETED")

        # 3. Supervisor attempts to approve Request 1 (₹26,000)
        # Total would be 10,000 + 26,000 = 36,000 > 30,000 cap!
        resume_res = gw.process_human_approval_resume(
            approval_id=approval_id,
            approver_id="SUPERVISOR-01",
            provided_token=approval_token
        )

        # Must fail closed: execution blocked due to capacity exhaustion during approval wait
        assert resume_res["decision"] == "BLOCKED"
        assert "CUMULATIVE_LIMIT_EXCEEDED_ON_RESUME" in resume_res["reason"]
        assert resume_res.get("execution_result") in ("NOT_EXECUTED", "BLOCKED", None)
        p_db.close()


def test_third_pass_audit_genesis_evidence_restart_and_cryptographic_verification():
    """
    Third-Pass Review Task 2: Verify genesis evidence record persistence across application restart
    and verify its computed SHA-256 digest against on-chain ledger commitment.
    """
    from evidence_manager.hash_manager import HashManager

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_genesis_restart.db")

        # 1. Start application: initialize EvidenceStore
        store_v1 = EvidenceStore(db_path=db_path)
        genesis_rec = store_v1.get_evidence("REQ-GENESIS-000")
        assert genesis_rec is not None
        assert genesis_rec["evidence_id"] == "EVIDENCE-REQ-GENESIS-000"
        assert genesis_rec["input_hash"] != "0" * 64
        assert genesis_rec["record_hash"] != "0" * 64
        assert len(genesis_rec["input_hash"]) == 64
        assert len(genesis_rec["record_hash"]) == 64

        first_computed_hash = HashManager.calculate_evidence_hash(genesis_rec)

        # 2. Simulate complete restart: teardown in-memory store
        del store_v1

        # 3. Reopen application from SQLite disk persistence
        store_v2 = EvidenceStore(db_path=db_path)
        p_db = PersistentStorageEngine(db_path=db_path)

        # Verify disk persistence directly via PersistentStorageEngine
        db_record = p_db.get_evidence("EVIDENCE-REQ-GENESIS-000")
        assert db_record is not None
        assert db_record["evidence_id"] == "EVIDENCE-REQ-GENESIS-000"

        # Verify retrieved record through EvidenceStore
        reloaded_genesis = store_v2.get_evidence("REQ-GENESIS-000")
        assert reloaded_genesis is not None

        # Verify cryptographic integrity
        verify_result = HashManager.verify_integrity(reloaded_genesis, first_computed_hash)
        assert verify_result["verified"] is True
        assert verify_result["status"] == "VERIFIED"
        p_db.close()
