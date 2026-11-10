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
import uuid

import yaml  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
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
    with open(config_path, encoding="utf-8") as f:
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
    with open(compose_path, encoding="utf-8") as f:
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
        now_utc = datetime.datetime.now(datetime.UTC)
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
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
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
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
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
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
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
    with open(crypto_path, encoding="utf-8") as f:
        crypto_cfg = yaml.safe_load(f)

    orderer_orgs = crypto_cfg["OrdererOrgs"][0]
    specs = [s["Hostname"] for s in orderer_orgs["Specs"]]
    assert "orderer" in specs
    assert "orderer2" in specs
    assert "orderer3" in specs

    # 2. docker-compose-fabric.yaml named volumes
    compose_path = os.path.join(os.path.dirname(__file__), "..", "fabric", "docker-compose-fabric.yaml")
    with open(compose_path, encoding="utf-8") as f:
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
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
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
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
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


def test_fourth_pass_audit_approval_resume_policy_rejection_releases_reservation():
    """
    Fourth-Pass Review Finding 1.a:
    Verify that if policy recheck fails in _atomic_validator during approval resume,
    the reserved cumulative capacity is immediately released to state REJECTED,
    preventing any dangling reservation leak.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_policy_recheck_release.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(
            agent_id="POLICY-RECHECK-AGENT",
            agent_name="Policy Recheck Agent",
            policy_id="POLICY-RECHECK-POL"
        )
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        policy = PolicyRecord(
            policy_id="POLICY-RECHECK-POL",
            agent_id="POLICY-RECHECK-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
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

        req_id = f"REQ-POL-REL-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "POLICY-RECHECK-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 25000.0},
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        # Modify policy to disallow TRANSFER_FUNDS before approval is resumed
        revised_policy = PolicyRecord(
            policy_id="POLICY-RECHECK-POL",
            agent_id="POLICY-RECHECK-AGENT",
            version="2.0",
            allowed_actions=["VIEW_BALANCE"],  # TRANSFER_FUNDS removed
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(revised_policy)

        # Resume approval
        resume_res = gw.process_human_approval_resume(
            approval_id=approval_id,
            approver_id="SUPERVISOR-01",
            provided_token=approval_token
        )

        # Must fail closed: execution blocked due to policy change
        assert resume_res["decision"] == "BLOCKED"
        assert "POLICY_RECHECK_FAILED" in resume_res["reason"]

        # Intent must have been released from reservation and transitioned to REJECTED
        intent = p_db.get_intent(req_id)
        assert intent is not None
        assert intent["state"] == "REJECTED"
        assert "POLICY_RECHECK_FAILED" in str(intent.get("outcome") or intent.get("outcome_json") or "")
        p_db.close()


def test_fourth_pass_audit_approval_resume_delegation_rejection_releases_reservation():
    """
    Fourth-Pass Review Finding 1.b:
    Verify that if delegation recheck fails in _atomic_validator during approval resume,
    the reserved cumulative capacity is immediately released to state REJECTED.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_delegation_recheck_release.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        issuer_reg = registry.register_agent(agent_id="FIN-SUPERVISOR-DEL", agent_name="Supervisor", policy_id="SUPERVISOR-POL")
        delegate_reg = registry.register_agent(agent_id="FIN-WORKER-DEL", agent_name="Worker", policy_id="WORKER-POL")
        delegate_priv = delegate_reg["private_key"]

        from identity_manager.delegation import DelegationTokenManager
        from policy_engine.policy_models import PolicyRecord, WorkingHours

        del_token = DelegationTokenManager.create_delegated_token(
            issuer_agent_id="FIN-SUPERVISOR-DEL",
            delegate_agent_id="FIN-WORKER-DEL",
            allowed_actions=["TRANSFER_FUNDS"],
            maximum_amount=50000.0,
            issuer_private_key=issuer_reg["private_key"],
            ttl_seconds=3600
        )

        loader = PolicyLoader()
        worker_pol = PolicyRecord(
            policy_id="WORKER-POL",
            agent_id="FIN-WORKER-DEL",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(worker_pol)

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

        req_id = f"REQ-DEL-REL-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "FIN-WORKER-DEL",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 28000.0},
            "delegation_token": del_token,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, delegate_priv)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        # Revoke the delegation token while request is awaiting approval
        DelegationTokenManager.revoke_token(del_token.get("token_id"))

        # Resume approval
        resume_res = gw.process_human_approval_resume(
            approval_id=approval_id,
            approver_id="SUPERVISOR-01",
            provided_token=approval_token
        )

        # Must fail closed: execution blocked due to revoked delegation token
        assert resume_res["decision"] == "BLOCKED"
        assert "DELEGATION_RECHECK_FAILED" in resume_res["reason"]

        # Intent must have been released from reservation and transitioned to REJECTED
        intent = p_db.get_intent(req_id)
        assert intent is not None
        assert intent["state"] == "REJECTED"
        assert "DELEGATION_RECHECK_FAILED" in str(intent.get("outcome") or intent.get("outcome_json") or "")
        p_db.close()


def test_fourth_pass_audit_approval_resume_db_failure_enqueues_reconciliation():
    """
    Fourth-Pass Review Finding 1.c:
    Verify that if the persistent database fails during post-execution intent state transition,
    the gateway logs a CRITICAL error, enqueues an emergency outbox record with
    status RECONCILIATION_REQUIRED, and returns reconciliation_status in outcome.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_db_failure_reconciliation.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(agent_id="DB-FAIL-AGENT", agent_name="DB Fail Agent", policy_id="DB-FAIL-POL")
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        pol = PolicyRecord(
            policy_id="DB-FAIL-POL",
            agent_id="DB-FAIL-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(pol)

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

        req_id = f"REQ-DB-FAIL-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "DB-FAIL-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 25000.0},
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        # Monkeypatch update_intent_state on p_db to simulate SQLite lock error
        real_update = p_db.update_intent_state

        def failing_update_intent_state(request_id, state, **kwargs):
            if state == "EXECUTED_PENDING_LEDGER":
                raise sqlite3.OperationalError("database is locked: simulated disk contention")
            return real_update(request_id, state, **kwargs)

        p_db.update_intent_state = failing_update_intent_state

        # Resume approval
        resume_res = gw.process_human_approval_resume(
            approval_id=approval_id,
            approver_id="SUPERVISOR-01",
            provided_token=approval_token
        )

        # Downstream execution succeeded, but reconciliation status must be reported
        assert resume_res["decision"] in ("ALLOWED", "COMPLETED", "ALLOWED_AFTER_APPROVAL")
        assert resume_res.get("reconciliation_status") is not None
        assert "INTENT_STATE_UPDATE_FAILED" in resume_res["reconciliation_status"]

        # Verify emergency outbox entry was written with RECONCILIATION_REQUIRED
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT payload_json FROM reconciliation_queue WHERE request_id = ? AND status = 'RECONCILIATION_REQUIRED'", (req_id,))
            rows = cur.fetchall()
            assert len(rows) >= 1
            payload_data = rows[0][0]
            assert "database is locked" in payload_data
        p_db.close()


def test_fourth_pass_audit_approval_resume_concurrent_duplicate_attempts():
    """
    Fourth-Pass Review Finding 1.d:
    Verify that concurrent approval resume requests for the same ticket execute atomically:
    exactly one thread executes the protected action, while duplicate attempts fail closed
    with REQUEST_ALREADY_APPROVED.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_concurrent_approval.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(agent_id="CONCUR-AGENT", agent_name="Concur Agent", policy_id="CONCUR-POL")
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        pol = PolicyRecord(
            policy_id="CONCUR-POL",
            agent_id="CONCUR-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(pol)

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

        req_id = f"REQ-CONCUR-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "CONCUR-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 25000.0},
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        results = []
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait()
            r = gw.process_human_approval_resume(
                approval_id=approval_id,
                approver_id="SUPERVISOR-01",
                provided_token=approval_token
            )
            results.append(r)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(results) == 2
        successes = [r for r in results if r.get("decision") in ("ALLOWED", "COMPLETED", "ALLOWED_AFTER_APPROVAL")]
        rejections = [r for r in results if r.get("decision") == "BLOCKED"]

        assert len(successes) == 1, "Exactly one thread must succeed in executing approval resume"
        assert len(rejections) == 1, "Duplicate resume must be rejected"
        assert "REQUEST_ALREADY_APPROVED" in rejections[0]["reason"]
        p_db.close()


def test_fourth_pass_audit_genesis_evidence_tamper_detection():
    """
    Fourth-Pass Review Finding 2:
    Verify that altering genesis evidence record stored in SQLite causes
    cryptographic verification to fail (TAMPERING_DETECTED), and strict startup
    fails closed.
    """
    from evidence_manager.evidence_store import EvidencePersistenceError
    from evidence_manager.hash_manager import HashManager

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_genesis_tamper.db")

        # 1. Initialize EvidenceStore normally (creates anchored genesis record)
        store = EvidenceStore(db_path=db_path, fail_closed=True)
        genesis = store.get_evidence("REQ-GENESIS-000")
        assert genesis is not None
        original_hash = HashManager.calculate_evidence_hash(genesis)

        # Verify initial cryptographic integrity
        initial_check = HashManager.verify_integrity(genesis, original_hash)
        assert initial_check["verified"] is True
        assert initial_check["status"] == "VERIFIED"

        # 2. Tamper directly with the SQLite database content
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE evidence_store
                SET evidence_json = '{"evidence_id": "EVIDENCE-REQ-GENESIS-000", "tampered_field": "unauthorized_modification"}'
                WHERE evidence_id = 'EVIDENCE-REQ-GENESIS-000'
            """)
            conn.commit()

        # 3. Reload from DB and verify HashManager detects tampering
        p_db = PersistentStorageEngine(db_path=db_path)
        tampered_rec = p_db.get_evidence("EVIDENCE-REQ-GENESIS-000")
        p_db.close()

        tampered_clean = {k: v for k, v in tampered_rec.items() if k != "_stored_hash"}
        tamper_check = HashManager.verify_integrity(tampered_clean, original_hash)
        assert tamper_check["verified"] is False
        assert tamper_check["status"] == "TAMPERING_DETECTED"

        # 4. Strict mode boot must fail closed with EvidencePersistenceError
        import pytest
        with pytest.raises(EvidencePersistenceError) as exc_info:
            EvidenceStore(db_path=db_path, fail_closed=True)
        assert "CORRUPTED_OR_TAMPERED_GENESIS_EVIDENCE" in str(exc_info.value) or "INDEPENDENT_TRUST_ANCHOR_VERIFICATION_FAILED" in str(exc_info.value)


def test_fifth_pass_audit_reservation_release_failure_surfaces_in_outcome():
    """
    Fifth-Pass Review Finding 1.a:
    Verify that if release_reservation fails (e.g. SQLite database locked/error)
    during approval resume validation failure, the error is NOT silently swallowed:
    it is recorded, logged, and surfaced in reconciliation_status and reason.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_release_failure_surfaced.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(agent_id="REL-FAIL-AGENT", agent_name="Release Fail Agent", policy_id="REL-FAIL-POL")
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        pol = PolicyRecord(
            policy_id="REL-FAIL-POL",
            agent_id="REL-FAIL-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(pol)

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

        req_id = f"REQ-REL-FAIL-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "REL-FAIL-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 25000.0},
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        # Monkeypatch release_reservation to simulate database lock
        def failing_release_reservation(request_id, new_state="REJECTED", reason=None):
            raise sqlite3.OperationalError("database is locked: simulated disk contention on release")

        p_db.release_reservation = failing_release_reservation

        # Monkeypatch approve_request validator callback to simulate failure after reservation
        def failing_ticket_approval(app_id, app_user, provided_token=None, validator_fn=None):
            # Run validator to simulate holding reservation
            if validator_fn:
                ok, v_msg = validator_fn(app_ticket)
            # Ticket consumption fails
            return False, None, "TICKET_PERSISTENCE_MUTEX_FAILED"

        approval_mgr.approve_request = failing_ticket_approval

        resume_res = gw.process_human_approval_resume(
            approval_id=approval_id,
            approver_id="SUPERVISOR-01",
            provided_token=approval_token
        )

        # Must fail closed: blocked
        assert resume_res["decision"] == "BLOCKED"
        # Release failure must NOT be swallowed: must be surfaced in reconciliation_status and reason
        assert resume_res.get("reconciliation_status") is not None
        assert "RESERVATION_RELEASE_FAILED" in resume_res["reconciliation_status"]
        assert "RESERVATION_RELEASE_FAILED" in resume_res["reason"]
        p_db.close()


def test_fifth_pass_audit_reconciliation_queue_failure_propagates_critical_warning():
    """
    Fifth-Pass Review Finding 1.b:
    Verify that if persistent DB intent state update fails AND saving to reconciliation_queue
    also fails, the failure is NOT silently ignored: a critical warning is reported.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_crit_recon_failure.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(agent_id="CRIT-FAIL-AGENT", agent_name="Crit Fail Agent", policy_id="CRIT-FAIL-POL")
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        pol = PolicyRecord(
            policy_id="CRIT-FAIL-POL",
            agent_id="CRIT-FAIL-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(pol)

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

        req_id = f"REQ-CRIT-FAIL-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "CRIT-FAIL-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 25000.0},
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None
        approval_id = app_ticket["approval_id"]
        approval_token = app_ticket["approval_token"]

        # 1. Fail update_intent_state
        real_update = p_db.update_intent_state

        def failing_update(request_id, state, **kwargs):
            if state == "EXECUTED_PENDING_LEDGER":
                raise sqlite3.OperationalError("database is locked: intent update failed")
            return real_update(request_id, state, **kwargs)

        p_db.update_intent_state = failing_update

        # 2. Fail save_retry_record as well (simulating complete I/O disk failure)
        def failing_save_retry(*args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error: reconciliation queue unwritable")

        p_db.save_retry_record = failing_save_retry

        resume_res = gw.process_human_approval_resume(
            approval_id=approval_id,
            approver_id="SUPERVISOR-01",
            provided_token=approval_token
        )

        # Must report critical reconciliation failure
        assert resume_res.get("reconciliation_status") is not None
        assert "CRITICAL_RECONCILIATION_FAILURE" in resume_res["reconciliation_status"]
        p_db.close()


def test_fifth_pass_audit_independent_trust_anchor_detects_simultaneous_tampering():
    """
    Fifth-Pass Review Finding 2:
    Verify that if an attacker modifies BOTH evidence_json AND recalculates evidence_hash
    inside SQLite, the independent external trust anchor detects the forgery
    and strict startup fails closed with INDEPENDENT_TRUST_ANCHOR_VERIFICATION_FAILED.
    """
    import json

    from evidence_manager.evidence_store import EvidencePersistenceError
    from evidence_manager.genesis_trust_anchor import (
        get_genesis_trust_anchor,
        verify_against_trust_anchor,
    )
    from evidence_manager.hash_manager import HashManager

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_simultaneous_tampering.db")

        # 1. Initialize EvidenceStore normally (creates anchored genesis record)
        store = EvidenceStore(db_path=db_path, fail_closed=True)
        genesis = store.get_evidence("REQ-GENESIS-000")
        assert genesis is not None
        anchor = get_genesis_trust_anchor()

        # Verify initial trust anchor verification passes
        trusted_check = verify_against_trust_anchor(genesis, anchor["expected_full_digest"])
        assert trusted_check["verified"] is True
        assert trusted_check["status"] == "VERIFIED"
        del store

        # 2. Malicious Attacker: Modify BOTH evidence_json AND recompute evidence_hash in SQLite
        forged_rec = {
            "evidence_schema_version": "2.0",
            "evidence_id": "EVIDENCE-REQ-GENESIS-000",
            "request_id": "REQ-GENESIS-000",
            "agent_id": "ROGUE-ATTACKER",
            "forged_payload": "unauthorized_forged_evidence_record",
            "record_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ledger_anchor_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }
        forged_json = json.dumps(forged_rec)
        forged_stored_hash = HashManager.calculate_evidence_hash(forged_rec)

        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE evidence_store
                SET evidence_json = ?, evidence_hash = ?
                WHERE evidence_id = 'EVIDENCE-REQ-GENESIS-000'
            """, (forged_json, forged_stored_hash))
            conn.commit()

        # 3. Verify that verify_against_trust_anchor detects the forgery
        p_db = PersistentStorageEngine(db_path=db_path)
        tampered_rec = p_db.get_evidence("EVIDENCE-REQ-GENESIS-000")
        p_db.close()

        tampered_clean = {k: v for k, v in tampered_rec.items() if k != "_stored_hash"}
        anchor_check = verify_against_trust_anchor(tampered_clean, forged_stored_hash)
        assert anchor_check["verified"] is False
        assert anchor_check["status"] == "TAMPERING_DETECTED"
        assert anchor_check["anchor_match"] is False or anchor_check["rec_hash_match"] is False

        # 4. Strict mode startup must fail closed with INDEPENDENT_TRUST_ANCHOR_VERIFICATION_FAILED
        import pytest
        with pytest.raises(EvidencePersistenceError) as exc_info:
            EvidenceStore(db_path=db_path, fail_closed=True)
        assert "INDEPENDENT_TRUST_ANCHOR_VERIFICATION_FAILED" in str(exc_info.value)


def test_fifth_pass_audit_approval_revalidation_order_protects_capacity():
    """
    Fifth-Pass Review Priority 4:
    Verify that all non-reservation checks (identity, cert, risk, policy, delegation)
    are performed BEFORE atomic reservation is requested.
    If a policy or delegation rule is violated, NO reservation is requested or held.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_revalidation_ordering.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))
        approval_mgr = HumanApprovalManager()

        reg = registry.register_agent(agent_id="ORDER-AGENT", agent_name="Order Test Agent", policy_id="ORDER-POL")
        priv_key = reg["private_key"]

        from policy_engine.policy_models import PolicyRecord, WorkingHours
        loader = PolicyLoader()
        pol = PolicyRecord(
            policy_id="ORDER-POL",
            agent_id="ORDER-AGENT",
            version="1.0",
            allowed_actions=["TRANSFER_FUNDS"],
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(pol)

        # Track whether revalidate_and_reserve_approved_intent is called
        reservation_calls = []
        real_reserve = p_db.revalidate_and_reserve_approved_intent

        def tracking_reserve(*args, **kwargs):
            reservation_calls.append(kwargs)
            return real_reserve(*args, **kwargs)

        p_db.revalidate_and_reserve_approved_intent = tracking_reserve

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

        req_id = f"REQ-ORDER-{uuid.uuid4().hex[:6]}"
        payload = {
            "request_id": req_id,
            "agent_id": "ORDER-AGENT",
            "action": "TRANSFER_FUNDS",
            "resource": "SUPPLIER-101",
            "parameters": {"amount": 25000.0},
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "nonce": uuid.uuid4().hex,
            "idempotency_key": uuid.uuid4().hex
        }
        payload["signature"] = SignatureManager.sign_request(payload, priv_key)
        res = gw.process_request(payload)
        assert res["decision"] == "PENDING_HUMAN_APPROVAL"

        app_ticket = approval_mgr.get_approval_by_request_id(req_id)
        assert app_ticket is not None

        # Revise policy to block TRANSFER_FUNDS BEFORE resume
        revised_pol = PolicyRecord(
            policy_id="ORDER-POL",
            agent_id="ORDER-AGENT",
            version="2.0",
            allowed_actions=["VIEW_BALANCE"],  # TRANSFER_FUNDS removed
            allowed_resource="*",
            maximum_amount=50000.0,
            cumulative_maximum_amount=50000.0,
            max_transactions_per_window=10,
            velocity_window_seconds=86400,
            human_approval_above=20000.0,
            working_hours=WorkingHours(start="00:00", end="23:59")
        )
        loader.save_policy(revised_pol)

        # Resume approval
        resume_res = gw.process_human_approval_resume(
            approval_id=app_ticket["approval_id"],
            approver_id="SUPERVISOR-01",
            provided_token=app_ticket["approval_token"]
        )

        # Recheck failed at Policy step
        assert resume_res["decision"] == "BLOCKED"
        assert "POLICY_RECHECK_FAILED" in resume_res["reason"]

        # Invariant: Revalidation ordering ensures atomic reservation was NEVER called
        assert len(reservation_calls) == 0, "Reservation must NOT be called if policy check fails"
        p_db.close()


# -----------------------------------------------------------------------------
# Sixth-Pass Security Audit Hardening Verification Tests
# -----------------------------------------------------------------------------
def test_sixth_pass_production_mode_missing_persistent_db_blocks_approval_resume():
    """
    Verify Finding 1 (Sixth Pass):
    In production mode (AGENTTRUST_PRODUCTION=true), an approval resume attempt
    where persistent_db is None or lacks revalidate_and_reserve_approved_intent
    MUST fail closed with ATOMIC_RESERVATION_UNAVAILABLE before consuming the ticket.
    """
    cert_mgr = CertificateManager()
    registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore())
    approval_mgr = HumanApprovalManager()
    loader = PolicyLoader()
    evaluator = PolicyEvaluator(loader)

    reg = registry.register_agent(agent_id="PROD-TEST-AGENT", agent_name="Prod Agent", policy_id="PROD-POL")
    priv_key = reg["private_key"]

    from policy_engine.policy_models import PolicyRecord, WorkingHours
    pol = PolicyRecord(
        policy_id="PROD-POL",
        agent_id="PROD-TEST-AGENT",
        version="1.0",
        allowed_actions=["TRANSFER_FUNDS"],
        allowed_resource="*",
        maximum_amount=50000.0,
        cumulative_maximum_amount=50000.0,
        max_transactions_per_window=10,
        velocity_window_seconds=86400,
        human_approval_above=20000.0,
        working_hours=WorkingHours(start="00:00", end="23:59")
    )
    loader.save_policy(pol)

    # Instantiate gateway with persistent_db=None
    gw = ActionGateway(
        registry=registry,
        cert_manager=cert_mgr,
        policy_evaluator=evaluator,
        replay_tracker=RequestTracker(300),
        finance_api=ProtectedFinanceAPI(),
        approval_manager=approval_mgr,
        evidence_store=EvidenceStore(),
        fabric_client=FabricClient(),
        persistent_db=None
    )

    req_id = f"REQ-PROD-RESUME-{uuid.uuid4().hex[:6]}"
    payload = {
        "request_id": req_id,
        "agent_id": "PROD-TEST-AGENT",
        "action": "TRANSFER_FUNDS",
        "resource": "SUPPLIER-101",
        "parameters": {"amount": 25000.0},
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "nonce": uuid.uuid4().hex,
        "idempotency_key": uuid.uuid4().hex
    }
    payload["signature"] = SignatureManager.sign_request(payload, priv_key)
    res = gw.process_request(payload)
    assert res["decision"] == "PENDING_HUMAN_APPROVAL"

    app_ticket = approval_mgr.get_approval_by_request_id(req_id)
    assert app_ticket is not None

    orig_prod = os.environ.get("AGENTTRUST_PRODUCTION")
    os.environ["AGENTTRUST_PRODUCTION"] = "true"
    try:
        resume_res = gw.process_human_approval_resume(
            approval_id=app_ticket["approval_id"],
            approver_id="SUPERVISOR-01",
            provided_token=app_ticket["approval_token"]
        )
        assert resume_res["decision"] == "BLOCKED"
        assert "ATOMIC_RESERVATION_UNAVAILABLE" in resume_res["reason"]

        # Ensure approval ticket remains unconsumed because validation failed closed
        ticket_after = approval_mgr.get_approval_by_id(app_ticket["approval_id"])
        assert ticket_after["status"] == "PENDING"
    finally:
        if orig_prod is not None:
            os.environ["AGENTTRUST_PRODUCTION"] = orig_prod
        else:
            os.environ.pop("AGENTTRUST_PRODUCTION", None)


def test_sixth_pass_reconciliation_status_preserves_intent_state():
    """
    Verify Finding 2 (Sixth Pass):
    When reconciliation_status is active, _finalize_gateway_outcome() must NEVER
    attempt normal intent finalization (update_intent_state to COMMITTED) or
    delete retry outbox records. The unconfirmed state must be preserved for worker reconciliation.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = os.path.join(tmp, "test_reconciliation_guard.db")
        p_db = PersistentStorageEngine(db_path=db_path)
        cert_mgr = CertificateManager(db_path=db_path)
        registry = AgentRegistry(cert_manager=cert_mgr, store=IdentityStore(db_path=db_path))

        gw = ActionGateway(
            registry=registry,
            cert_manager=cert_mgr,
            policy_evaluator=PolicyEvaluator(PolicyLoader()),
            replay_tracker=RequestTracker(300),
            finance_api=ProtectedFinanceAPI(),
            approval_manager=HumanApprovalManager(),
            evidence_store=EvidenceStore(db_path=db_path),
            fabric_client=FabricClient(),
            persistent_db=p_db
        )

        req_id = f"REQ-RECON-{uuid.uuid4().hex[:6]}"
        idemp_key = f"IDEMP-{uuid.uuid4().hex[:6]}"
        event_id = f"EVENT-RECON-{uuid.uuid4().hex[:8]}"

        # Reserve and record an intent
        p_db.check_and_reserve_cumulative_volume(
            agent_id="FINANCE-AGENT-001",
            action="TRANSFER_FUNDS",
            amount=1000.0,
            window_seconds=86400,
            max_cumulative_limit=50000.0,
            request_id=req_id,
            idempotency_key=idemp_key
        )

        # Save an emergency retry record in persistent_db
        p_db.save_retry_record(
            event_id=event_id,
            request_id=req_id,
            payload={
                "request_id": req_id,
                "status": "RECONCILIATION_REQUIRED",
                "actual_execution": "SUCCESS",
                "error": "simulated lock"
            },
            error_msg="INTENT_STATE_UPDATE_FAILED: simulated lock",
            status="RECONCILIATION_REQUIRED"
        )

        # Call _finalize_gateway_outcome with active reconciliation_status
        outcome = gw._finalize_gateway_outcome(
            request_id=req_id,
            agent_id="FINANCE-AGENT-001",
            action="TRANSFER_FUNDS",
            resource="TREASURY",
            parameters={"amount": 1000.0},
            decision="ALLOWED",
            reason="POLICY_PASSED",
            policy_id="FIN-POL-001",
            policy_version="1.0",
            agent_version="1.0",
            api_result="EXECUTED",
            event_id=event_id,
            reconciliation_status="INTENT_STATE_UPDATE_FAILED: simulated lock"
        )

        # 1. Output must reflect reconciliation_status
        assert outcome.get("reconciliation_status") == "INTENT_STATE_UPDATE_FAILED: simulated lock"

        # 2. Intent must NOT have transitioned to COMMITTED
        intent = p_db.get_intent(req_id)
        assert intent is not None
        assert intent["state"] == "AUTHORIZED_PENDING_EXECUTION", f"Intent state should remain uncommitted, got {intent['state']}"

        # 3. Outbox retry record must NOT have been deleted
        retry_rec = p_db.get_retry_record(event_id)
        assert retry_rec is not None, "Retry outbox record must be preserved for worker reconciliation"
        assert retry_rec["status"] == "RECONCILIATION_REQUIRED"

        p_db.close()


def test_sixth_pass_signed_genesis_manifest_tamper_detection():
    """
    Verify Finding 3 (Sixth Pass):
    Enforces cryptographic RSA PSS signature verification over config/trusted_genesis_anchor.json
    against the trusted Root Authority public key.
    Tampering with the hash, metadata, or digital signature MUST cause
    verify_manifest_authenticity() to fail closed with MANIFEST_SIGNATURE_INVALID or
    MANIFEST_SIGNATURE_MISSING, and verify_against_trust_anchor() to return
    status="MANIFEST_AUTHENTICATION_FAILED".
    """
    import json

    from evidence_manager.genesis_trust_anchor import (
        CANONICAL_FABRIC_BLOCK0_HASH,
        get_genesis_trust_anchor,
        verify_against_trust_anchor,
        verify_manifest_authenticity,
    )

    # 1. Authentic manifest must verify successfully
    manifest = get_genesis_trust_anchor()
    assert manifest.get("_manifest_authenticated") is True
    assert manifest.get("ledger_anchor_hash") == CANONICAL_FABRIC_BLOCK0_HASH

    auth_ok, auth_reason = verify_manifest_authenticity(manifest)
    assert auth_ok is True
    assert auth_reason == "AUTHENTIC"

    # 2. Tampered payload (altered ledger_anchor_hash) must fail signature verification
    tampered_payload = dict(manifest)
    tampered_payload["ledger_anchor_hash"] = "0" * 64
    tampered_payload.pop("_manifest_authenticated", None)
    tampered_payload.pop("_authentication_error", None)

    ok, reason = verify_manifest_authenticity(tampered_payload)
    assert ok is False
    assert "MANIFEST_SIGNATURE_INVALID" in reason

    # 3. Tampered signature must fail signature verification
    tampered_sig = dict(manifest)
    tampered_sig.pop("_manifest_authenticated", None)
    tampered_sig.pop("_authentication_error", None)
    tampered_sig["signature"] = "bad" + tampered_sig["signature"][3:]

    ok2, reason2 = verify_manifest_authenticity(tampered_sig)
    assert ok2 is False
    assert "MANIFEST_SIGNATURE_INVALID" in reason2

    # 4. Missing signature must fail signature verification
    no_sig = dict(manifest)
    no_sig.pop("_manifest_authenticated", None)
    no_sig.pop("_authentication_error", None)
    no_sig.pop("signature", None)

    ok3, reason3 = verify_manifest_authenticity(no_sig)
    assert ok3 is False
    assert "MANIFEST_SIGNATURE_MISSING" in reason3

    # 5. Injection of tampered manifest via environment variable must fail closed in verify_against_trust_anchor
    orig_env = os.environ.get("AGENTTRUST_GENESIS_TRUST_ANCHOR")
    os.environ["AGENTTRUST_GENESIS_TRUST_ANCHOR"] = json.dumps(tampered_payload)
    try:
        sample_record = {
            "evidence_id": "EVIDENCE-REQ-GENESIS-000",
            "request_id": "REQ-GENESIS-000",
            "ledger_anchor_hash": CANONICAL_FABRIC_BLOCK0_HASH,
            "record_hash": manifest.get("expected_record_hash", "")
        }
        res = verify_against_trust_anchor(sample_record, manifest.get("expected_full_digest", ""))
        assert res["verified"] is False
        assert res["status"] == "MANIFEST_AUTHENTICATION_FAILED"
        assert "MANIFEST_SIGNATURE_INVALID" in res["reason"]
    finally:
        if orig_env is not None:
            os.environ["AGENTTRUST_GENESIS_TRUST_ANCHOR"] = orig_env
        else:
            os.environ.pop("AGENTTRUST_GENESIS_TRUST_ANCHOR", None)



