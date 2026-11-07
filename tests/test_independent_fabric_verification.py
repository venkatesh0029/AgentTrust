"""
Work Package #6: Independent Hyperledger Fabric Verification Test Suite.
Validates two-path commit verification (Gateway Path A vs Independent Peer Path B):
1. Genuine Fabric transaction is independently verified (VERIFIED_COMMITTED).
2. Fake transaction ID is rejected (REJECTED).
3. Fabric block number mismatch is detected (REJECTED).
4. Invalid transaction validation code is rejected (e.g. MVCC_READ_CONFLICT -> REJECTED).
5. Modified block data fails cryptographic integrity verification (REJECTED).
6. Gateway reports success but peer has no committed transaction (REJECTED).
7. Peer temporarily unavailable results in pending verification (PENDING_VERIFICATION).
8. Duplicate submissions resolve using the same event ID idempotently.
9. Multi-peer verification returns consistent transaction evidence.
10. Multi-peer consensus divergence is detected and rejected (REJECTED).
"""

import os
import tempfile

import pytest

from fabric.commit_verifier import (
    CommitVerificationEngine,
    SimulatorPeerClient,
    TxValidationCode,
    VerificationResult,
    VerificationStatus,
)
from fabric.fabric_client import FabricClient
from fabric.ledger_service import FabricLedgerService


@pytest.fixture
def temp_db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def fabric_env(temp_db_path):
    os.environ["FABRIC_GATEWAY_MODE"] = "simulator"
    client = FabricClient(db_path=temp_db_path)
    return client


def test_01_genuine_fabric_transaction_independently_verified(fabric_env):
    """
    Scenario 1: Genuine Fabric transaction submitted through Gateway (Path A)
    and independently verified against peer nodes (Path B).
    Must result in VERIFIED_COMMITTED with TxValidationCode.VALID.
    """
    client = fabric_env
    event_id = "evt-gen-001"

    result = client.record_action_event_verified(
        event_id=event_id,
        request_id="req-gen-001",
        agent_id="agent-wp6-verifier",
        action="TRANSFER_FUNDS",
        resource="account://corp/treasury",
        decision="PERMIT",
        reason="Valid dual-authorization signatures verified",
        policy_id="pol-fin-99",
        policy_version="1.0.0",
        evidence_reference="ev://fin/audit/001",
        evidence_hash="sha256-verified-hash-001"
    )

    assert result["verification_status"] == VerificationStatus.VERIFIED_COMMITTED.value
    assert result["tx_id"] == f"TX-{event_id}"
    assert result["block_number"] >= 1
    assert result["validation_code"] == TxValidationCode.VALID.value

    verification: VerificationResult = result["verification"]
    assert verification.is_verified is True
    assert len(verification.peer_evidences) == 2
    for peer_ev in verification.peer_evidences:
        assert peer_ev.block_integrity_valid is True
        assert peer_ev.validation_code == "VALID"
        assert peer_ev.payload["action"] == "TRANSFER_FUNDS"


def test_02_fake_transaction_id_rejected(fabric_env):
    """
    Scenario 2: Gateway claims success with a fabricated transaction ID that
    does not exist in peer storage. Must be REJECTED.
    """
    client = fabric_env

    fake_gateway_response = {
        "status": "COMMITTED",
        "tx_id": "TX-FABRICATED-NONEXISTENT-999",
        "block_index": 1,
        "block_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "mode": "simulator"
    }

    verification = client.verify_committed_transaction(fake_gateway_response)

    assert verification.status == VerificationStatus.REJECTED
    assert verification.is_verified is False
    assert any("TX_NOT_FOUND_ON_PEER" in reason for reason in verification.failure_reasons)


def test_03_fabric_block_number_mismatch_detected(fabric_env):
    """
    Scenario 3: Gateway reports block 99, but peer ledger committed the transaction
    in block 1. Must detect block mismatch and REJECT.
    """
    client = fabric_env
    event_id = "evt-mismatch-block-003"

    gateway_res = client.record_action_event(
        event_id=event_id,
        request_id="req-mismatch-003",
        agent_id="agent-wp6-verifier",
        action="ACCESS_SECRETS",
        resource="vault://keys/master",
        decision="PERMIT",
        reason="Security approved",
        policy_id="pol-sec-01",
        policy_version="1.0.0",
        evidence_reference="ev://sec/003",
        evidence_hash="sha256-hash-003"
    )

    tampered_gateway_res = dict(gateway_res)
    tampered_gateway_res["block_index"] = 99  # Fabricated block number

    verification = client.verify_committed_transaction(tampered_gateway_res)

    assert verification.status == VerificationStatus.REJECTED
    assert any("BLOCK_NUMBER_MISMATCH" in r for r in verification.failure_reasons)


def test_04_invalid_transaction_validation_code_rejected(fabric_env):
    """
    Scenario 4: Transaction was ordered into a block, but peer validation marked
    it invalid (e.g. MVCC_READ_CONFLICT or BAD_RWSET).
    Gateway returning HTTP 200 / COMMITTED must NOT cause false acceptance;
    CommitVerificationEngine must REJECT based on the validation code.
    """
    client = fabric_env
    event_id = "evt-mvcc-conflict-004"

    gateway_res = client.record_action_event(
        event_id=event_id,
        request_id="req-mvcc-004",
        agent_id="agent-wp6-verifier",
        action="UPDATE_LEDGER",
        resource="db://accounts/101",
        decision="PERMIT",
        reason="Concurrent update",
        policy_id="pol-cc-01",
        policy_version="1.0.0",
        evidence_reference="ev://cc/004",
        evidence_hash="sha256-hash-004"
    )

    tx_id = gateway_res["tx_id"]

    # Simulate Fabric Peer MVCC conflict validation failure
    client.ledger_service.mark_transaction_validation_code(
        tx_id=tx_id,
        code=TxValidationCode.MVCC_READ_CONFLICT.value
    )

    # Path A says COMMITTED, but Path B discovers MVCC_READ_CONFLICT
    verification = client.verify_committed_transaction(gateway_res)

    assert verification.status == VerificationStatus.REJECTED
    assert any("INVALID_TRANSACTION_VALIDATION_CODE" in r for r in verification.failure_reasons)
    assert any("MVCC_READ_CONFLICT" in r for r in verification.failure_reasons)


def test_05_modified_block_data_fails_integrity_verification(fabric_env):
    """
    Scenario 5: An attacker or corrupt storage modifies transaction data in a block
    (e.g. flips decision from DENY to PERMIT).
    Cryptographic recalculation of data_hash and block_hash must detect tampering and REJECT.
    """
    client = fabric_env
    event_id = "evt-tamper-005"

    gateway_res = client.record_action_event(
        event_id=event_id,
        request_id="req-tamper-005",
        agent_id="agent-wp6-verifier",
        action="DELETE_DATABASE",
        resource="db://prod/users",
        decision="DENY",
        reason="Restricted operation",
        policy_id="pol-safe-01",
        policy_version="1.0.0",
        evidence_reference="ev://safe/005",
        evidence_hash="sha256-hash-005"
    )

    block_num = gateway_res["block_index"]

    # Attacker alters payload inside block from DENY to PERMIT
    tampered = client.ledger_service.tamper_block_payload(block_num, "decision", "PERMIT")
    assert tampered is True

    verification = client.verify_committed_transaction(gateway_res)

    assert verification.status == VerificationStatus.REJECTED
    assert any("BLOCK_INTEGRITY_COMPROMISED" in r for r in verification.failure_reasons)


def test_06_gateway_reports_success_but_peer_has_no_committed_transaction():
    """
    Scenario 6: Untrusted/compromised Gateway reports HTTP 200 success, but
    isolated peer ledger has no record of the transaction.
    Must detect bridge hallucination and REJECT.
    """
    ledger = FabricLedgerService()
    peer_client = SimulatorPeerClient("peer0.org1.agenttrust.com", ledger)
    verifier = CommitVerificationEngine([peer_client])

    hallucinated_gateway_response = {
        "status": "COMMITTED",
        "tx_id": "TX-HALLUCINATED-BRIDGE-12345",
        "block_index": 5,
        "block_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "mode": "live"
    }

    verification = verifier.verify_transaction(hallucinated_gateway_response)

    assert verification.status == VerificationStatus.REJECTED
    assert any("TX_NOT_FOUND_ON_PEER" in r for r in verification.failure_reasons)


def test_07_peer_temporarily_unavailable_results_in_pending_verification(fabric_env):
    """
    Scenario 7: Peer nodes are unreachable (network partition, timeout).
    Must result in PENDING_VERIFICATION, NOT false success and NOT permanent rejection.
    """
    client = fabric_env
    event_id = "evt-partition-007"

    gateway_res = client.record_action_event(
        event_id=event_id,
        request_id="req-partition-007",
        agent_id="agent-wp6-verifier",
        action="TRANSFER_FUNDS",
        resource="account://corp/ops",
        decision="PERMIT",
        reason="Normal transfer",
        policy_id="pol-fin-01",
        policy_version="1.0.0",
        evidence_reference="ev://fin/007",
        evidence_hash="sha256-hash-007"
    )

    # Simulate network partition on all independent peers
    for p in client.peer_clients:
        if isinstance(p, SimulatorPeerClient):
            p.simulate_partition = True

    verification = client.verify_committed_transaction(gateway_res)

    assert verification.status == VerificationStatus.PENDING_VERIFICATION
    assert verification.is_verified is False
    assert any("PEER_TEMPORARILY_UNAVAILABLE" in r for r in verification.failure_reasons)

    # Once partition resolves, verification succeeds
    for p in client.peer_clients:
        if isinstance(p, SimulatorPeerClient):
            p.simulate_partition = False

    resolved_verification = client.verify_committed_transaction(gateway_res)
    assert resolved_verification.status == VerificationStatus.VERIFIED_COMMITTED
    assert resolved_verification.is_verified is True


def test_08_duplicate_submissions_resolve_using_same_event_id(fabric_env):
    """
    Scenario 8: Duplicate event submissions resolve idempotently to the existing
    committed transaction and verify cleanly without creating competing duplicate blocks.
    """
    client = fabric_env
    event_id = "evt-idempotent-008"

    # First submission
    res1 = client.record_action_event(
        event_id=event_id,
        request_id="req-idem-001",
        agent_id="agent-wp6-verifier",
        action="EXECUTE_TRADE",
        resource="equity://AAPL",
        decision="PERMIT",
        reason="Within trade limit",
        policy_id="pol-trade-01",
        policy_version="1.0.0",
        evidence_reference="ev://trade/001",
        evidence_hash="sha256-trade-hash-001"
    )

    initial_block_count = len(client.ledger_service.blocks)
    block_index_1 = res1["block_index"]

    # Duplicate submission with identical event_id
    res2 = client.record_action_event(
        event_id=event_id,
        request_id="req-idem-002",
        agent_id="agent-wp6-verifier",
        action="EXECUTE_TRADE",
        resource="equity://AAPL",
        decision="PERMIT",
        reason="Duplicate trade attempt",
        policy_id="pol-trade-01",
        policy_version="1.0.0",
        evidence_reference="ev://trade/001",
        evidence_hash="sha256-trade-hash-001"
    )

    # Must resolve idempotently to same block without creating a new block
    assert res2.get("idempotent_replay") is True
    assert res2["block_index"] == block_index_1
    assert len(client.ledger_service.blocks) == initial_block_count

    # Both verify identically
    v1 = client.verify_committed_transaction(res1)
    v2 = client.verify_committed_transaction(res2)

    assert v1.status == VerificationStatus.VERIFIED_COMMITTED
    assert v2.status == VerificationStatus.VERIFIED_COMMITTED
    assert v1.tx_id == v2.tx_id
    assert v1.block_number == v2.block_number


def test_09_multi_peer_verification_returns_consistent_transaction_evidence(fabric_env):
    """
    Scenario 9: Multiple independent peer nodes (Org1 and Org2) return
    consistent transaction evidence, matching block numbers, hashes, and validation codes.
    """
    client = fabric_env
    event_id = "evt-multi-peer-009"

    res = client.record_action_event_verified(
        event_id=event_id,
        request_id="req-multipeer-009",
        agent_id="agent-wp6-verifier",
        action="SIGN_CONTRACT",
        resource="contract://partner/agmt-99",
        decision="PERMIT",
        reason="Partner authorization verified",
        policy_id="pol-contract-01",
        policy_version="1.0.0",
        evidence_reference="ev://contract/009",
        evidence_hash="sha256-contract-009",
        min_peers=2
    )

    assert res["verification_status"] == VerificationStatus.VERIFIED_COMMITTED.value
    verification: VerificationResult = res["verification"]
    assert len(verification.peer_evidences) == 2

    peer_0 = verification.peer_evidences[0]
    peer_1 = verification.peer_evidences[1]

    assert peer_0.peer_id != peer_1.peer_id
    assert peer_0.block_number == peer_1.block_number
    assert peer_0.block_hash == peer_1.block_hash
    assert peer_0.validation_code == peer_1.validation_code == "VALID"
    assert verification.details.get("multi_peer_consensus") is True


def test_10_multi_peer_consensus_divergence_rejected(fabric_env):
    """
    Scenario 10: Multi-peer consensus divergence: Peer A and Peer B return conflicting
    block hashes or validation codes for the same transaction.
    CommitVerificationEngine must detect consensus fork and REJECT.
    """
    client = fabric_env
    event_id = "evt-divergence-010"

    gateway_res = client.record_action_event(
        event_id=event_id,
        request_id="req-div-010",
        agent_id="agent-wp6-verifier",
        action="TRANSFER_FUNDS",
        resource="account://corp/escrow",
        decision="PERMIT",
        reason="Escrow payout",
        policy_id="pol-fin-02",
        policy_version="1.0.0",
        evidence_reference="ev://fin/010",
        evidence_hash="sha256-hash-010"
    )

    # Create a divergent peer that has a conflicting block hash
    divergent_ledger = FabricLedgerService()
    # Populate with a different block
    divergent_ledger.record_audit_event(
        event_id=event_id,
        request_id="req-div-010",
        agent_id="agent-wp6-verifier",
        action="TRANSFER_FUNDS",
        resource="account://corp/escrow",
        decision="PERMIT",
        reason="Escrow payout on forked ledger",
        policy_id="pol-fin-02",
        policy_version="1.0.0",
        evidence_reference="ev://fin/010",
        evidence_hash="sha256-hash-010"
    )

    peer1 = SimulatorPeerClient("peer0.org1.agenttrust.com", client.ledger_service)
    divergent_peer2 = SimulatorPeerClient("peer0.org2.divergent.com", divergent_ledger)

    verifier = CommitVerificationEngine([peer1, divergent_peer2])
    verification = verifier.verify_transaction(gateway_res, min_peers=2)

    assert verification.status == VerificationStatus.REJECTED
    assert any("MULTI_PEER_DIVERGENCE" in r for r in verification.failure_reasons)
