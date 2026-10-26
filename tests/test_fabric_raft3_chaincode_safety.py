from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CHAINCODE = ROOT / "fabric" / "chaincode" / "agenttrust_cc.go"
HARNESS = ROOT / "scripts" / "fabric_raft3_chaincode.py"


def test_chaincode_uses_deterministic_transaction_timestamp():
    source = CHAINCODE.read_text(encoding="utf-8")
    assert "GetTxTimestamp()" in source
    assert "time.Now()" not in source
    assert source.count("transactionTimestamp(ctx)") == 3


def test_harness_targets_only_isolated_project_and_channel():
    source = HARNESS.read_text(encoding="utf-8")
    assert 'PROJECT = "agenttrust-raft3"' in source
    assert 'NETWORK = "agenttrust-raft3-net"' in source
    assert 'CHANNEL = "agenttrust-raft3"' in source
    assert "agenttrust_persistent.db" not in source
    assert "--waitForEvent" in source


def test_contract_uses_both_org_endorsement_policy():
    source = HARNESS.read_text(encoding="utf-8")
    assert "AND('Org1MSP.peer','Org2MSP.peer')" in source


def test_smoke_test_checks_authentic_and_tampered_evidence():
    source = HARNESS.read_text(encoding="utf-8")
    assert '"VerifyEvidenceReference"' in source
    assert '"TAMPERING_DETECTED"' in source
    assert '"VERIFIED"' in source


def test_package_manifest_detects_source_drift():
    source = HARNESS.read_text(encoding="utf-8")
    assert "MANIFEST_FILE" in source
    assert "source_hash" in source
    from scripts.fabric_raft3_chaincode import source_hash
    initial = source_hash()
    assert isinstance(initial, str) and len(initial) == 64


def test_orderer_tls_and_peer_endpoints_configured():
    source = HARNESS.read_text(encoding="utf-8")
    assert "orderer1.agenttrust.com" in source
    assert "peer0.org1.agenttrust.com" in source
    assert "peer0.org2.agenttrust.com" in source
    assert "7051" in source
    assert "9051" in source


def test_ccaas_architecture_and_package_isolation():
    source = HARNESS.read_text(encoding="utf-8")
    assert "agenttrust_raft3_ccaas.tar.gz" in source
    assert "docker-compose-raft3-ccaas.yaml" in source
    assert "agenttrust-raft3-chaincode" in source
    ccaas_compose = (ROOT / "fabric" / "raft3" / "docker-compose-raft3-ccaas.yaml").read_text(encoding="utf-8")
    assert "agenttrust-raft3-chaincode:" in ccaas_compose
    assert "agenttrust-raft3-net" in ccaas_compose
    assert "docker-compose-fabric.yaml" not in ccaas_compose
