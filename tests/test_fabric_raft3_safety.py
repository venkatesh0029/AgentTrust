from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.fabric_raft3 import (
    COMPOSE_FILE,
    RAFT3_ROOT,
    ROOT,
    build_compose_down_command,
    contains_leader_evidence,
)


def test_normal_down_preserves_named_volumes() -> None:
    command = build_compose_down_command()
    assert "down" in command
    assert "--volumes" not in command
    assert "-v" not in command


def test_volume_removal_requires_explicit_option() -> None:
    command = build_compose_down_command(destroy_volumes=True)
    assert "down" in command
    assert "--volumes" in command


def test_lab_is_isolated_from_existing_fabric_compose() -> None:
    assert RAFT3_ROOT == ROOT / "fabric" / "raft3"
    assert COMPOSE_FILE == RAFT3_ROOT / "docker-compose-raft3.yaml"
    assert COMPOSE_FILE.name != "docker-compose-fabric.yaml"
    source = (PROJECT_ROOT / "scripts" / "fabric_raft3.py").read_text(encoding="utf-8")
    assert 'ROOT / "agenttrust_persistent.db"' not in source


def test_three_orderer_hosts_and_tls_consenters_are_configured() -> None:
    configtx = (RAFT3_ROOT / "configtx.yaml").read_text(encoding="utf-8")
    crypto = (RAFT3_ROOT / "crypto-config.yaml").read_text(encoding="utf-8")
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    for orderer in ("orderer1", "orderer2", "orderer3"):
        assert f"Hostname: {orderer}" in crypto
        assert f"Host: {orderer}.agenttrust.com" in configtx
        assert f"{orderer}.agenttrust.com:" in compose
    assert configtx.count("ClientTLSCert:") == 3
    assert configtx.count("ServerTLSCert:") == 3
    assert "Host: peer0.org1.agenttrust.com" in configtx
    assert "Host: peer0.org2.agenttrust.com" in configtx


def test_bootstrap_artifacts_are_ignored_by_git() -> None:
    ignore = (RAFT3_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "crypto-config/" in ignore
    assert "channel-artifacts/" in ignore


def test_leader_evidence_requires_a_raft_leader_message() -> None:
    assert contains_leader_evidence("Start accepting requests as Raft leader at block [0]")
    assert contains_leader_evidence("node became leader at term 2")
    assert not contains_leader_evidence("Starting orderer on port 7050")
