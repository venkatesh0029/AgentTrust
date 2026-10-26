#!/usr/bin/env python3
"""Deploy and smoke-test Go chaincode on the isolated AgentTrust Raft-3 lab using CCaaS."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "fabric" / "raft3"
COMPOSE_FILE = LAB / "docker-compose-raft3.yaml"
CCAAS_COMPOSE_FILE = LAB / "docker-compose-raft3-ccaas.yaml"
CHANNEL_BLOCK = LAB / "channel-artifacts" / "agenttrust-raft3.block"
ARTIFACTS = LAB / "channel-artifacts"
PACKAGE_FILE = ARTIFACTS / "agenttrust_raft3_ccaas.tar.gz"
MANIFEST_FILE = ARTIFACTS / "agenttrust_raft3.package.json"
CHAINCODE_SOURCE = ROOT / "fabric" / "chaincode"
PROJECT = "agenttrust-raft3"
NETWORK = "agenttrust-raft3-net"
TOOLS_IMAGE = "hyperledger/fabric-tools:2.5.4"
CHANNEL = "agenttrust-raft3"
CHAINCODE = "agenttrust"
VERSION = "1.0"
SEQUENCE = 1
PACKAGE_LABEL = "agenttrust_raft3_ccaas_1.0"
CC_SERVICE = "agenttrust-raft3-chaincode"
CC_PORT = 9999
ORDERER = os.environ.get("RAFT3_TARGET_ORDERER", "orderer1.agenttrust.com")
ORDERERS = (
    "orderer1.agenttrust.com",
    "orderer2.agenttrust.com",
    "orderer3.agenttrust.com",
)
PEERS: dict[int, dict[str, Any]] = {
    1: {
        "org": 1,
        "msp_id": "Org1MSP",
        "peer": "peer0.org1.agenttrust.com",
        "port": 7051,
        "address": "peer0.org1.agenttrust.com:7051",
        "domain": "org1.agenttrust.com",
        "tls_root": "/work/crypto-config/peerOrganizations/org1.agenttrust.com/peers/peer0.org1.agenttrust.com/tls/ca.crt",
        "admin_msp": "/work/crypto-config/peerOrganizations/org1.agenttrust.com/users/Admin@org1.agenttrust.com/msp",
    },
    2: {
        "org": 2,
        "msp_id": "Org2MSP",
        "peer": "peer0.org2.agenttrust.com",
        "port": 9051,
        "address": "peer0.org2.agenttrust.com:9051",
        "domain": "org2.agenttrust.com",
        "tls_root": "/work/crypto-config/peerOrganizations/org2.agenttrust.com/peers/peer0.org2.agenttrust.com/tls/ca.crt",
        "admin_msp": "/work/crypto-config/peerOrganizations/org2.agenttrust.com/users/Admin@org2.agenttrust.com/msp",
    },
}

ORDERER_CA = f"/work/crypto-config/ordererOrganizations/agenttrust.com/orderers/{ORDERER}/tls/ca.crt"
ORDERER_ADDRESS = f"{ORDERER}:7050"
ENDORSEMENT_POLICY = "AND('Org1MSP.peer','Org2MSP.peer')"


def run_command(
    command: Sequence[str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=str(cwd or ROOT),
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required executable not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {' '.join(command)}") from exc
    if check and result.returncode != 0:
        detail = (result.stdout or "").strip() if capture else ""
        suffix = f"\n{detail}" if detail else ""
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(command)}{suffix}")
    return result


def fabric_tools_command(
    org: int,
    args: Sequence[str],
    *,
    capture: bool = True,
    check: bool = True,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    if org not in PEERS:
        raise ValueError(f"Unknown org: {org}")
    peer_info = PEERS[org]
    command = [
        "docker", "run", "--rm",
        "--network", NETWORK,
        "--volume", f"{LAB.resolve()}:/work",
        "--volume", f"{CHAINCODE_SOURCE.resolve()}:/chaincode",
        "--workdir", "/work",
        "--env", "FABRIC_CFG_PATH=/var/hyperledger/fabric/config",
        "--env", f"CORE_PEER_LOCALMSPID={peer_info['msp_id']}",
        "--env", f"CORE_PEER_MSPCONFIGPATH={peer_info['admin_msp']}",
        "--env", f"CORE_PEER_ADDRESS={peer_info['address']}",
        "--env", "CORE_PEER_TLS_ENABLED=true",
        "--env", f"CORE_PEER_TLS_ROOTCERT_FILE={peer_info['tls_root']}",
        TOOLS_IMAGE,
        *args,
    ]
    return run_command(command, capture=capture, check=check, timeout=timeout)


def source_hash() -> str:
    """Compute deterministic SHA-256 hash of all chaincode source files."""
    hasher = hashlib.sha256()
    for file_path in sorted(CHAINCODE_SOURCE.rglob("*")):
        if file_path.is_file() and not file_path.name.startswith("."):
            rel = file_path.relative_to(CHAINCODE_SOURCE).as_posix()
            hasher.update(rel.encode("utf-8"))
            hasher.update(file_path.read_bytes())
    return hasher.hexdigest()


def read_manifest() -> dict[str, Any] | None:
    if MANIFEST_FILE.is_file():
        try:
            return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def write_manifest(current_source_hash: str, package_id: str) -> None:
    data = {
        "label": PACKAGE_LABEL,
        "channel": CHANNEL,
        "chaincode": CHAINCODE,
        "version": VERSION,
        "sequence": SEQUENCE,
        "source_hash": current_source_hash,
        "package_id": package_id,
        "package_file": str(PACKAGE_FILE.relative_to(ROOT)),
        "timestamp": time.time(),
    }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def package_chaincode(force: bool = False) -> tuple[Path, str]:
    """Create CCaaS package containing metadata.json and code.tar.gz (connection.json)."""
    current_h = source_hash()
    manifest = read_manifest()

    if not force and PACKAGE_FILE.is_file() and manifest and manifest.get("source_hash") == current_h:
        pkg_id = manifest.get("package_id")
        if pkg_id:
            print(f"[REUSE] Existing CCaaS package matches source hash: {PACKAGE_FILE.name} ({pkg_id})")
            return PACKAGE_FILE, pkg_id

    print(f"Packaging CCaaS chaincode {CHAINCODE} ({PACKAGE_LABEL}) for {CC_SERVICE}:{CC_PORT}...")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    conn_data = json.dumps({
        "address": f"{CC_SERVICE}:{CC_PORT}",
        "dial_timeout": "10s",
        "tls_required": False,
    }, indent=2).encode("utf-8")

    code_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=code_tar_buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo(name="connection.json")
        ti.size = len(conn_data)
        ti.mtime = 0
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(conn_data))
    code_tar_bytes = code_tar_buf.getvalue()

    metadata_data = json.dumps({
        "type": "ccaas",
        "label": PACKAGE_LABEL,
    }, indent=2).encode("utf-8")

    with tarfile.open(PACKAGE_FILE, mode="w:gz") as outer:
        meta_ti = tarfile.TarInfo(name="metadata.json")
        meta_ti.size = len(metadata_data)
        meta_ti.mtime = 0
        meta_ti.mode = 0o644
        outer.addfile(meta_ti, io.BytesIO(metadata_data))

        code_ti = tarfile.TarInfo(name="code.tar.gz")
        code_ti.size = len(code_tar_bytes)
        code_ti.mtime = 0
        code_ti.mode = 0o644
        outer.addfile(code_ti, io.BytesIO(code_tar_bytes))

    pkg_bytes = PACKAGE_FILE.read_bytes()
    pkg_hash = hashlib.sha256(pkg_bytes).hexdigest()
    pkg_id = f"{PACKAGE_LABEL}:{pkg_hash}"
    write_manifest(current_h, pkg_id)
    print(f"[PASS] CCaaS package created: {PACKAGE_FILE.relative_to(ROOT)} ({len(pkg_bytes)} bytes)")
    print(f"[PASS] Calculated Package ID: {pkg_id}")
    return PACKAGE_FILE, pkg_id


def start_ccaas_service(package_id: str) -> None:
    """Start or update the CCaaS container service on the isolated Raft-3 network."""
    if not CCAAS_COMPOSE_FILE.is_file():
        raise RuntimeError(f"Missing CCaaS Compose file: {CCAAS_COMPOSE_FILE}")

    print(f"Starting CCaaS service with CHAINCODE_ID={package_id}...")
    env = dict(os.environ)
    env["RAFT3_CHAINCODE_ID"] = package_id

    run_command(
        [
            "docker", "compose",
            "--project-name", PROJECT,
            "--file", str(CCAAS_COMPOSE_FILE),
            "up", "-d", "--build",
        ],
        env=env,
        timeout=300,
    )
    print(f"[PASS] CCaaS service '{CC_SERVICE}' running on network '{NETWORK}'.")


def get_installed_package_ids(org: int) -> list[str]:
    res = fabric_tools_command(org, ["peer", "lifecycle", "chaincode", "queryinstalled"], capture=True, check=False)
    if res.returncode != 0:
        return []
    output = res.stdout or ""
    pattern = rf"({re.escape(PACKAGE_LABEL)}:[0-9a-fA-F]+)"
    return re.findall(pattern, output)


def install_chaincode_on_peer(org: int, expected_package_id: str) -> str:
    installed = get_installed_package_ids(org)
    if expected_package_id in installed:
        print(f"[PASS] Org{org} peer already has package installed: {expected_package_id}")
        return expected_package_id

    print(f"Installing CCaaS package on Org{org} peer...")
    fabric_tools_command(
        org,
        [
            "peer", "lifecycle", "chaincode", "install",
            f"/work/channel-artifacts/{PACKAGE_FILE.name}",
        ],
        capture=True,
    )
    installed = get_installed_package_ids(org)
    if expected_package_id not in installed:
        raise RuntimeError(f"Package ID {expected_package_id} not found in Org{org} installed packages: {installed}")
    print(f"[PASS] Org{org} peer installed package: {expected_package_id}")
    return expected_package_id


def check_commit_readiness() -> dict[str, bool]:
    res = fabric_tools_command(
        1,
        [
            "peer", "lifecycle", "chaincode", "checkcommitreadiness",
            "--channelID", CHANNEL,
            "--name", CHAINCODE,
            "--version", VERSION,
            "--sequence", str(SEQUENCE),
            "--signature-policy", ENDORSEMENT_POLICY,
            "--output", "json",
        ],
        capture=True,
        check=False,
    )
    if res.returncode != 0:
        return {}
    try:
        data = json.loads(res.stdout or "{}")
        return data.get("approvals", {})
    except json.JSONDecodeError:
        return {}


def approve_chaincode_for_org(org: int, package_id: str) -> None:
    readiness = check_commit_readiness()
    msp = str(PEERS[org]["msp_id"])
    if readiness.get(msp) is True:
        print(f"[PASS] Org{org} ({msp}) has already approved chaincode definition.")
        return

    print(f"Approving chaincode definition for Org{org} ({msp}) with package ID {package_id}...")
    fabric_tools_command(
        org,
        [
            "peer", "lifecycle", "chaincode", "approveformyorg",
            "-o", ORDERER_ADDRESS,
            "--ordererTLSHostnameOverride", ORDERER,
            "--tls",
            "--cafile", ORDERER_CA,
            "--channelID", CHANNEL,
            "--name", CHAINCODE,
            "--version", VERSION,
            "--package-id", package_id,
            "--sequence", str(SEQUENCE),
            "--signature-policy", ENDORSEMENT_POLICY,
        ],
        capture=True,
    )
    print(f"[PASS] Org{org} approved chaincode definition.")


def is_chaincode_committed() -> bool:
    res = fabric_tools_command(
        1,
        [
            "peer", "lifecycle", "chaincode", "querycommitted",
            "--channelID", CHANNEL,
            "--name", CHAINCODE,
            "--output", "json",
        ],
        capture=True,
        check=False,
    )
    if res.returncode != 0:
        return False
    try:
        data = json.loads(res.stdout or "{}")
        return data.get("sequence") == SEQUENCE
    except json.JSONDecodeError:
        return False


def commit_chaincode_definition() -> None:
    if is_chaincode_committed():
        print(f"[PASS] Chaincode '{CHAINCODE}' (sequence {SEQUENCE}) is already committed on '{CHANNEL}'.")
        return

    print(f"Committing chaincode definition '{CHAINCODE}' sequence {SEQUENCE} with endorsement policy {ENDORSEMENT_POLICY}...")
    fabric_tools_command(
        1,
        [
            "peer", "lifecycle", "chaincode", "commit",
            "-o", ORDERER_ADDRESS,
            "--ordererTLSHostnameOverride", ORDERER,
            "--tls",
            "--cafile", ORDERER_CA,
            "--channelID", CHANNEL,
            "--name", CHAINCODE,
            "--version", VERSION,
            "--sequence", str(SEQUENCE),
            "--signature-policy", ENDORSEMENT_POLICY,
            "--peerAddresses", str(PEERS[1]["address"]),
            "--tlsRootCertFiles", str(PEERS[1]["tls_root"]),
            "--peerAddresses", str(PEERS[2]["address"]),
            "--tlsRootCertFiles", str(PEERS[2]["tls_root"]),
        ],
        capture=True,
    )
    print(f"[PASS] Chaincode definition committed on channel '{CHANNEL}'.")


def deploy_command(force_repackage: bool = False) -> None:
    print("=== Deploying AgentTrust Chaincode (CCaaS) to Isolated Raft-3 Lab ===")
    _, package_id = package_chaincode(force=force_repackage)

    start_ccaas_service(package_id)

    for org in (1, 2):
        install_chaincode_on_peer(org, package_id)

    for org in (1, 2):
        approve_chaincode_for_org(org, package_id)

    readiness = check_commit_readiness()
    print(f"Commit readiness check: {readiness}")
    if not (readiness.get("Org1MSP") and readiness.get("Org2MSP")):
        raise RuntimeError(f"Commit readiness incomplete: {readiness}")

    commit_chaincode_definition()

    for org in (1, 2):
        res = fabric_tools_command(
            org,
            [
                "peer", "lifecycle", "chaincode", "querycommitted",
                "--channelID", CHANNEL,
                "--name", CHAINCODE,
            ],
            capture=True,
        )
        print(f"[Org{org} committed definition]\n{(res.stdout or '').strip()}")


def smoke_test_command() -> None:
    print("=== Running Smoke Test on Isolated Raft-3 Channel ===")
    if not is_chaincode_committed():
        raise RuntimeError("Chaincode is not committed on channel. Run deploy first.")

    event_id = f"EVENT-RAFT3-{uuid.uuid4().hex[:8].upper()}"
    req_id = f"REQ-RAFT3-{uuid.uuid4().hex[:8].upper()}"
    agent_id = "FINANCE-AGENT-001"
    action = "TRANSFER_FUNDS"
    resource = "TREASURY_LEDGER"
    decision = "ALLOWED"
    reason = "POLICY_LIMIT_WITHIN_BOUNDS"
    policy_id = "FIN-POL-001"
    policy_version = "1.0"
    evidence_ref = f"EVID-REF-{uuid.uuid4().hex[:8].upper()}"
    evidence_payload = f"audit_evidence_data_{uuid.uuid4().hex}".encode("utf-8")
    authentic_hash = hashlib.sha256(evidence_payload).hexdigest()
    tampered_hash = "0" * 64

    print(f"1. Submitting RecordActionEvent transaction ({event_id})...")
    invoke_args = json.dumps({
        "Args": [
            "RecordActionEvent",
            event_id,
            req_id,
            agent_id,
            action,
            resource,
            decision,
            reason,
            policy_id,
            policy_version,
            evidence_ref,
            authentic_hash,
        ]
    })

    fabric_tools_command(
        1,
        [
            "peer", "chaincode", "invoke",
            "-o", ORDERER_ADDRESS,
            "--ordererTLSHostnameOverride", ORDERER,
            "--tls",
            "--cafile", ORDERER_CA,
            "-C", CHANNEL,
            "-n", CHAINCODE,
            "--peerAddresses", str(PEERS[1]["address"]),
            "--tlsRootCertFiles", str(PEERS[1]["tls_root"]),
            "--peerAddresses", str(PEERS[2]["address"]),
            "--tlsRootCertFiles", str(PEERS[2]["tls_root"]),
            "-c", invoke_args,
            "--waitForEvent",
        ],
        capture=True,
        timeout=300,
    )
    print(f"[PASS] Transaction committed across both peer organizations with endorsement policy {ENDORSEMENT_POLICY}.")

    print("2. Querying committed ActionEvent from Org1 peer...")
    query_args = json.dumps({"Args": ["GetActionEvent", event_id]})
    query_res = fabric_tools_command(
        1,
        [
            "peer", "chaincode", "query",
            "-C", CHANNEL,
            "-n", CHAINCODE,
            "-c", query_args,
        ],
        capture=True,
    )
    query_output = query_res.stdout or ""
    print(f"   Response: {query_output.strip()}")
    assert event_id in query_output
    assert authentic_hash in query_output
    print("[PASS] ActionEvent verified on Org1 peer ledger.")

    print("3. Verifying authentic evidence reference on ledger...")
    auth_args = json.dumps({"Args": ["VerifyEvidenceReference", evidence_ref, authentic_hash]})
    auth_res = fabric_tools_command(
        1,
        [
            "peer", "chaincode", "query",
            "-C", CHANNEL,
            "-n", CHAINCODE,
            "-c", auth_args,
        ],
        capture=True,
    )
    auth_output = auth_res.stdout or ""
    print(f"   Response: {auth_output.strip()}")
    assert '"VERIFIED"' in auth_output
    print("[PASS] Authentic evidence reference status: VERIFIED.")

    print("4. Verifying tamper detection with mismatched evidence hash on Org2 peer...")
    tamper_args = json.dumps({"Args": ["VerifyEvidenceReference", evidence_ref, tampered_hash]})
    tamper_res = fabric_tools_command(
        2,
        [
            "peer", "chaincode", "query",
            "-C", CHANNEL,
            "-n", CHAINCODE,
            "-c", tamper_args,
        ],
        capture=True,
    )
    tamper_output = tamper_res.stdout or ""
    print(f"   Response: {tamper_output.strip()}")
    assert '"TAMPERING_DETECTED"' in tamper_output
    print("[PASS] Tampered evidence reference status: TAMPERING_DETECTED.")

    print("5. Confirming ledger height on both peer organizations...")
    for org in (1, 2):
        info_res = fabric_tools_command(
            org,
            ["peer", "channel", "getinfo", "-c", CHANNEL],
            capture=True,
        )
        print(f"   [Org{org}] {(info_res.stdout or '').strip()}")
    print("[PASS] Multi-peer Raft-3 consensus smoke test complete!")


def status_command() -> None:
    print("=== AgentTrust Raft-3 Chaincode Status ===")
    ps_res = run_command(
        ["docker", "compose", "--project-name", PROJECT, "--file", str(COMPOSE_FILE), "ps"],
        capture=True,
        check=False,
    )
    print(ps_res.stdout or "No containers running.")

    manifest = read_manifest()
    if CCAAS_COMPOSE_FILE.is_file():
        env = dict(os.environ)
        if manifest and manifest.get("package_id"):
            env["RAFT3_CHAINCODE_ID"] = manifest["package_id"]
        else:
            env["RAFT3_CHAINCODE_ID"] = f"{PACKAGE_LABEL}:unknown"
        ccaas_ps = run_command(
            ["docker", "compose", "--project-name", PROJECT, "--file", str(CCAAS_COMPOSE_FILE), "ps"],
            capture=True,
            check=False,
            env=env,
        )
        print("\n[CCaaS Service]")
        print(ccaas_ps.stdout or "No CCaaS container running.")

    if manifest:
        source_hash = str(manifest.get("source_hash") or "")
        print(f"\n[Manifest] Label: {manifest.get('label')}, PackageID: {manifest.get('package_id')}, Hash: {source_hash[:16]}...")
    else:
        print("\n[Manifest] No package manifest found.")

    for org in (1, 2):
        print(f"\n--- Org{org} ({PEERS[org]['peer']}) ---")
        inst = fabric_tools_command(org, ["peer", "lifecycle", "chaincode", "queryinstalled"], capture=True, check=False)
        print(f"[Installed]\n{(inst.stdout or '').strip()}")
        comm = fabric_tools_command(org, ["peer", "lifecycle", "chaincode", "querycommitted", "-C", CHANNEL, "-n", CHAINCODE], capture=True, check=False)
        print(f"[Committed]\n{(comm.stdout or '').strip()}")
        h_info = fabric_tools_command(org, ["peer", "channel", "getinfo", "-c", CHANNEL], capture=True, check=False)
        print(f"[Channel Height]\n{(h_info.stdout or '').strip()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage CCaaS chaincode lifecycle on isolated Raft-3 lab.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pkg_parser = subparsers.add_parser("package", help="Package chaincode into CCaaS tar.gz")
    pkg_parser.add_argument("--force", action="store_true", help="Force repackage even if source hash matches")

    dep_parser = subparsers.add_parser("deploy", help="Deploy CCaaS chaincode across both orgs on Raft-3 channel")
    dep_parser.add_argument("--force-repackage", action="store_true", help="Force repackaging before deploy")

    subparsers.add_parser("smoke-test", help="Run end-to-end transaction commit and tamper verification")
    subparsers.add_parser("status", help="Inspect chaincode status and ledger heights")

    args = parser.parse_args()

    if args.command == "package":
        package_chaincode(force=args.force)
    elif args.command == "deploy":
        deploy_command(force_repackage=args.force_repackage)
    elif args.command == "smoke-test":
        smoke_test_command()
    elif args.command == "status":
        status_command()


if __name__ == "__main__":
    main()
