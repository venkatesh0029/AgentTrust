#!/usr/bin/env python3
"""Manage AgentTrust's isolated three-orderer Raft resilience lab.

This tool intentionally uses fabric/raft3/ only. It never modifies the frozen
single-orderer network configuration or agenttrust_persistent.db.
"""
from __future__ import annotations

import argparse
import base64
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
RAFT3_ROOT = ROOT / "fabric" / "raft3"
COMPOSE_FILE = RAFT3_ROOT / "docker-compose-raft3.yaml"
CRYPTO_CONFIG = RAFT3_ROOT / "crypto-config"
ARTIFACTS = RAFT3_ROOT / "channel-artifacts"
GENESIS_BLOCK = ARTIFACTS / "orderer.genesis.block"
CHANNEL_TX = ARTIFACTS / "agenttrust-raft3.tx"
CHANNEL_BLOCK = ARTIFACTS / "agenttrust-raft3.block"
PROJECT_NAME = "agenttrust-raft3"
NETWORK_NAME = "agenttrust-raft3-net"
TOOLS_IMAGE = "hyperledger/fabric-tools:2.5.4"
ORDERERS = (
    "orderer1.agenttrust.com",
    "orderer2.agenttrust.com",
    "orderer3.agenttrust.com",
)
PEERS = ("peer0.org1.agenttrust.com", "peer0.org2.agenttrust.com")
COUCHDB_ENDPOINTS = {
    "Org1": "http://127.0.0.1:15984/_up",
    "Org2": "http://127.0.0.1:16984/_up",
}
EXPECTED_SERVICES = set(ORDERERS) | set(PEERS) | {
    "couchdb0.org1.agenttrust.com",
    "couchdb0.org2.agenttrust.com",
}


def compose_base_command() -> list[str]:
    return [
        "docker", "compose", "--project-name", PROJECT_NAME,
        "--file", str(COMPOSE_FILE),
    ]


def build_compose_down_command(destroy_volumes: bool = False) -> list[str]:
    """Build a non-destructive down command unless volume deletion is explicit."""
    command = compose_base_command() + ["down", "--remove-orphans"]
    if destroy_volumes:
        command.append("--volumes")
    return command


def contains_leader_evidence(log_text: str) -> bool:
    normalized = log_text.lower()
    return "start accepting requests as raft leader" in normalized or "became leader" in normalized


def run_command(
    command: Sequence[str],
    *,
    check: bool = True,
    capture: bool = False,
    cwd: Path | None = None,
    timeout: int | None = None,
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


def ensure_docker() -> None:
    run_command(["docker", "info", "--format", "{{.ServerVersion}}"], capture=True, timeout=15)


def static_validate() -> None:
    if not COMPOSE_FILE.is_file():
        raise RuntimeError(f"Missing isolated Compose file: {COMPOSE_FILE}")
    crypto_template = (RAFT3_ROOT / "crypto-config.yaml").read_text(encoding="utf-8")
    configtx = (RAFT3_ROOT / "configtx.yaml").read_text(encoding="utf-8")
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
    for orderer in ORDERERS:
        short_name = orderer.removesuffix(".agenttrust.com")
        if f"Hostname: {short_name}" not in crypto_template:
            raise RuntimeError(f"Crypto template is missing {short_name}.")
        if f"Host: {orderer}" not in configtx:
            raise RuntimeError(f"Raft config is missing consenter {orderer}.")
        if f"{orderer}:" not in compose_text:
            raise RuntimeError(f"Compose file is missing service {orderer}.")
    if configtx.count("ClientTLSCert:") != 3 or configtx.count("ServerTLSCert:") != 3:
        raise RuntimeError("The configtx profile must define exactly three client/server TLS certificate pairs.")
    run_command(["docker", "compose", "--file", str(COMPOSE_FILE), "config", "--quiet"], capture=True)


def ensure_bootstrap_artifacts() -> None:
    missing = [str(p.relative_to(ROOT)) for p in (GENESIS_BLOCK, CHANNEL_TX) if not p.is_file()]
    for orderer in ORDERERS:
        cert = CRYPTO_CONFIG / "ordererOrganizations" / "agenttrust.com" / "orderers" / orderer / "tls" / "server.crt"
        if not cert.is_file():
            missing.append(str(cert.relative_to(ROOT)))
    for peer in PEERS:
        org_domain = "org1.agenttrust.com" if ".org1." in peer else "org2.agenttrust.com"
        cert = CRYPTO_CONFIG / "peerOrganizations" / org_domain / "peers" / peer / "tls" / "server.crt"
        if not cert.is_file():
            missing.append(str(cert.relative_to(ROOT)))
    if missing:
        raise RuntimeError("Bootstrap artifacts are missing. Run 'bootstrap' first:\n  - " + "\n  - ".join(missing))


def _raft3_volumes_present() -> list[str]:
    result = run_command(["docker", "volume", "ls", "--format", "{{.Name}}"], capture=True)
    prefix = PROJECT_NAME + "_"
    return [line.strip() for line in (result.stdout or "").splitlines() if line.strip().startswith(prefix)]


def _running_services() -> set[str]:
    result = run_command(
        compose_base_command() + ["ps", "--services", "--filter", "status=running"],
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    return {line.strip() for line in (result.stdout or "").splitlines() if line.strip()}


def _orderer_logs(tail: int = 300) -> str:
    result = run_command(
        compose_base_command() + ["logs", "--no-color", "--tail", str(tail), *ORDERERS],
        capture=True,
        check=False,
    )
    return result.stdout or ""


def _couchdb_ready(url: str, timeout: float = 2.0) -> bool:
    credential = base64.b64encode(b"admin:adminpw").decode("ascii")
    request = Request(url, headers={"Authorization": f"Basic {credential}"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status == 200
    except (OSError, URLError, TimeoutError):
        return False


def validate_command() -> None:
    ensure_docker()
    static_validate()
    print("[PASS] Docker daemon responsive.")
    print("[PASS] Isolated Raft-3 Compose file validates.")
    print("[PASS] Three orderer services and three TLS consenters are declared.")
    print("[PASS] Frozen fabric/docker-compose-fabric.yaml is not modified by this CLI.")
    print("[PASS] Runtime state is isolated under fabric/raft3/ and project agenttrust-raft3.")
    if GENESIS_BLOCK.is_file() and CHANNEL_TX.is_file():
        ensure_bootstrap_artifacts()
        print("[PASS] Generated bootstrap artifacts are present.")
    else:
        print("[INFO] Bootstrap artifacts have not been generated; run: py -3.11 scripts/fabric_raft3.py bootstrap")


def bootstrap_command(force_regenerate: bool = False) -> None:
    ensure_docker()
    static_validate()
    generated_exists = CRYPTO_CONFIG.exists() or ARTIFACTS.exists()
    if generated_exists and not force_regenerate:
        raise RuntimeError(
            "Generated Raft-3 crypto/artifacts already exist. Inspect them first. "
            "Use bootstrap --force-regenerate only for an intentionally fresh lab rebuild."
        )
    if force_regenerate:
        running = _running_services()
        volumes = _raft3_volumes_present()
        if running:
            raise RuntimeError("Stop the isolated Raft-3 network before regenerating credentials: run down first.")
        if volumes:
            raise RuntimeError(
                "Raft-3 named volumes still exist. Refusing to pair new certificates with old ledgers. "
                "Run 'down --destroy-volumes' and confirm the prompt before force-regenerating."
            )
        confirmation = input("Type REGENERATE RAFT3 CRYPTO to delete only fabric/raft3 generated artifacts: ")
        if confirmation != "REGENERATE RAFT3 CRYPTO":
            raise RuntimeError("Confirmation did not match; no generated files were removed.")
        if CRYPTO_CONFIG.exists():
            shutil.rmtree(CRYPTO_CONFIG)
        if ARTIFACTS.exists():
            shutil.rmtree(ARTIFACTS)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    bind_path = str(RAFT3_ROOT.resolve())
    shell_script = (
        "set -eu; "
        "cryptogen generate --config=./crypto-config.yaml --output=./crypto-config; "
        "mkdir -p ./channel-artifacts; "
        "configtxgen -profile AgentTrustRaft3Genesis -channelID system-channel "
        "-outputBlock ./channel-artifacts/orderer.genesis.block; "
        "configtxgen -profile AgentTrustRaft3Channel -channelID agenttrust-raft3 "
        "-outputCreateChannelTx ./channel-artifacts/agenttrust-raft3.tx"
    )
    print(f"Generating isolated identities and Raft-3 genesis/channel artifacts in {RAFT3_ROOT} ...")
    run_command([
        "docker", "run", "--rm", "--pull=missing",
        "--volume", f"{bind_path}:/work",
        "--workdir", "/work",
        "--env", "FABRIC_CFG_PATH=/work",
        TOOLS_IMAGE, "sh", "-lc", shell_script,
    ], timeout=600)
    ensure_bootstrap_artifacts()
    print("[PASS] Three orderer identities and TLS certificates generated.")
    print(f"[PASS] System-channel genesis block: {GENESIS_BLOCK.relative_to(ROOT)}")
    print(f"[PASS] Application-channel transaction: {CHANNEL_TX.relative_to(ROOT)}")
    print("Only fabric/raft3/ generated paths were written. No live containers, volumes, or demo database were changed.")


def wait_for_readiness(timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_missing: set[str] = set(EXPECTED_SERVICES)
    couch_ready: set[str] = set()
    leader_seen = False
    while time.monotonic() < deadline:
        running = _running_services()
        last_missing = EXPECTED_SERVICES - running
        couch_ready = {name for name, url in COUCHDB_ENDPOINTS.items() if _couchdb_ready(url)}
        leader_seen = contains_leader_evidence(_orderer_logs())
        if not last_missing and couch_ready == set(COUCHDB_ENDPOINTS) and leader_seen:
            print("[PASS] All 7 isolated services are running.")
            print("[PASS] Both CouchDB health endpoints are responsive.")
            print("[PASS] Raft leader-election evidence found in orderer logs.")
            return
        time.sleep(3)
    details = [f"missing running services: {sorted(last_missing)}", f"CouchDB ready: {sorted(couch_ready)}", f"leader evidence: {leader_seen}"]
    raise RuntimeError(
        f"Raft-3 network did not reach readiness within {timeout_seconds}s. "
        + "; ".join(details)
        + ". Containers and volumes were left in place for diagnosis; run status and inspect orderer logs."
    )


def up_command(timeout_seconds: int) -> None:
    ensure_docker()
    static_validate()
    ensure_bootstrap_artifacts()
    print("Starting the isolated Raft-3 lab. The existing single-orderer network remains untouched.")
    run_command(compose_base_command() + ["up", "-d"], timeout=600)
    wait_for_readiness(timeout_seconds)
    print("Raft-3 orderer quorum is showing leader-election evidence. Run channel-setup to create/join the app channel.")


def _fabric_tools_command(org: int, peer_args: Sequence[str], *, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    if org not in (1, 2):
        raise ValueError("org must be 1 or 2")
    peer = f"peer0.org{org}.agenttrust.com"
    domain = f"org{org}.agenttrust.com"
    msp_id = f"Org{org}MSP"
    admin_msp = f"/work/crypto-config/peerOrganizations/{domain}/users/Admin@{domain}/msp"
    peer_tls = f"/work/crypto-config/peerOrganizations/{domain}/peers/{peer}/tls/ca.crt"
    peer_port = "7051" if org == 1 else "9051"
    command = [
        "docker", "run", "--rm", "--network", NETWORK_NAME,
        "--volume", f"{RAFT3_ROOT.resolve()}:/work",
        "--workdir", "/work",
        "--env", "FABRIC_CFG_PATH=/var/hyperledger/fabric/config",
        "--env", f"CORE_PEER_LOCALMSPID={msp_id}",
        "--env", f"CORE_PEER_MSPCONFIGPATH={admin_msp}",
        "--env", f"CORE_PEER_ADDRESS={peer}:{peer_port}",
        "--env", "CORE_PEER_TLS_ENABLED=true",
        "--env", f"CORE_PEER_TLS_ROOTCERT_FILE={peer_tls}",
        TOOLS_IMAGE,
        *peer_args,
    ]
    return run_command(command, capture=capture, check=check, timeout=180)


def channel_setup_command() -> None:
    ensure_bootstrap_artifacts()
    running = _running_services()
    missing = EXPECTED_SERVICES - running
    if missing:
        raise RuntimeError(f"Start the isolated Raft-3 network first; services not running: {sorted(missing)}")
    if not CHANNEL_BLOCK.is_file():
        print("Creating the isolated application channel through the three-consenter orderer cluster...")
        _fabric_tools_command(1, [
            "peer", "channel", "create",
            "--ordererTLSHostnameOverride", ORDERERS[0],
            "-o", f"{ORDERERS[0]}:7050",
            "-c", "agenttrust-raft3",
            "-f", "/work/channel-artifacts/agenttrust-raft3.tx",
            "--outputBlock", "/work/channel-artifacts/agenttrust-raft3.block",
            "--tls",
            "--cafile", "/work/crypto-config/ordererOrganizations/agenttrust.com/orderers/orderer1.agenttrust.com/tls/ca.crt",
        ])
    else:
        print("Channel block artifact already exists; reusing it and checking peer membership.")
    for org in (1, 2):
        listing = _fabric_tools_command(org, ["peer", "channel", "list"], capture=True).stdout or ""
        if "agenttrust-raft3" in listing:
            print(f"[PASS] Org{org} peer is already joined to agenttrust-raft3.")
            continue
        _fabric_tools_command(org, ["peer", "channel", "join", "-b", "/work/channel-artifacts/agenttrust-raft3.block"])
        print(f"[PASS] Org{org} peer joined agenttrust-raft3.")
    print("[PASS] Application channel created/joined. Chaincode deployment is deliberately a later step.")


def status_command() -> None:
    print("=== AgentTrust Isolated Three-Orderer Raft Lab ===")
    ps = run_command(compose_base_command() + ["ps"], capture=True, check=False)
    print(ps.stdout or "No Compose containers found.")
    if ps.returncode != 0:
        print("Compose status unavailable; run validate and inspect Docker.")
        return
    for label, url in COUCHDB_ENDPOINTS.items():
        print(f"[{label} CouchDB] {'READY' if _couchdb_ready(url) else 'NOT READY'} ({url})")
    logs = _orderer_logs()
    matches = [line for line in logs.splitlines() if any(term in line.lower() for term in (
        "raft leader", "became leader", "became follower", "raft node", "consenter", "quorum"
    ))]
    print("[Recent Raft log evidence]")
    if matches:
        for line in matches[-12:]:
            print(line)
    else:
        print("No recent Raft election/consensus lines found. Inspect all orderer logs for startup errors.")
    if CHANNEL_BLOCK.is_file() and _running_services():
        for org in (1, 2):
            listing = _fabric_tools_command(org, ["peer", "channel", "list"], capture=True, check=False)
            if listing.returncode == 0 and "agenttrust-raft3" in (listing.stdout or ""):
                info = _fabric_tools_command(org, ["peer", "channel", "getinfo", "-c", "agenttrust-raft3"], capture=True, check=False)
                print(f"[Org{org} channel info] {(info.stdout or info.stderr or '').strip()}")
            else:
                print(f"[Org{org}] channel not joined or peer CLI unavailable.")


def down_command(destroy_volumes: bool = False) -> None:
    command = build_compose_down_command(destroy_volumes)
    if destroy_volumes:
        print("WARNING: This removes only volumes belonging to the isolated agenttrust-raft3 Compose project.")
        print("The 41-agent SQLite demo database and the existing single-orderer network are not targeted.")
        confirmation = input("Type DESTROY RAFT3 VOLUMES to permanently delete isolated Raft-3 ledger/world-state data: ")
        if confirmation != "DESTROY RAFT3 VOLUMES":
            raise RuntimeError("Confirmation did not match; volumes were not removed.")
    run_command(command)
    print("Compose services stopped. Named volumes were " + ("deleted by explicit request." if destroy_volumes else "preserved."))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="Validate Docker, Compose, and the three-consenter topology")
    bootstrap_parser = subparsers.add_parser("bootstrap", help="Generate isolated orderer/peer crypto and genesis/channel artifacts")
    bootstrap_parser.add_argument("--force-regenerate", action="store_true", help="Explicitly replace generated Raft-3 crypto/artifacts after safety checks")
    up_parser = subparsers.add_parser("up", help="Start the isolated 3-orderer lab without deleting volumes")
    up_parser.add_argument("--timeout", type=int, default=240, help="Readiness timeout in seconds (default: 240)")
    subparsers.add_parser("channel-setup", help="Create the Raft-3 application channel and join both peers")
    subparsers.add_parser("status", help="Report service state, CouchDB health, Raft log evidence, and peer channel info")
    down_parser = subparsers.add_parser("down", help="Stop the isolated lab; preserve named volumes by default")
    down_parser.add_argument("--destroy-volumes", "--force", dest="destroy_volumes", action="store_true", help="Explicitly request removal of this project's named volumes; confirmation required")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            validate_command()
        elif args.command == "bootstrap":
            bootstrap_command(args.force_regenerate)
        elif args.command == "up":
            if args.timeout < 30:
                raise RuntimeError("Readiness timeout must be at least 30 seconds.")
            up_command(args.timeout)
        elif args.command == "channel-setup":
            channel_setup_command()
        elif args.command == "status":
            status_command()
        elif args.command == "down":
            down_command(args.destroy_volumes)
        return 0
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
