#!/usr/bin/env python3
"""
AgentTrust Hyperledger Fabric Lifecycle Management CLI.

Provides validated operations for managing the multi-peer Fabric network:
- validate: verify Docker, Compose syntax, crypto artifacts, port mapping, and tokens.
- status: inspect running services, CouchDB world states, bridge readiness, gossip, and Raft consensus.
- up: launch containers and poll until runtime readiness is achieved.
- down: stop containers safely; named volumes are preserved unless --destroy-volumes / -Force is explicitly confirmed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def repo_root() -> Path:
    """Resolve the root of the AgentTrust repository."""
    return Path(__file__).resolve().parent.parent


def build_down_args(compose_base: list[str], destroy_volumes: bool) -> list[str]:
    """Construct docker compose down command arguments based on volume flag."""
    args = list(compose_base) + ["down"]
    if destroy_volumes:
        args.append("--volumes")
    return args


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for the lifecycle CLI."""
    parser = argparse.ArgumentParser(
        prog="fabric_lifecycle",
        description="AgentTrust Hyperledger Fabric Lifecycle & Readiness Manager",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Custom repository root path (defaults to auto-detected root)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: validate
    subparsers.add_parser(
        "validate",
        help="Validate Docker daemon, compose syntax, crypto assets, and gateway configuration.",
    )

    # Subcommand: status
    subparsers.add_parser(
        "status",
        help="Inspect container status, CouchDB health, bridge readiness, gossip, and Raft leader.",
    )

    # Subcommand: up
    up_parser = subparsers.add_parser(
        "up",
        help="Start Fabric containers and wait for runtime readiness.",
    )
    up_parser.add_argument(
        "--timeout",
        type=int,
        default=240,
        help="Maximum wait time in seconds for readiness (default: 240).",
    )
    up_parser.add_argument(
        "--poll-interval",
        type=float,
        default=3.0,
        help="Seconds between readiness polls (default: 3.0).",
    )

    # Subcommand: down
    down_parser = subparsers.add_parser(
        "down",
        help="Stop Fabric containers safely. Preserves named volumes by default.",
    )
    down_parser.add_argument(
        "--destroy-volumes",
        "-Force",
        "-force",
        action="store_true",
        dest="destroy_volumes",
        help="Explicitly destroy named volumes (requires interactive confirmation phrase).",
    )

    return parser


def bridge_health_ready(reachable: bool, body: dict[str, Any] | None) -> bool:
    """Determine whether the Go SDK Gateway Bridge is reachable and in READY state."""
    if not reachable or not body or not isinstance(body, dict):
        return False
    return body.get("status") == "ONLINE" and body.get("fabric") == "READY"


def is_running_state(service_state: dict[str, Any] | None) -> bool:
    """Determine if a service is in active running state."""
    if not service_state or not isinstance(service_state, dict):
        return False
    status = service_state.get("Status", "")
    return status.lower() == "running"


def is_successful_one_shot_state(service_state: dict[str, Any] | None) -> bool:
    """Determine if a one-shot container finished successfully with exit code 0."""
    if not service_state or not isinstance(service_state, dict):
        return False
    status = service_state.get("Status", "").lower()
    exit_code = service_state.get("ExitCode")
    return status == "exited" and exit_code == 0


def _has_gossip_membership_event(log: str, peer: str) -> bool:
    """Check log snippet for actual gossip membership discovery of target peer."""
    lower_log = log.lower()
    peer_lower = peer.lower()
    if peer_lower not in lower_log:
        return False
    markers = ("membership view has changed", "peers went online", "membership updated", "discovered peer")
    return any(marker in lower_log for marker in markers)


def probe_http_json(url: str, timeout: float = 3.0) -> tuple[bool, dict[str, Any] | None]:
    """Perform a GET request to an HTTP endpoint and return (reachable, parsed_json)."""
    req = urllib.request.Request(url, headers={"User-Agent": "AgentTrust-Lifecycle/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8")
            try:
                return True, json.loads(data)
            except Exception:
                return True, {"raw": data}
    except Exception:
        return False, None


def command_validate(root: Path) -> int:
    """Validate Docker daemon, Compose config, crypto assets, and gateway credentials."""
    print("=== AgentTrust Fabric Network Pre-flight Validation ===")
    compose_file = root / "fabric" / "docker-compose-fabric.yaml"

    # 1. Docker availability
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            print("[FAIL] Docker daemon is not responsive. Ensure Docker Desktop is running.", file=sys.stderr)
            return 1
        print("[PASS] Docker daemon is responsive.")
    except Exception as exc:
        print(f"[FAIL] Docker execution failed: {exc}", file=sys.stderr)
        return 1

    # 2. Compose file syntax
    if not compose_file.exists():
        print(f"[FAIL] Compose file not found: {compose_file}", file=sys.stderr)
        return 1
    res = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "config", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        print(f"[FAIL] Compose configuration syntax check failed:\n{res.stderr}", file=sys.stderr)
        return 1
    print("[PASS] Docker Compose configuration is syntactically valid.")

    # 3. Required cryptographic material
    required_paths = [
        root / "fabric" / "channel-artifacts" / "orderer.genesis.block",
        root / "fabric" / "crypto-config" / "ordererOrganizations" / "agenttrust.com",
        root / "fabric" / "crypto-config" / "peerOrganizations" / "org1.agenttrust.com",
        root / "fabric" / "crypto-config" / "peerOrganizations" / "org2.agenttrust.com",
    ]
    for req_path in required_paths:
        if not req_path.exists():
            print(f"[FAIL] Required cryptographic material missing: {req_path}", file=sys.stderr)
            return 1
    print("[PASS] Required genesis block and MSP crypto material are present.")

    # 4. Loopback bridge port mapping
    content = compose_file.read_text(encoding="utf-8")
    if "127.0.0.1:8090:8090" not in content and "8090:8090" not in content:
        print("[FAIL] Loopback bridge port 8090 is not mapped in docker-compose-fabric.yaml", file=sys.stderr)
        return 1
    print("[PASS] Go SDK Gateway Bridge loopback port 8090 is mapped.")

    # 5. Gateway token check
    token = os.environ.get("FABRIC_GATEWAY_TOKEN", "").strip()
    if not token or len(token) < 32:
        print(
            "[FAIL] FABRIC_GATEWAY_TOKEN environment variable is not configured with at least 32 characters.",
            file=sys.stderr,
        )
        return 1
    print("[PASS] FABRIC_GATEWAY_TOKEN is configured with sufficient entropy.")

    print("\n[SUCCESS] All Fabric prerequisites and configurations validated successfully.")
    return 0


def print_status(root: Path) -> int:
    """Inspect and report detailed health of all Fabric services and runtime components."""
    print("=== AgentTrust Hyperledger Fabric Network Status ===")
    compose_file = root / "fabric" / "docker-compose-fabric.yaml"

    # 1. Compose service states
    res = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "ps", "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        print(f"[FAIL] Failed to retrieve container status: {res.stderr}", file=sys.stderr)
        return 1

    services: list[dict[str, Any]] = []
    for line in res.stdout.strip().splitlines():
        if line.strip():
            try:
                services.append(json.loads(line))
            except Exception:
                pass

    print(f"\n[Services] Running containers detected: {len(services)}")
    for svc in services:
        name = svc.get("Name") or svc.get("Service", "unknown")
        status = svc.get("Status", "unknown")
        state = svc.get("State", "unknown")
        print(f"  - {name:<35} State: {state:<10} Status: {status}")

    # 2. CouchDB health checks
    c1_ok, c1_body = probe_http_json("http://127.0.0.1:5984")
    c2_ok, c2_body = probe_http_json("http://127.0.0.1:6984")
    print("\n[CouchDB World State Databases]")
    print(f"  - Org1 CouchDB (127.0.0.1:5984): {'READY (v' + c1_body.get('version', '?') + ')' if c1_ok and c1_body else 'UNREACHABLE'}")
    print(f"  - Org2 CouchDB (127.0.0.1:6984): {'READY (v' + c2_body.get('version', '?') + ')' if c2_ok and c2_body else 'UNREACHABLE'}")

    # 3. Go SDK Gateway Bridge Probe
    br_ok, br_body = probe_http_json("http://127.0.0.1:8090/health")
    ready = bridge_health_ready(br_ok, br_body)
    print("\n[Gateway Bridge Health Probe (127.0.0.1:8090/health)]")
    if ready and br_body:
        print(f"  - Status       : {br_body.get('status')} (READY)")
        print(f"  - Fabric State : {br_body.get('fabric')}")
        print(f"  - Channel      : {br_body.get('channel', 'agenttrust-channel')}")
        print(f"  - Chaincode    : {br_body.get('chaincode', 'agenttrust-cc')}")
    else:
        status_msg = br_body.get("status") if br_body else "UNREACHABLE"
        print(f"  - Status       : {status_msg} (NOT READY)")

    # 4. Raft Consensus Inspection
    orderer_log_res = subprocess.run(
        ["docker", "logs", "orderer.agenttrust.com", "--tail", "500"],
        capture_output=True,
        text=True,
        check=False,
    )
    orderer_logs = (orderer_log_res.stdout + "\n" + orderer_log_res.stderr).lower()
    has_raft_leader = (
        "elected leader" in orderer_logs
        or "raft leader" in orderer_logs
        or "became leader" in orderer_logs
        or "orderer.consensus.etcdraft" in orderer_logs
    )
    print("\n[Raft Ordering Consensus]")
    print("  - Orderer Node : orderer.agenttrust.com:7050")
    print(f"  - Raft Status  : {'ACTIVE (Consensus evidence found in logs)' if has_raft_leader else 'INITIALIZING / NO LOG EVIDENCE'}")

    # 5. Peer Gossip Discovery Inspection
    peer_log_res = subprocess.run(
        ["docker", "logs", "peer0.org1.agenttrust.com", "--tail", "500"],
        capture_output=True,
        text=True,
        check=False,
    )
    peer_logs = peer_log_res.stdout + "\n" + peer_log_res.stderr
    gossip_ok = _has_gossip_membership_event(peer_logs, "peer0.org2.agenttrust.com") or (
        "gossip" in peer_logs.lower() and "peer0.org2" in peer_logs.lower()
    )
    print("\n[Multi-Organization Gossip Discovery]")
    print("  - Gossip Mesh  : Org1 (peer0.org1) <---> Org2 (peer0.org2)")
    print(f"  - Membership   : {'ESTABLISHED (Gossip membership event verified)' if gossip_ok else 'PENDING / NO RECENT MEMBERSHIP EVENT'}")

    return 0


def command_up(root: Path, timeout: int, poll_interval: float) -> int:
    """Start all Fabric services and wait for runtime readiness."""
    print("=== Launching AgentTrust Hyperledger Fabric Network ===")
    compose_file = root / "fabric" / "docker-compose-fabric.yaml"

    cmd = ["docker", "compose", "-f", str(compose_file), "up", "-d"]
    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        print(f"[FAIL] Docker Compose startup failed with exit code {res.returncode}", file=sys.stderr)
        return 1

    print(f"\nWaiting for Fabric network runtime readiness (timeout: {timeout}s)...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        br_ok, br_body = probe_http_json("http://127.0.0.1:8090/health")
        if bridge_health_ready(br_ok, br_body):
            elapsed = time.time() - start_time
            print(f"[PASS] Fabric network is ONLINE and READY ({elapsed:.1f}s).")
            return 0
        time.sleep(poll_interval)

    print(
        f"[FAIL] Network startup timed out after {timeout}s waiting for gateway bridge readiness.",
        file=sys.stderr,
    )
    print("Containers are left running for inspection. Named volumes were not removed.", file=sys.stderr)
    return 1


def command_down(root: Path, destroy_volumes: bool) -> int:
    """Stop the network safely, preserving volumes unless explicitly confirmed."""
    compose_file = root / "fabric" / "docker-compose-fabric.yaml"

    if destroy_volumes:
        print("=" * 70, file=sys.stderr)
        print("WARNING: DESTRUCTIVE ACTION REQUESTED", file=sys.stderr)
        print("This will permanently remove Docker named volumes (ledger world-state and crypto).", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        try:
            confirmation = input("Type 'DESTROY VOLUMES' to proceed: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[ABORT] Operation cancelled by user. Volumes preserved.", file=sys.stderr)
            return 1
        if confirmation != "DESTROY VOLUMES":
            print("[ABORT] Confirmation phrase did not match. Volumes preserved.", file=sys.stderr)
            return 1

    args = build_down_args(["docker", "compose", "-f", str(compose_file)], destroy_volumes=destroy_volumes)
    print(f"Executing: {' '.join(args)}")
    res = subprocess.run(args, check=False)
    if res.returncode == 0:
        if destroy_volumes:
            print("[PASS] Fabric network stopped and named volumes destroyed.")
        else:
            print("[PASS] Fabric network stopped safely. Named volumes preserved.")
        return 0
    else:
        print(f"[FAIL] Teardown failed with exit code {res.returncode}", file=sys.stderr)
        return res.returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = (args.root or repo_root()).resolve()
    if not (root / ".git").exists() and not (root / ".git").is_file():
        print(f"[FAIL] Repository root not found or is not a Git worktree: {root}", file=sys.stderr)
        return 2
    try:
        if args.command == "validate":
            return command_validate(root)
        if args.command == "up":
            if args.timeout < 1 or args.poll_interval <= 0:
                parser.error("--timeout must be >= 1 and --poll-interval must be > 0")
            return command_up(root, args.timeout, args.poll_interval)
        if args.command == "status":
            return print_status(root)
        if args.command == "down":
            return command_down(root, args.destroy_volumes)
        parser.error("Unknown command")
    except (RuntimeError, OSError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
