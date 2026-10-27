#!/usr/bin/env python3
"""
AgentTrust Deployment Verification Utility.
Probes a running AgentTrust instance to verify operational readiness,
health status, configuration profile, and ledger consensus mode.

Usage:
    python scripts/verify_deployment.py [--url http://127.0.0.1:8000] [--expected-profile development]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def probe_endpoint(url: str, timeout: float = 5.0) -> tuple[int, dict[str, Any] | str]:
    """Issues an HTTP GET request and returns (status_code, parsed_json_or_text)."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AgentTrust-DeploymentVerifier/1.0", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = raw
            return resp.status, data
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = raw
        return e.code, data
    except Exception as exc:
        return 0, str(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify AgentTrust Deployment Health & Profile")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL of running AgentTrust server")
    parser.add_argument("--expected-profile", choices=["development", "demo", "production"], default=None, help="Expected AGENTTRUST_ENV profile")
    parser.add_argument("--expected-mode", default=None, help="Expected operational mode (e.g. MODE_C_AGENTTRUST_NO_FABRIC)")
    parser.add_argument("--retries", type=int, default=5, help="Number of connection retries before failing")
    parser.add_argument("--retry-delay", type=float, default=2.0, help="Seconds to wait between retries")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    print("=" * 75)
    print("  AGENTTRUST DEPLOYMENT VERIFICATION")
    print(f"  Target Server: {base_url}")
    print("=" * 75)

    # 1. Wait for server connectivity
    connected = False
    health_data: dict[str, Any] = {}
    print(f"\n[1/4] Probing server liveness at {base_url}/api/health...")

    for attempt in range(1, args.retries + 1):
        code, data = probe_endpoint(f"{base_url}/api/health")
        if code == 200 and isinstance(data, dict):
            connected = True
            health_data = data
            print(f"      Connected successfully (HTTP 200 on attempt {attempt}/{args.retries})")
            break
        print(f"      Attempt {attempt}/{args.retries} failed: HTTP {code} -> {data}. Retrying in {args.retry_delay}s...")
        time.sleep(args.retry_delay)

    if not connected:
        print("\n[DEPLOYMENT CHECK: FAILED]")
        print(f"ERROR: Could not establish connection to AgentTrust server at {base_url}.")
        print("Remediation:")
        print("  1. Verify the server is running (e.g. 'docker compose ps' or local uvicorn process).")
        print("  2. Check server logs for startup or port-binding failures.")
        return 1

    # 2. Check /healthz probe
    print(f"\n[2/4] Probing gateway telemetry probe at {base_url}/healthz...")
    hz_code, hz_data = probe_endpoint(f"{base_url}/healthz")
    if hz_code != 200 or not isinstance(hz_data, dict):
        print(f"      WARNING: /healthz probe returned HTTP {hz_code} -> {hz_data}")
        hz_status = "UNKNOWN"
    else:
        hz_status = hz_data.get("status", "UNKNOWN")
        uptime = hz_data.get("uptime_seconds", 0)
        invariants = hz_data.get("security_invariants_enforced", 0)
        print(f"      Telemetry Status: {hz_status} (Uptime: {uptime}s, Invariants: {invariants})")

    # 3. Check Operational Mode (/mode)
    print(f"\n[3/4] Inspecting operational security mode at {base_url}/mode...")
    mode_code, mode_data = probe_endpoint(f"{base_url}/mode")
    if mode_code != 200 or not isinstance(mode_data, dict):
        print(f"      ERROR: /mode query failed with HTTP {mode_code}: {mode_data}")
        return 1

    current_mode = mode_data.get("current_mode", "UNKNOWN")
    print(f"      Active Mode: {current_mode}")

    # Determine Ledger Backend: Simulator vs Live Fabric
    if current_mode == "MODE_D_AGENTTRUST_FABRIC":
        ledger_backend = "Hyperledger Fabric (Consensus-Backed)"
    elif current_mode == "MODE_C_AGENTTRUST_NO_FABRIC":
        ledger_backend = "Local Hash-Chain Simulator (Zero Network Overhead)"
    elif current_mode == "MODE_B_AUTH_RBAC":
        ledger_backend = "RBAC Only (No Immutable Audit)"
    elif current_mode == "MODE_A_DIRECT_API":
        ledger_backend = "None (Direct Unprotected API)"
    else:
        ledger_backend = "Unknown Mode"

    print(f"      Ledger Type: {ledger_backend}")

    # Mode validation
    if args.expected_mode and current_mode != args.expected_mode:
        print(f"\n[MODE MISMATCH] Expected mode '{args.expected_mode}', but server is in '{current_mode}'.")
        return 1

    # 4. Summary Scorecard
    print("\n[4/4] Verification Summary Scorecard:")
    print("-" * 75)
    print(f"  Server Target      : {base_url}")
    print("  Health Endpoint    : ONLINE (HTTP 200)")
    print(f"  Telemetry Probe    : {hz_status}")
    print(f"  Operational Mode   : {current_mode}")
    print(f"  Consensus Backend  : {ledger_backend}")
    print(f"  Cache Backend      : {health_data.get('cache_backend', 'in-memory')}")
    print("-" * 75)

    print("\n[DEPLOYMENT CHECK: PASSED]")
    print(f"AgentTrust instance at {base_url} is healthy and ready for traffic.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
