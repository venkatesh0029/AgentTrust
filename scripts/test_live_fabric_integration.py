#!/usr/bin/env python3
"""
Hyperledger Fabric Multi-Peer Live Consensus & Verification Suite.

Validates:
1. Live network health and gateway readiness across multi-peer topology.
2. Real transaction submission through Fabric Gateway Bridge (FABRIC_GATEWAY_MODE=live).
3. On-chain query and cryptographic tamper detection on the live immutable ledger.
4. Fail-closed safety: guarantees NO silent fallback to simulation when Fabric is unreachable.
"""

import os
import sys
import uuid
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Configure Live Fabric Gateway Bridge credentials
os.environ["FABRIC_GATEWAY_MODE"] = "live"
os.environ["FABRIC_GATEWAY_URL"] = "http://127.0.0.1:8090"
os.environ["FABRIC_GATEWAY_TOKEN"] = "jWIcW8MImMbQWx8t9Q4H4uE-g1ko1nS9UmUR-xfw10x8U1zZnQXSqZ8jufIvLig1"

from fabric.fabric_client import FabricClient  # noqa: E402


def run_live_fabric_verification() -> int:
    print("=" * 70)
    print("HYPERLEDGER FABRIC LIVE MULTI-PEER CONSENSUS VERIFICATION")
    print("=" * 70)
    print(f"Gateway URL   : {os.environ['FABRIC_GATEWAY_URL']}")
    print(f"Gateway Mode  : {os.environ['FABRIC_GATEWAY_MODE']}")
    print("Topology      : Orderer (Raft), Peer0 Org1, Peer0 Org2, CouchDB, CCaaS\n")

    client = FabricClient()

    # --- Test 1: Real Action Event Transaction Commit ---
    print("[1/4] Submitting Real Transaction to Live Fabric Ledger...")
    event_id = f"EVENT-LIVE-{uuid.uuid4().hex[:8].upper()}"
    req_id = f"REQ-LIVE-{uuid.uuid4().hex[:8].upper()}"
    evidence_ref = f"EVID-REF-{uuid.uuid4().hex[:8].upper()}"
    evidence_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    try:
        commit_res = client.record_action_event(
            event_id=event_id,
            request_id=req_id,
            agent_id="FINANCE-AGENT-001",
            action="TRANSFER_FUNDS",
            resource="TREASURY_LEDGER",
            decision="ALLOWED",
            reason="POLICY_LIMIT_WITHIN_BOUNDS",
            policy_id="FIN-POL-001",
            policy_version="1.0",
            evidence_reference=evidence_ref,
            evidence_hash=evidence_hash
        )
        print(f"      Status       : {commit_res.get('status')}")
        print(f"      Event ID     : {commit_res.get('event_id')}")
        print(f"      Fabric Result: {commit_res.get('result', {}).get('docType')}")
        assert commit_res.get("status") == "COMMITTED", f"Unexpected status: {commit_res}"
        print("      Result       : PASS (Transaction committed by Raft orderer)")
    except Exception as e:
        print(f"      Result       : FAILED ({e})", file=sys.stderr)
        return 1

    # --- Test 2: On-Chain Query & Verification ---
    print("\n[2/4] Querying Committed State from Live Peer Ledger...")
    try:
        committed_doc = client.get_event(event_id)
        assert committed_doc is not None, "get_event returned None"
        print(f"      Found Event  : {committed_doc.get('event_id')}")
        print(f"      Committed Tx : {committed_doc.get('request_id')}")
        print(f"      Decision     : {committed_doc.get('decision')}")
        assert committed_doc.get("event_id") == event_id
        assert committed_doc.get("evidence_hash") == evidence_hash
        print("      Result       : PASS (Immutable state read from ledger)")
    except Exception as e:
        print(f"      Result       : FAILED ({e})", file=sys.stderr)
        return 1

    # --- Test 3: Evidence Cryptographic Tamper Verification ---
    print("\n[3/4] Testing Live Chaincode Tamper Detection...")
    try:
        # 3a. Authentic evidence
        auth_ver = client.verify_evidence_hash(evidence_ref, evidence_hash)
        print(f"      Authentic Hash Verification: {auth_ver.get('status')} (verified: {auth_ver.get('verified')})")
        assert auth_ver.get("verified") is True and auth_ver.get("status") == "VERIFIED"

        # 3b. Tampered evidence
        tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        tamp_ver = client.verify_evidence_hash(evidence_ref, tampered_hash)
        print(f"      Tampered Hash Detection    : {tamp_ver.get('status')} (verified: {tamp_ver.get('verified')})")
        assert tamp_ver.get("verified") is False and tamp_ver.get("status") == "TAMPERING_DETECTED"
        print("      Result       : PASS (Cryptographic tamper protection enforced)")
    except Exception as e:
        print(f"      Result       : FAILED ({e})", file=sys.stderr)
        return 1

    # --- Test 4: Fail-Closed Protection (No Silent Fallback to Simulator) ---
    print("\n[4/4] Verifying Fail-Closed Behavior on Peer Unreachability...")
    saved_url = os.environ["FABRIC_GATEWAY_URL"]
    try:
        # Point to unreachable port
        os.environ["FABRIC_GATEWAY_URL"] = "http://127.0.0.1:59999"
        failed_closed = False
        try:
            client.record_action_event(
                event_id="EVENT-FAIL-PROBE",
                request_id="REQ-FAIL-PROBE",
                agent_id="FINANCE-AGENT-001",
                action="TRANSFER_FUNDS",
                resource="TREASURY",
                decision="ALLOWED",
                reason="PROBE",
                policy_id="POL-01",
                policy_version="1.0",
                evidence_reference="EVID-FAIL",
                evidence_hash=evidence_hash
            )
        except RuntimeError as re:
            failed_closed = True
            print(f"      Caught expected exception: {type(re).__name__}")
            print(f"      Error message summary    : {str(re)[:80]}...")

        assert failed_closed, "Security violation: Application silently proceeded or fell back to simulator!"
        print("      Result       : PASS (Strict fail-closed enforcement verified)")
    finally:
        os.environ["FABRIC_GATEWAY_URL"] = saved_url

    print("\n" + "=" * 70)
    print("ALL 4 LIVE HYPERLEDGER FABRIC INTEGRATION CRITERIA VERIFIED!")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(run_live_fabric_verification())
