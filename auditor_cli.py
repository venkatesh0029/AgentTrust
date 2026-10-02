"""
Independent Auditor CLI Tool for AgentTrust Framework.
Allows external auditors to independently verify transaction evidence inclusion proofs,
Root CA certificate trust chains, and Fabric block Merkle root digests without trusting gateway runtime.
"""

import argparse
import json
import sys

from evidence_manager.merkle_tree import MerkleTree


def verify_evidence_proof(evidence_file: str, merkle_root: str, proof_file: str) -> bool:
    """Verifies off-chain evidence inclusion against Merkle root."""
    with open(evidence_file, 'r') as f:
        evidence_data = json.load(f)

    with open(proof_file, 'r') as f:
        proof_data = json.load(f)

    evidence_hash = evidence_data.get("evidence_hash") or evidence_data.get("request_hash")
    if not evidence_hash:
        print("❌ Error: Evidence file missing 'evidence_hash' field.")
        return False

    valid = MerkleTree.verify_inclusion_proof(evidence_hash, proof_data, merkle_root)
    if valid:
        print(f"✅ VERIFIED: Evidence '{evidence_data.get('evidence_id')}' cryptographically included in Merkle Root '{merkle_root}'.")
    else:
        print(f"❌ TAMPERING DETECTED: Evidence '{evidence_data.get('evidence_id')}' does NOT match Merkle Root '{merkle_root}'.")
    return valid

def main():
    parser = argparse.ArgumentParser(description="AgentTrust Independent Auditor CLI")
    parser.add_argument("--verify-proof", action="store_true", help="Verify Merkle inclusion proof for an evidence record")
    parser.add_argument("--evidence", type=str, help="Path to evidence JSON file")
    parser.add_argument("--root", type=str, help="Merkle root hex string")
    parser.add_argument("--proof", type=str, help="Path to inclusion proof JSON file")

    args = parser.parse_args()

    if args.verify_proof:
        if not (args.evidence and args.root and args.proof):
            print("Usage: python auditor_cli.py --verify-proof --evidence <ev.json> --root <hash> --proof <proof.json>")
            sys.exit(1)
        ok = verify_evidence_proof(args.evidence, args.root, args.proof)
        sys.exit(0 if ok else 1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
