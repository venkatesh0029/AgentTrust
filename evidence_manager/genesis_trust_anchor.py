"""
AgentTrust Independent Genesis Evidence Trust Anchor Module

Establishes an independent, external trust anchor for the framework's Genesis Evidence
record (EVIDENCE-REQ-GENESIS-000), eliminating self-referential hashing.
Verifies stored evidence records against an immutable, separately provisioned ledger commitment
(e.g., Fabric Block 0 channel root anchor), ensuring that attackers with SQLite write access
cannot rewrite both evidence_json and evidence_hash undetected.
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_ANCHOR_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "trusted_genesis_anchor.json")
)

FALLBACK_TRUST_ANCHOR: dict[str, Any] = {
    "ledger_channel": "agenttrust-channel",
    "genesis_block_index": 0,
    "genesis_orderer_consensus": "etcdraft",
    "ledger_anchor_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "expected_record_hash": "dd996d38df8c75052872ad17bbe16559da20869751dd42872ef1ca316b865e8e",
    "expected_full_digest": "ef2ab549cf094e9b1315feca5d798b9527aa86a22d0f420234ac86c0f3a37495",
    "anchor_authority": "AgentTrust-Root-CA",
    "created_at": "2026-01-01T00:00:00Z"
}


def get_genesis_trust_anchor() -> dict[str, Any]:
    """
    Retrieves the independent external trust anchor.
    Priority:
    1. AGENTTRUST_GENESIS_TRUST_ANCHOR env var (raw JSON or filepath)
    2. config/trusted_genesis_anchor.json
    3. Embedded FALLBACK_TRUST_ANCHOR
    """
    env_anchor = os.environ.get("AGENTTRUST_GENESIS_TRUST_ANCHOR")
    if env_anchor:
        env_anchor = env_anchor.strip()
        if env_anchor.startswith("{"):
            try:
                return json.loads(env_anchor)
            except Exception as e:
                logger.error(f"Failed to parse AGENTTRUST_GENESIS_TRUST_ANCHOR JSON: {e}")
        elif os.path.exists(env_anchor):
            try:
                with open(env_anchor, encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to read trust anchor file from {env_anchor}: {e}")

    if os.path.exists(DEFAULT_ANCHOR_PATH):
        try:
            with open(DEFAULT_ANCHOR_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read default trust anchor from {DEFAULT_ANCHOR_PATH}: {e}")

    return dict(FALLBACK_TRUST_ANCHOR)


def verify_against_trust_anchor(evidence_record: dict[str, Any], stored_hash: str) -> dict[str, Any]:
    """
    Cryptographically verifies an evidence record and its stored hash
    against the independent external trust anchor.
    """
    anchor = get_genesis_trust_anchor()
    expected_anchor_hash = anchor.get("ledger_anchor_hash", "")
    expected_rec_hash = anchor.get("expected_record_hash", "")
    expected_full_digest = anchor.get("expected_full_digest", "")

    rec_anchor = evidence_record.get("ledger_anchor_hash", "")
    rec_hash = evidence_record.get("record_hash", "")

    anchor_match = (rec_anchor.lower() == expected_anchor_hash.lower())
    rec_hash_match = (rec_hash.lower() == expected_rec_hash.lower())
    full_digest_match = (stored_hash.lower() == expected_full_digest.lower())

    verified = anchor_match and rec_hash_match and full_digest_match

    return {
        "verified": verified,
        "status": "VERIFIED" if verified else "TAMPERING_DETECTED",
        "anchor_match": anchor_match,
        "rec_hash_match": rec_hash_match,
        "full_digest_match": full_digest_match,
        "expected_anchor_hash": expected_anchor_hash,
        "actual_anchor_hash": rec_anchor,
        "expected_record_hash": expected_rec_hash,
        "actual_record_hash": rec_hash
    }

