"""
AgentTrust Cryptographically Authenticated Genesis Evidence Trust Anchor Module

Establishes an independently signed, externally authenticated trust anchor for the framework's
Genesis Evidence record (EVIDENCE-REQ-GENESIS-000), eliminating self-referential hashing.
Verifies stored evidence records against an immutable, digitally signed ledger commitment
manifest derived from the canonical Hyperledger Fabric Block 0 configuration.

Trust Architecture:
1. Root Authority Public Key: Stored in config/genesis_anchor_authority.pub and compiled into code.
2. Signed Trust Manifest: config/trusted_genesis_anchor.json contains Block 0 commitment and
   digital signature from the Root Authority.
3. Startup Verification: Fails closed if the manifest signature is invalid, missing, or forged.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_ANCHOR_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "trusted_genesis_anchor.json")
)

DEFAULT_PUBKEY_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "genesis_anchor_authority.pub")
)

DEFAULT_AUTHORITY_PUBKEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2R8muKAdPA5ASUb8EAGF\n"
    "3WWglp9R/3DGCbz0U14wqfvyaQQ5Ks2+uzO3rdbie9iSVyRpTFTS5hw/lS7mqmFZ\n"
    "rkS6kqzR2Os8M+6Zj6OAiCy8daMfiKXOCBcF57H1RAb8IGTkyJ4DN0lrWvxDkz/H\n"
    "cLdgSYTCuS1PCcXmj6i0w+FHiGFmGIScCYXpbS3IhZR2N5xeZ+aiEZEj7iYdnPVa\n"
    "1JW2pdO84KadVQ0YVX8Z/+kmS168bu/90Y1LdMaOKlcLRGHJYb9PpsN6NJi82fK3\n"
    "OBFULl6pGME5R1/SPbiQxT3YSbTClap4rY4bMpTAqW2MP3Sh3IUTTtqJDhSQ/7/J\n"
    "7QIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)

# Canonical Fabric Block 0 commitment hash derived from TwoOrgsOrdererGenesis configuration
CANONICAL_FABRIC_BLOCK0_HASH = "da91bd496a33e8432fba702761b0f614d5193aba7628300cb04be281be5d7e90"

FALLBACK_TRUST_ANCHOR: dict[str, Any] = {
    "manifest_version": "1.0",
    "ledger_channel": "agenttrust-channel",
    "genesis_block_index": 0,
    "genesis_orderer_consensus": "etcdraft",
    "ledger_anchor_hash": CANONICAL_FABRIC_BLOCK0_HASH,
    "expected_record_hash": "a48248389eea4c5d1f471b379c7272c23bbaeabbb46f79a6c5902bfca2a82a32",
    "expected_full_digest": "6d66f9bec6f1ae045baf4dce9abac3adcfe3882cee0189abe21920c13cdfd9b7",
    "anchor_authority": "AgentTrust-Root-CA",
    "created_at": "2026-01-01T00:00:00Z",
    "signature": (
        "hBFlxwvtAxopZ++2SdCEQ4u04vsENJZrqF5JJuNNTbnLbn+xGN+H1bohfx5LXXCbk/ZRHksdDuTXjWrhQMZbIOAuxd09rITf0DbfMpX1WA"
        "oflz3SmPhkluP1qQy0gXi4pljsbznBXPK63C5P01BQmLtTcetXSbGhHepLb9r4Hv/PEO7guiL/2LW0jUsaaLPnHknJlQxcwM+uliA6v84x"
        "x/amNYQ8D+7Ol90k8oeffEYGAkHSmdaL5nkQKm0/ba+F4EktGL/BR6xF+5H38cqqYNHsUrAPMNx3le6Lbfn63V4C5OkzRWsYPvI6sf4rAf"
        "6+G4PcClOtsFyjLdreJW3T7g=="
    )
}


def get_authority_public_key() -> str:
    """Returns the trusted Root Authority public key."""
    env_pub = os.environ.get("AGENTTRUST_GENESIS_AUTHORITY_PUBKEY")
    if env_pub and env_pub.strip().startswith("-----BEGIN"):
        return env_pub.strip()

    if os.path.exists(DEFAULT_PUBKEY_PATH):
        try:
            with open(DEFAULT_PUBKEY_PATH, encoding="utf-8") as f:
                content = f.read().strip()
                if content.startswith("-----BEGIN"):
                    return content
        except Exception as e:
            logger.warning(f"Could not read authority public key from {DEFAULT_PUBKEY_PATH}: {e}")

    return DEFAULT_AUTHORITY_PUBKEY


def verify_manifest_authenticity(manifest: dict[str, Any]) -> tuple[bool, str]:
    """
    Cryptographically verifies the digital signature on the genesis trust anchor manifest.
    Returns (True, 'AUTHENTIC') or (False, reason).
    """
    if not isinstance(manifest, dict):
        return False, "MANIFEST_INVALID_FORMAT: Manifest must be a JSON object"

    signature = manifest.get("signature")
    if not signature:
        return False, "MANIFEST_SIGNATURE_MISSING: Genesis trust anchor manifest lacks digital signature"

    payload_to_verify = {k: v for k, v in manifest.items() if k != "signature" and not k.startswith("_")}
    pubkey = get_authority_public_key()

    try:
        from identity_manager.signature_manager import SignatureManager
        valid = SignatureManager.verify_signature(payload_to_verify, signature, pubkey)
        if not valid:
            return False, "MANIFEST_SIGNATURE_INVALID: Digital signature verification failed against trusted Root CA key"
        return True, "AUTHENTIC"
    except Exception as ex:
        return False, f"MANIFEST_VERIFICATION_ERROR: {ex}"


def get_genesis_trust_anchor() -> dict[str, Any]:
    """
    Retrieves and authenticates the independent external trust anchor manifest.
    Priority:
    1. AGENTTRUST_GENESIS_TRUST_ANCHOR env var (raw JSON or filepath)
    2. config/trusted_genesis_anchor.json
    3. Embedded FALLBACK_TRUST_ANCHOR
    Fails closed if the retrieved anchor lacks a valid cryptographic signature.
    """
    candidate: dict[str, Any] | None = None

    env_anchor = os.environ.get("AGENTTRUST_GENESIS_TRUST_ANCHOR")
    if env_anchor:
        env_anchor = env_anchor.strip()
        if env_anchor.startswith("{"):
            try:
                candidate = json.loads(env_anchor)
            except Exception as e:
                logger.error(f"Failed to parse AGENTTRUST_GENESIS_TRUST_ANCHOR JSON: {e}")
        elif os.path.exists(env_anchor):
            try:
                with open(env_anchor, encoding="utf-8") as f:
                    candidate = json.load(f)
            except Exception as e:
                logger.error(f"Failed to read trust anchor file from {env_anchor}: {e}")

    if candidate is None and os.path.exists(DEFAULT_ANCHOR_PATH):
        try:
            with open(DEFAULT_ANCHOR_PATH, encoding="utf-8") as f:
                candidate = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read default trust anchor from {DEFAULT_ANCHOR_PATH}: {e}")

    if candidate is None:
        candidate = dict(FALLBACK_TRUST_ANCHOR)

    # Verify cryptographic signature of candidate manifest
    auth_ok, auth_reason = verify_manifest_authenticity(candidate)
    if not auth_ok:
        logger.critical(f"GENESIS_TRUST_ANCHOR_AUTHENTICATION_FAILED: {auth_reason}")
        # Return candidate marked unauthenticated so verify_against_trust_anchor fails closed
        candidate["_manifest_authenticated"] = False
        candidate["_authentication_error"] = auth_reason
        return candidate

    candidate["_manifest_authenticated"] = True
    return candidate


def verify_against_trust_anchor(evidence_record: dict[str, Any], stored_hash: str) -> dict[str, Any]:
    """
    Cryptographically verifies an evidence record and its stored hash
    against the authenticated independent external trust anchor.
    """
    anchor = get_genesis_trust_anchor()

    # 1. Manifest Authenticity Check
    if not anchor.get("_manifest_authenticated", True):
        auth_err = anchor.get("_authentication_error", "MANIFEST_AUTHENTICATION_FAILED")
        return {
            "verified": False,
            "status": "MANIFEST_AUTHENTICATION_FAILED",
            "reason": auth_err,
            "anchor_match": False,
            "rec_hash_match": False,
            "full_digest_match": False,
            "signature_authenticated": False
        }

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
        "signature_authenticated": True,
        "anchor_match": anchor_match,
        "rec_hash_match": rec_hash_match,
        "full_digest_match": full_digest_match,
        "expected_anchor_hash": expected_anchor_hash,
        "actual_anchor_hash": rec_anchor,
        "expected_record_hash": expected_rec_hash,
        "actual_record_hash": rec_hash,
        "expected_full_digest": expected_full_digest,
        "actual_full_digest": stored_hash
    }
