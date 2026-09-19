import json
import hashlib
from typing import Dict, Any

class HashManager:
    """
    Computes SHA-256 hashes of canonical evidence records and verifies data integrity.
    """

    @staticmethod
    def canonical_json_bytes(evidence_record: Dict[str, Any]) -> bytes:
        """Converts evidence dict to deterministic sorted JSON bytes."""
        json_str = json.dumps(evidence_record, sort_keys=True, separators=(',', ':'))
        return json_str.encode('utf-8')

    @classmethod
    def calculate_evidence_hash(cls, evidence_record: Dict[str, Any]) -> str:
        """Calculates hex SHA-256 hash string of evidence record."""
        data_bytes = cls.canonical_json_bytes(evidence_record)
        return hashlib.sha256(data_bytes).hexdigest()

    @classmethod
    def verify_integrity(cls, current_evidence: Dict[str, Any], expected_hash: str) -> Dict[str, Any]:
        """
        Re-computes SHA-256 hash of current evidence and compares with stored on-chain hash.
        Returns verification detail dictionary.
        """
        recalculated_hash = cls.calculate_evidence_hash(current_evidence)
        is_match = (recalculated_hash.lower() == expected_hash.lower())

        return {
            "verified": is_match,
            "stored_hash": expected_hash,
            "recalculated_hash": recalculated_hash,
            "status": "VERIFIED" if is_match else "TAMPERING_DETECTED"
        }
