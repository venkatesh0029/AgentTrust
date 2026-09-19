from typing import Dict, Any, Optional
from evidence_manager.hash_manager import HashManager

class EvidenceStore:
    """Off-Chain Storage engine for detailed sensitive evidence records."""

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}

    def save_evidence(self, evidence_record: Dict[str, Any]) -> str:
        """
        Saves evidence off-chain and returns calculated SHA-256 hash.
        """
        evidence_id = evidence_record["evidence_id"]
        self._store[evidence_id] = evidence_record
        return HashManager.calculate_evidence_hash(evidence_record)

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        return self._store.get(evidence_id)

    def get_evidence_by_request_id(self, request_id: str) -> Optional[Dict[str, Any]]:
        for ev in self._store.values():
            if ev.get("request_id") == request_id:
                return ev
        return None

    def simulate_tamper(self, evidence_id: str, field_name: str, new_value: Any) -> bool:
        """
        Simulates malicious tampering with off-chain evidence for security demonstration!
        """
        evidence = self.get_evidence(evidence_id)
        if not evidence:
            return False

        if field_name == "amount" and "input" in evidence and isinstance(evidence["input"], dict):
            evidence["input"]["amount"] = new_value
        else:
            evidence[field_name] = new_value

        self._store[evidence_id] = evidence
        return True
