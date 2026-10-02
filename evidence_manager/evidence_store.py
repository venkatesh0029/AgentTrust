import logging
from typing import Any

from evidence_manager.hash_manager import HashManager

logger = logging.getLogger(__name__)


class EvidencePersistenceError(Exception):
    """Raised when evidence fails to persist to persistent storage engine."""
    pass


class EvidenceStore:
    """Off-Chain Storage engine for detailed sensitive evidence records."""

    def __init__(self, db_path: str = "agenttrust_persistent.db"):
        self.db_path = db_path
        self._store: dict[str, dict[str, Any]] = {}
        self._load_from_storage()

    def _load_from_storage(self) -> None:
        try:
            from fabric.persistent_db import PersistentStorageEngine
            records = PersistentStorageEngine(self.db_path).list_evidence()
            for r in records:
                ev_id = r.get("evidence_id")
                if ev_id:
                    self._store[ev_id] = r
        except Exception as exc:
            logger.debug(f"Could not load evidence from persistent storage: {exc}")

    def save_evidence(self, evidence_record: dict[str, Any]) -> str:
        """
        Saves evidence off-chain and returns calculated SHA-256 hash.
        Fails closed by raising EvidencePersistenceError if persistence fails.
        """
        evidence_id = evidence_record["evidence_id"]
        self._store[evidence_id] = evidence_record
        ev_hash = HashManager.calculate_evidence_hash(evidence_record)
        try:
            from fabric.persistent_db import PersistentStorageEngine
            PersistentStorageEngine(self.db_path).save_evidence(
                evidence_id=evidence_id,
                request_id=evidence_record.get("request_id", ""),
                agent_id=evidence_record.get("agent_id", ""),
                evidence_hash=ev_hash,
                evidence_data=evidence_record
            )
        except Exception as exc:
            logger.exception("Evidence persistence failed")
            raise EvidencePersistenceError(f"Evidence persistence failed: {exc}") from exc
        return ev_hash


    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        return self._store.get(evidence_id)

    def get_evidence_by_request_id(self, request_id: str) -> dict[str, Any] | None:
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
