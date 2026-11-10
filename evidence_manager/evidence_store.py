import logging
import os
from typing import Any

from database_config import resolve_database_path
from evidence_manager.hash_manager import HashManager

logger = logging.getLogger(__name__)


class EvidencePersistenceError(Exception):
    """Raised when evidence fails to persist to persistent storage engine."""


class EvidenceStore:
    """Off-Chain Storage engine for detailed sensitive evidence records."""

    def __init__(self, db_path: str | None = None, fail_closed: bool = False):
        self.db_path = resolve_database_path(db_path)
        self.fail_closed = fail_closed
        self._store: dict[str, dict[str, Any]] = {}
        self._ensure_genesis_record(fail_closed=fail_closed)
        self._load_from_storage()
        self._ensure_genesis_record(fail_closed=fail_closed)

    def _ensure_genesis_record(self, fail_closed: bool = False) -> None:
        is_strict = (
            fail_closed
            or self.fail_closed
            or os.environ.get("STRICT_PERSISTENCE", "false").lower() in ("true", "1")
            or os.environ.get("AGENTTRUST_PRODUCTION", "false").lower() in ("true", "1")
        )

        if "EVIDENCE-REQ-GENESIS-000" not in self._store:
            genesis_input = {
                "system": "AgentTrust Framework",
                "channel": "agenttrust-channel",
                "consensus": "Fabric Permissioned Ledger Simulator",
                "genesis_block": 0,
                "status": "INITIALIZED"
            }
            input_digest = HashManager.calculate_evidence_hash(genesis_input)

            genesis_rec = {
                "evidence_schema_version": "2.0",
                "evidence_id": "EVIDENCE-REQ-GENESIS-000",
                "request_id": "REQ-GENESIS-000",
                "agent_id": "SYSTEM",
                "certificate_fingerprint": "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "LEDGER_GENESIS_INITIALIZE",
                "resource": "SYSTEM_CORE",
                "input": genesis_input,
                "input_hash": input_digest,
                "output_hash": input_digest,
                "decision": "INITIALIZED",
                "decision_reason": "LEDGER_GENESIS_BOOTSTRAP",
                "policy_id": "SYSTEM-GENESIS-POL",
                "policy_version": "1.0",
                "agent_version": "1.0",
                "model_version": "AgentTrust-Core-v2.0",
                "tool_version": "AgentTrust-Gateway-v1.0",
                "nonce": "N-GENESIS-000",
                "approval_reference": None,
                "api_execution_result": "INITIALIZED",
                "error_details": None,
                "timestamp": "2026-01-01T00:00:00Z",
                "execution_trace": {"mode": "GENESIS_BOOTSTRAP", "record_type": "GENESIS_SENTINEL"},
                "risk_score": 0.0,
                "risk_level": "LOW",
                "risk_factors": [],
                "matched_rules": ["genesis_state_initialization"],
                "sequence_number": 0,
                "previous_record_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "record_hash": ""
            }
            from evidence_manager.genesis_trust_anchor import (
                get_genesis_trust_anchor,
                verify_against_trust_anchor,
            )
            anchor = get_genesis_trust_anchor()
            genesis_rec["ledger_anchor_hash"] = anchor["ledger_anchor_hash"]
            rec_hash = HashManager.calculate_evidence_hash(genesis_rec)
            genesis_rec["record_hash"] = rec_hash
            full_digest = HashManager.calculate_evidence_hash(genesis_rec)
            self._store["EVIDENCE-REQ-GENESIS-000"] = genesis_rec

            try:
                from fabric.persistent_db import PersistentStorageEngine
                pe = PersistentStorageEngine(self.db_path)
                existing = pe.get_evidence("EVIDENCE-REQ-GENESIS-000")
                if not existing:
                    pe.save_evidence(
                        evidence_id="EVIDENCE-REQ-GENESIS-000",
                        request_id="REQ-GENESIS-000",
                        agent_id="SYSTEM",
                        evidence_hash=full_digest,
                        evidence_data=genesis_rec
                    )
                else:
                    existing_clean = {k: v for k, v in existing.items() if k != "_stored_hash"}
                    expected_hash = existing.get("_stored_hash") or existing.get("record_hash") or ""

                    # 1. Local SQLite integrity check (detects single-field corruption)
                    check = HashManager.verify_integrity(existing_clean, expected_hash)
                    if not check.get("verified"):
                        logger.error(
                            f"CORRUPTED_OR_TAMPERED_GENESIS_EVIDENCE: Stored {expected_hash} != Recalculated {check.get('recalculated_hash')}"
                        )
                        if is_strict:
                            raise EvidencePersistenceError("CORRUPTED_OR_TAMPERED_GENESIS_EVIDENCE: Stored genesis record does not match trusted digest")

                    # 2. Independent External Trust Anchor Check (detects attackers with write access to both JSON and hash)
                    anchor_check = verify_against_trust_anchor(existing_clean, expected_hash)
                    if not anchor_check.get("verified"):
                        logger.error(
                            f"INDEPENDENT_TRUST_ANCHOR_VERIFICATION_FAILED: "
                            f"Anchor match={anchor_check['anchor_match']}, RecHash match={anchor_check['rec_hash_match']}, FullDigest match={anchor_check['full_digest_match']}"
                        )
                        if is_strict:
                            raise EvidencePersistenceError(
                                "INDEPENDENT_TRUST_ANCHOR_VERIFICATION_FAILED: stored genesis record or hash does not match independent external trust anchor"
                            )

                    self._store["EVIDENCE-REQ-GENESIS-000"] = existing_clean
            except Exception as exc:
                logger.error(f"Failed to persist or verify genesis evidence record in store ({self.db_path}): {exc}")
                if is_strict:
                    raise EvidencePersistenceError(f"Genesis evidence persistence or verification failed: {exc}") from exc

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
        if evidence_id in ("REQ-GENESIS-000", "EVIDENCE-REQ-GENESIS-000"):
            self._ensure_genesis_record()
            return self._store.get("EVIDENCE-REQ-GENESIS-000")

        if evidence_id in self._store:
            return self._store[evidence_id]
        # Direct lookup by request_id
        for ev in self._store.values():
            if ev.get("request_id") == evidence_id:
                return ev
        # Prepend EVIDENCE- if missing
        if not evidence_id.startswith("EVIDENCE-"):
            prefixed = f"EVIDENCE-{evidence_id}"
            if prefixed in self._store:
                return self._store[prefixed]
        # Strip EVIDENCE- if present
        else:
            stripped = evidence_id[len("EVIDENCE-"):]
            for ev in self._store.values():
                if ev.get("request_id") == stripped:
                    return ev
        return None

    def get_evidence_by_request_id(self, request_id: str) -> dict[str, Any] | None:
        if request_id in ("REQ-GENESIS-000", "EVIDENCE-REQ-GENESIS-000"):
            self._ensure_genesis_record()
            return self._store.get("EVIDENCE-REQ-GENESIS-000")

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
