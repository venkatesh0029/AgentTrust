import datetime
import hashlib
import json
import threading
from typing import Any


class AuditChainRecord:
    """Canonical Immutable Audit Event record in the hash chain."""

    def __init__(
        self,
        event_id: str,
        sequence_number: int,
        event_type: str,
        request_id: str,
        agent_id: str,
        request_hash: str,
        risk_score: float,
        policy_version: str,
        decision: str,
        execution_result: str,
        previous_record_hash: str,
        timestamp: str | None = None
    ):
        self.event_id = event_id
        self.sequence_number = sequence_number
        self.event_type = event_type
        self.request_id = request_id
        self.agent_id = agent_id
        self.request_hash = request_hash
        self.risk_score = risk_score
        self.policy_version = policy_version
        self.decision = decision
        self.execution_result = execution_result
        self.previous_record_hash = previous_record_hash
        self.timestamp = timestamp or datetime.datetime.now(datetime.UTC).isoformat()
        self.record_hash = self.calculate_record_hash()

    def calculate_record_hash(self) -> str:
        data = {
            "event_id": self.event_id,
            "sequence_number": self.sequence_number,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "request_hash": self.request_hash,
            "risk_score": self.risk_score,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "execution_result": self.execution_result,
            "previous_record_hash": self.previous_record_hash,
            "timestamp": self.timestamp
        }
        json_bytes = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(json_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "sequence_number": self.sequence_number,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "request_hash": self.request_hash,
            "risk_score": self.risk_score,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "execution_result": self.execution_result,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
            "event_hash": self.record_hash,
            "timestamp": self.timestamp
        }

from database_config import resolve_database_path


class AuditPersistenceError(RuntimeError):
    """Raised when durable persistence of an audit block fails."""


class AuditChainWriter:
    """
    Concurrency-Safe Atomic Hash Chain Audit Logger.
    Enforces thread locking, strict sequence numbering, durable persistence,
    and automatic restart rehydration with tamper detection.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, db_path: str | None = None, auto_rehydrate: bool = False):
        self._db_path = resolve_database_path(db_path) if db_path is not None else None
        self._records: list[AuditChainRecord] = []
        self._lock = threading.RLock()
        self._current_sequence = 0
        if self._db_path is not None:
            if auto_rehydrate:
                self.rehydrate_from_db(self._db_path)
            else:
                self._sync_records_from_db()
            if not self._records:
                self._append_genesis_record()
        else:
            # Initialize Genesis Record in-memory
            self._append_genesis_record()

    def _append_genesis_record(self):
        genesis_rec = AuditChainRecord(
            event_id="EV-GENESIS-000",
            sequence_number=0,
            event_type="GENESIS",
            request_id="REQ-GENESIS-000",
            agent_id="SYSTEM",
            request_hash=self.GENESIS_HASH,
            risk_score=0.0,
            policy_version="1.0",
            decision="INITIALIZED",
            execution_result="SUCCESS",
            previous_record_hash=self.GENESIS_HASH
        )
        self._records.append(genesis_rec)

    def rehydrate_from_db(self, db_path: str | None = None) -> dict[str, Any]:
        """
        Rehydrates in-memory audit chain from persisted SQLite records.
        Validates sequence numbers, previous hashes, and cryptographic hashes.
        """
        with self._lock:
            resolved_path = resolve_database_path(db_path or self._db_path) if (db_path or self._db_path) else None
            self._db_path = resolved_path
            if not resolved_path:
                self._records = []
                self._current_sequence = 0
                self._append_genesis_record()
                return {"rehydrated": False, "reason": "NO_DATABASE_CONFIGURED"}

            self._sync_records_from_db()
            if self._records:
                integrity_check = self._verify_records(self._records)
                if not integrity_check.get("valid"):
                    self._rehydration_error = integrity_check.get("reason", "Chain tampering detected during rehydration")
                    return {"rehydrated": False, "error": self._rehydration_error}
                return {"rehydrated": True, "count": len(self._records), "latest_sequence": self._current_sequence}
            else:
                self._records = []
                self._current_sequence = 0
                self._append_genesis_record()
                try:
                    from fabric.persistent_db import PersistentStorageEngine
                    storage = PersistentStorageEngine(resolved_path)
                    gen_rec = self._records[0]
                    storage.save_block(
                        previous_hash=gen_rec.previous_record_hash,
                        block_hash=gen_rec.record_hash,
                        tx_count=1,
                        block_data=gen_rec.to_dict(),
                        timestamp=gen_rec.timestamp
                    )
                except Exception:
                    pass
                return {"rehydrated": True, "count": 1, "latest_sequence": 0}

    def _sync_records_from_db(self) -> None:
        """Synchronizes in-memory chain from database records committed across workers."""
        if not self._db_path:
            return
        from fabric.persistent_db import PersistentStorageEngine
        storage = PersistentStorageEngine(self._db_path)
        blocks = storage.get_all_blocks()

        chain_records: list[AuditChainRecord] = []
        for blk in blocks:
            bdata = blk.get("block_data", {})
            if not isinstance(bdata, dict):
                continue
            # Identify audit chain records by key fields
            if "event_id" in bdata and "sequence_number" in bdata:
                rec = AuditChainRecord(
                    event_id=bdata["event_id"],
                    sequence_number=int(bdata["sequence_number"]),
                    event_type=bdata.get("event_type", "UNKNOWN"),
                    request_id=bdata.get("request_id", ""),
                    agent_id=bdata.get("agent_id", ""),
                    request_hash=bdata.get("request_hash", ""),
                    risk_score=float(bdata.get("risk_score", 0.0)),
                    policy_version=bdata.get("policy_version", "1.0"),
                    decision=bdata.get("decision", ""),
                    execution_result=bdata.get("execution_result", ""),
                    previous_record_hash=bdata.get("previous_record_hash", ""),
                    timestamp=bdata.get("timestamp") or blk.get("timestamp")
                )
                stored_hash = bdata.get("record_hash") or blk.get("block_hash")
                if stored_hash:
                    rec.record_hash = stored_hash
                chain_records.append(rec)

        if chain_records:
            chain_records.sort(key=lambda r: r.sequence_number)
            self._records = chain_records
            self._current_sequence = chain_records[-1].sequence_number

    def write_event(
        self,
        event_type: str,
        request_id: str,
        agent_id: str,
        request_hash: str,
        risk_score: float,
        policy_version: str,
        decision: str,
        execution_result: str,
        event_id: str | None = None
    ) -> AuditChainRecord:
        """
        Concurrency-Safe atomic append of an audit record to the hash chain.
        When SQLite persistence is configured, delegates sequence allocation and previous hash
        linking to atomic database transactions (BEGIN IMMEDIATE) to guarantee zero collisions
        and prevent chain forks across separate worker processes.
        """
        with self._lock:
            if not self._db_path:
                # In-memory execution
                if not self._records:
                    self._append_genesis_record()
                # Idempotency check in memory
                if event_id:
                    for r in self._records:
                        if r.event_id == event_id:
                            return r

                self._current_sequence += 1
                seq = self._current_sequence
                prev_hash = self._records[-1].record_hash if self._records else self.GENESIS_HASH
                ev_id = event_id or f"EV-CHAIN-{seq:06d}"

                record = AuditChainRecord(
                    event_id=ev_id,
                    sequence_number=seq,
                    event_type=event_type,
                    request_id=request_id,
                    agent_id=agent_id,
                    request_hash=request_hash,
                    risk_score=risk_score,
                    policy_version=policy_version,
                    decision=decision,
                    execution_result=execution_result,
                    previous_record_hash=prev_hash
                )
                self._records.append(record)
                return record

            # Persistent SQLite execution with cross-process BEGIN IMMEDIATE
            from fabric.persistent_db import PersistentStorageEngine
            storage = PersistentStorageEngine(self._db_path)
            try:
                rec_dict, is_new = storage.atomic_append_audit_block(
                    event_type=event_type,
                    request_id=request_id,
                    agent_id=agent_id,
                    request_hash=request_hash,
                    risk_score=risk_score,
                    policy_version=policy_version,
                    decision=decision,
                    execution_result=execution_result,
                    event_id=event_id
                )
            except Exception as exc:
                raise AuditPersistenceError(
                    f"Durable audit persistence failed for event '{event_id or 'auto'}': {exc}"
                ) from exc

            # Sync local records from SQLite
            self._sync_records_from_db()

            # Return the committed record from self._records
            for r in reversed(self._records):
                if r.event_id == rec_dict["event_id"] and r.sequence_number == rec_dict["sequence_number"]:
                    return r

            # Fallback
            rec = AuditChainRecord(
                event_id=rec_dict["event_id"],
                sequence_number=rec_dict["sequence_number"],
                event_type=rec_dict["event_type"],
                request_id=rec_dict["request_id"],
                agent_id=rec_dict["agent_id"],
                request_hash=rec_dict["request_hash"],
                risk_score=rec_dict["risk_score"],
                policy_version=rec_dict["policy_version"],
                decision=rec_dict["decision"],
                execution_result=rec_dict["execution_result"],
                previous_record_hash=rec_dict["previous_record_hash"],
                timestamp=rec_dict.get("timestamp")
            )
            rec.record_hash = rec_dict.get("record_hash") or rec.calculate_record_hash()
            self._records.append(rec)
            self._current_sequence = rec.sequence_number
            return rec

    def get_chain(self) -> list[dict[str, Any]]:
        with self._lock:
            if self._db_path:
                self._sync_records_from_db()
            return [r.to_dict() for r in self._records]

    def get_chain_events(self) -> list[dict[str, Any]]:
        """Alias for get_chain to return all chain event dictionaries."""
        return self.get_chain()

    def _verify_records(self, records: list[AuditChainRecord]) -> dict[str, Any]:
        """Internal helper validating records integrity, sequence continuity, and hash chain."""
        if not records:
            return {"valid": False, "reason": "EMPTY_CHAIN"}

        for i in range(len(records)):
            current = records[i]

            # 1. Check internal record hash calculation
            recalculated = current.calculate_record_hash()
            if recalculated != current.record_hash:
                return {
                    "valid": False,
                    "status": "TAMPERING_DETECTED",
                    "tampered_sequence": current.sequence_number,
                    "event_id": current.event_id,
                    "reason": f"Record hash mismatch at sequence #{current.sequence_number}."
                }

            # 2. Check strict sequential progression
            if current.sequence_number != i:
                return {
                    "valid": False,
                    "status": "TAMPERING_DETECTED",
                    "tampered_sequence": current.sequence_number,
                    "event_id": current.event_id,
                    "reason": f"Sequence discontinuity: expected #{i}, found #{current.sequence_number}."
                }

            # 3. Check chain link to previous record
            if i > 0:
                prev = records[i - 1]
                if current.previous_record_hash != prev.record_hash:
                    return {
                        "valid": False,
                        "status": "TAMPERING_DETECTED",
                        "tampered_sequence": current.sequence_number,
                        "event_id": current.event_id,
                        "reason": f"Previous record hash link broken at sequence #{current.sequence_number}."
                    }

        return {
            "valid": True,
            "status": "VERIFIED_INTACT",
            "total_records": len(records),
            "latest_record_hash": records[-1].record_hash
        }

    def verify_chain_integrity(self) -> dict[str, Any]:
        """
        Verifies entire hash chain from Genesis to latest block.
        Detects historical tampering or sequence gaps.
        """
        with self._lock:
            if getattr(self, "_rehydration_error", None):
                return {
                    "valid": False,
                    "status": "TAMPERING_DETECTED",
                    "reason": self._rehydration_error
                }
            if self._db_path:
                self._sync_records_from_db()
            return self._verify_records(self._records)

    def simulate_tamper_record(self, sequence_number: int, field_name: str, new_value: Any) -> bool:
        """Simulates tampering with a past audit chain record for security research demonstration."""
        with self._lock:
            tampered = False
            for rec in self._records:
                if rec.sequence_number == sequence_number:
                    setattr(rec, field_name, new_value)
                    tampered = True
                    break
            if tampered and self._db_path:
                try:
                    from fabric.persistent_db import PersistentStorageEngine
                    storage = PersistentStorageEngine(self._db_path)
                    storage.tamper_block_data(sequence_number, field_name, new_value)
                except Exception:
                    pass
            return tampered
