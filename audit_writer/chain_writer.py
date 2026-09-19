import hashlib
import json
import datetime
import threading
from typing import Dict, Any, List, Optional

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
        timestamp: Optional[str] = None
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
        self.timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
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

    def to_dict(self) -> Dict[str, Any]:
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
            "timestamp": self.timestamp
        }

class AuditChainWriter:
    """
    Concurrency-Safe Atomic Hash Chain Audit Logger.
    Enforces thread locking, strict sequence numbering, and tamper detection.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self):
        self._records: List[AuditChainRecord] = []
        self._lock = threading.Lock()
        self._current_sequence = 0
        # Initialize Genesis Record
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
        event_id: Optional[str] = None
    ) -> AuditChainRecord:
        """
        Thread-safe atomic append of an audit record to the hash chain.
        """
        with self._lock:
            self._current_sequence += 1
            seq = self._current_sequence
            prev_hash = self._records[-1].record_hash
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

    def get_chain(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._records]

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Verifies entire hash chain from Genesis to latest block.
        Detects historical tampering or sequence gaps.
        """
        with self._lock:
            if not self._records:
                return {"valid": False, "reason": "EMPTY_CHAIN"}

            for i in range(len(self._records)):
                current = self._records[i]

                # Check internal record hash calculation
                recalculated = current.calculate_record_hash()
                if recalculated != current.record_hash:
                    return {
                        "valid": False,
                        "status": "TAMPERING_DETECTED",
                        "tampered_sequence": current.sequence_number,
                        "event_id": current.event_id,
                        "reason": f"Record hash mismatch at sequence #{current.sequence_number}."
                    }

                # Check chain link to previous record
                if i > 0:
                    prev = self._records[i - 1]
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
                "total_records": len(self._records),
                "latest_record_hash": self._records[-1].record_hash
            }

    def simulate_tamper_record(self, sequence_number: int, field_name: str, new_value: Any) -> bool:
        """Simulates tampering with a past audit chain record for security research demonstration."""
        with self._lock:
            for rec in self._records:
                if rec.sequence_number == sequence_number:
                    setattr(rec, field_name, new_value)
                    return True
            return False
