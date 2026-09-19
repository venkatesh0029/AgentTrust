import time
import datetime
from typing import Dict, Any, List, Optional, Tuple, Set

class FailedCommitRecord:
    """Represents a failed blockchain ledger commitment held in retry storage."""

    def __init__(self, event_id: str, request_id: str, payload: Dict[str, Any], error_msg: str):
        self.event_id = event_id
        self.request_id = request_id
        self.payload = payload
        self.error_msg = error_msg
        self.created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.retry_count = 0
        self.max_retries = 3
        self.status = "PENDING_RETRY"  # PENDING_RETRY, RETRIED_SUCCESS, DEAD_LETTER_QUEUE

class RetryQueueManager:
    """
    Manages durable failure retry queue, Dead-Letter Queue (DLQ), and manual/automatic retry.
    """

    def __init__(self):
        self._pending_queue: Dict[str, FailedCommitRecord] = {}
        self._dead_letter_queue: Dict[str, FailedCommitRecord] = {}
        self._processed_idempotency_keys: Set[str] = set()

    def enqueue_failed_commit(self, event_id: str, request_id: str, payload: Dict[str, Any], error_msg: str) -> FailedCommitRecord:
        """Enqueues failed transaction into retry queue."""
        record = FailedCommitRecord(event_id, request_id, payload, error_msg)
        self._pending_queue[event_id] = record
        return record

    def list_pending_retries(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_id": r.event_id,
                "request_id": r.request_id,
                "retry_count": r.retry_count,
                "status": r.status,
                "error": r.error_msg,
                "created_at": r.created_at
            }
            for r in self._pending_queue.values() if r.status == "PENDING_RETRY"
        ]

    def retry_commit(self, event_id: str, fabric_client) -> Tuple[bool, str]:
        """
        Retries committing failed transaction to Fabric ledger.
        Moves to DLQ if max retries exceeded.
        """
        record = self._pending_queue.get(event_id)
        if not record:
            return False, "EVENT_NOT_IN_RETRY_QUEUE"

        if record.retry_count >= record.max_retries:
            record.status = "DEAD_LETTER_QUEUE"
            self._dead_letter_queue[event_id] = record
            self._pending_queue.pop(event_id, None)
            return False, "MAX_RETRIES_EXCEEDED_MOVED_TO_DLQ"

        record.retry_count += 1
        try:
            p = record.payload
            res = fabric_client.record_action_event(
                event_id=p["event_id"],
                request_id=p["request_id"],
                agent_id=p["agent_id"],
                action=p["action"],
                resource=p["resource"],
                decision=p["decision"],
                reason=p["reason"],
                policy_id=p["policy_id"],
                policy_version=p["policy_version"],
                evidence_reference=p["evidence_reference"],
                evidence_hash=p["evidence_hash"]
            )
            record.status = "RETRIED_SUCCESS"
            self._pending_queue.pop(event_id, None)
            return True, "RETRY_SUCCESSFUL"
        except Exception as e:
            if record.retry_count >= record.max_retries:
                record.status = "DEAD_LETTER_QUEUE"
                self._dead_letter_queue[event_id] = record
                self._pending_queue.pop(event_id, None)
            return False, f"RETRY_FAILED: {str(e)}"
