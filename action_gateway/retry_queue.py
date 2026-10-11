import datetime
from typing import Any


class FailedCommitRecord:
    """Represents a failed blockchain ledger commitment held in retry storage."""

    def __init__(self, event_id: str, request_id: str, payload: dict[str, Any], error_msg: str, status: str = "PENDING_RETRY", retry_count: int = 0):
        self.event_id = event_id
        self.request_id = request_id
        self.payload = payload
        self.error_msg = error_msg
        self.created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.retry_count = retry_count
        self.max_retries = 3
        self.status = status  # PENDING_RETRY, RETRIED_SUCCESS, DEAD_LETTER_QUEUE


class RetryQueueManager:
    """
    Manages durable failure retry queue, Dead-Letter Queue (DLQ), and manual/automatic retry.
    Supports optional PersistentStorageEngine SQLite backing for restart resilience.
    """

    def __init__(self, persistent_db=None):
        self.persistent_db = persistent_db
        self._pending_queue: dict[str, FailedCommitRecord] = {}
        self._dead_letter_queue: dict[str, FailedCommitRecord] = {}
        self._processed_idempotency_keys: set[str] = set()

        # Hydrate from persistent DB if available
        if self.persistent_db:
            persisted = self.persistent_db.list_pending_retries()
            for r in persisted:
                rec = FailedCommitRecord(
                    event_id=r["event_id"],
                    request_id=r["request_id"],
                    payload=r["payload"],
                    error_msg=r["error_msg"],
                    status=r["status"],
                    retry_count=r["retry_count"]
                )
                self._pending_queue[rec.event_id] = rec

    def enqueue_failed_commit(self, event_id: str, request_id: str, payload: dict[str, Any], error_msg: str) -> FailedCommitRecord:
        """Enqueues failed transaction into retry queue and durable DB."""
        record = FailedCommitRecord(event_id, request_id, payload, error_msg)
        self._pending_queue[event_id] = record

        if self.persistent_db:
            self.persistent_db.save_retry_record(
                event_id=event_id,
                request_id=request_id,
                payload=payload,
                error_msg=error_msg,
                status="PENDING_RETRY",
                retry_count=0
            )

        return record

    def list_pending_retries(self) -> list[dict[str, Any]]:
        return [
            {
                "event_id": r.event_id,
                "request_id": r.request_id,
                "retry_count": r.retry_count,
                "status": r.status,
                "error": r.error_msg,
                "created_at": r.created_at,
                "payload": r.payload
            }
            for r in self._pending_queue.values() if r.status == "PENDING_RETRY"
        ]

    def retry_commit(self, event_id: str, fabric_client) -> tuple[bool, str]:
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
            if self.persistent_db:
                self.persistent_db.update_retry_status(event_id, "DEAD_LETTER_QUEUE", record.retry_count)
            return False, "MAX_RETRIES_EXCEEDED_MOVED_TO_DLQ"

        record.retry_count += 1
        try:
            p = record.payload
            _res = fabric_client.record_action_event(
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
            if self.persistent_db:
                self.persistent_db.delete_retry_record(event_id)
            return True, "RETRY_SUCCESSFUL"
        except Exception as e:
            if record.retry_count >= record.max_retries:
                record.status = "DEAD_LETTER_QUEUE"
                self._dead_letter_queue[event_id] = record
                self._pending_queue.pop(event_id, None)
                if self.persistent_db:
                    self.persistent_db.update_retry_status(event_id, "DEAD_LETTER_QUEUE", record.retry_count)
            else:
                if self.persistent_db:
                    self.persistent_db.update_retry_status(event_id, "PENDING_RETRY", record.retry_count)
            return False, f"RETRY_FAILED: {e!s}"
