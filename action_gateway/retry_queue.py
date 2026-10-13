import datetime
import os
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

            if hasattr(self.persistent_db, "list_dead_letter_retries"):
                dead_letters = self.persistent_db.list_dead_letter_retries()
                for record_data in dead_letters:
                    if record_data.get("corrupt") or not isinstance(
                        record_data.get("payload"), dict
                    ):
                        # Keep corrupt records in persistent storage for diagnosis.
                        # Never hydrate them into the executable retry queue.
                        continue
                    record = FailedCommitRecord(
                        event_id=record_data["event_id"],
                        request_id=record_data["request_id"],
                        payload=record_data["payload"],
                        error_msg=record_data["error_msg"],
                        status=record_data["status"],
                        retry_count=record_data["retry_count"],
                    )
                    self._dead_letter_queue[record.event_id] = record

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

    def pending_count(self) -> int:
        """Returns the current number of pending failed commits in queue."""
        if self.persistent_db:
            return len(self.persistent_db.list_pending_retries())
        return sum(1 for r in self._pending_queue.values() if r.status == "PENDING_RETRY")

    def list_pending_retries(self) -> list[dict[str, Any]]:
        if self.persistent_db:
            persisted = self.persistent_db.list_pending_retries()
            for r in persisted:
                if r["event_id"] not in self._pending_queue:
                    self._pending_queue[r["event_id"]] = FailedCommitRecord(
                        event_id=r["event_id"],
                        request_id=r["request_id"],
                        payload=r["payload"],
                        error_msg=r["error_msg"],
                        status=r["status"],
                        retry_count=r["retry_count"]
                    )
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
        """Reconcile uncertain commits before attempting a retry."""
        record = self._pending_queue.get(event_id)
        if not record and self.persistent_db:
            # Attempt to rehydrate from DB
            persisted = self.persistent_db.list_pending_retries()
            for r in persisted:
                if r["event_id"] == event_id:
                    record = FailedCommitRecord(
                        event_id=r["event_id"],
                        request_id=r["request_id"],
                        payload=r["payload"],
                        error_msg=r["error_msg"],
                        status=r["status"],
                        retry_count=r["retry_count"],
                    )
                    self._pending_queue[event_id] = record
                    break

        if not record:
            return False, "EVENT_NOT_IN_RETRY_QUEUE"

        if record.retry_count >= record.max_retries:
            record.status = "DEAD_LETTER_QUEUE"
            self._dead_letter_queue[event_id] = record
            self._pending_queue.pop(event_id, None)
            if self.persistent_db:
                self.persistent_db.update_retry_status(
                    event_id, "DEAD_LETTER_QUEUE", record.retry_count
                )
            return False, "MAX_RETRIES_EXCEEDED_MOVED_TO_DLQ"

        mode = os.environ.get("FABRIC_GATEWAY_MODE", "simulator").strip().lower()
        if mode not in {"simulator", "live"}:
            raise ValueError(
                "Invalid FABRIC_GATEWAY_MODE. Expected 'simulator' or 'live'."
            )

        p = record.payload
        evidence_data = p.get("evidence") or {}
        ev_ref = (
            evidence_data.get("evidence_id")
            or p.get("evidence_reference")
            or f"EVID-RETRY-{event_id}"
        )
        ev_hash = (
            evidence_data.get("evidence_hash")
            or p.get("evidence_hash")
            or f"HASH-RETRY-{event_id}"
        )
        pol_id = p.get("policy_id") or "FIN-POLICY-001"
        pol_ver = p.get("policy_version") or "1.0.0"

        expected_fields = {
            "event_id": p.get("event_id", event_id),
            "request_id": p.get("request_id", record.request_id),
            "agent_id": p.get("agent_id", "AGENT-UNKNOWN"),
            "action": p.get("action", "TRANSFER_FUNDS"),
            "resource": p.get("resource", "BANK_RESERVE_IN"),
            "decision": p.get("decision", "ALLOWED"),
            "reason": p.get("reason", "VALID"),
            "policy_id": pol_id,
            "policy_version": pol_ver,
            "evidence_reference": ev_ref,
            "evidence_hash": ev_hash,
        }

        # Step 1: Reconcile against ledger if client supports get_event
        if hasattr(fabric_client, "get_event"):
            try:
                existing_event = fabric_client.get_event(event_id)
            except Exception as exc:
                # Live query failure / timeout preserves uncertainty: do not increment retry count, do not resubmit
                return False, f"RETRY_FAILED: {exc!s}"

            if existing_event is not None:
                if isinstance(existing_event, dict) and all(
                    existing_event.get(k) == v for k, v in expected_fields.items()
                ):
                    # Successfully reconciled: already committed on ledger
                    record.status = "RETRIED_SUCCESS"
                    self._pending_queue.pop(event_id, None)
                    if self.persistent_db:
                        self.persistent_db.delete_retry_record(event_id)
                    return True, "RETRY_SUCCESSFUL"
                else:
                    # Conflicting data under the same event ID
                    record.status = "DEAD_LETTER_QUEUE"
                    self._dead_letter_queue[event_id] = record
                    self._pending_queue.pop(event_id, None)
                    if self.persistent_db:
                        self.persistent_db.update_retry_status(
                            event_id, "DEAD_LETTER_QUEUE", record.retry_count
                        )
                    return False, "RETRY_FAILED: RECONCILIATION_CONFLICT"
            else:
                # Event is absent from ledger
                if mode == "live":
                    # In live mode, absence is treated as uncertain; do not blindly resubmit
                    return False, "RETRY_FAILED: LIVE_LEDGER_STATE_UNCERTAIN"

        # Step 2: Safe to attempt write (simulator mode with absent event, or fallback)
        record.retry_count += 1
        try:
            _res = fabric_client.record_action_event(
                event_id=expected_fields["event_id"],
                request_id=expected_fields["request_id"],
                agent_id=expected_fields["agent_id"],
                action=expected_fields["action"],
                resource=expected_fields["resource"],
                decision=expected_fields["decision"],
                reason=expected_fields["reason"],
                policy_id=expected_fields["policy_id"],
                policy_version=expected_fields["policy_version"],
                evidence_reference=expected_fields["evidence_reference"],
                evidence_hash=expected_fields["evidence_hash"],
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
                    self.persistent_db.update_retry_status(
                        event_id, "DEAD_LETTER_QUEUE", record.retry_count
                    )
            else:
                if self.persistent_db:
                    self.persistent_db.update_retry_status(
                        event_id, "PENDING_RETRY", record.retry_count
                    )
            return False, f"RETRY_FAILED: {e!s}"
