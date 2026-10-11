import datetime
import threading
from typing import Any

from replay_protection.nonce_manager import NonceManager
from replay_protection.timestamp_validator import TimestampValidator


class RequestTracker:
    """
    Unified Replay and Idempotency Protection Engine tracking Request IDs, Nonces,
    Expiration timestamps, and Idempotency Keys with Thread-Safety and Automatic Eviction.
    Supports optional PersistentStorageEngine SQLite backing for restart resilience.
    """

    def __init__(self, timestamp_window: int = 300, persistent_db=None):
        self.timestamp_window = timestamp_window
        self.persistent_db = persistent_db
        self.nonce_manager = NonceManager()
        self.timestamp_validator = TimestampValidator(timestamp_window)
        self._processed_request_ids: dict[str, float] = {}
        self._idempotency_records: dict[str, dict[str, Any]] = {}
        self._in_flight_keys: set[str] = set()
        self._lock = threading.Lock()

        # Hydrate from persistent DB if available
        if self.persistent_db:
            try:
                db_nonces = self.persistent_db.get_all_nonces()
                for n in db_nonces:
                    self.nonce_manager.register_nonce(n)
                self._processed_request_ids.update(self.persistent_db.get_all_request_ids())
            except Exception:
                pass

    def check_and_track(
        self,
        request_id: str,
        nonce: str,
        timestamp_iso: str,
        expires_at_iso: str = "",
        idempotency_key: str | None = None
    ) -> tuple[bool, str]:
        """
        Validates request against replay attacks atomically under lock.
        Returns (is_allowed, reason).
        """
        with self._lock:
            # Periodically evict expired entries
            self._evict_expired_entries()

            # 1. Check if Request ID already processed
            if request_id in self._processed_request_ids:
                return False, "REPLAY_DETECTED"

            # 2. Check Nonce
            if self.nonce_manager.is_nonce_used(nonce):
                return False, "REPLAY_DETECTED"

            # 3. Check Timestamp freshness
            valid_time, reason = self.timestamp_validator.validate(timestamp_iso, expires_at_iso)
            if not valid_time:
                return False, reason

            # Register request ID and nonce upon successful verification
            now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
            self._processed_request_ids[request_id] = now_ts
            self.nonce_manager.register_nonce(nonce)

            if self.persistent_db:
                try:
                    self.persistent_db.save_nonce(request_id, nonce, now_ts)
                except Exception:
                    pass

            return True, "FRESH_REQUEST"

    def _evict_expired_entries(self) -> None:
        """Evicts expired nonces and request IDs outside the timestamp window."""
        self.nonce_manager.evict_expired(self.timestamp_window)
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        expired_reqs = [r for r, ts in self._processed_request_ids.items() if ts > 0 and now - ts > self.timestamp_window]
        for r in expired_reqs:
            del self._processed_request_ids[r]
        if self.persistent_db:
            try:
                self.persistent_db.evict_expired_nonces(self.timestamp_window)
            except Exception:
                pass

    def acquire_in_flight(self, agent_id: str, idempotency_key: str | None) -> bool:
        """Acquires lock for an in-flight idempotency key. Returns False if already in-flight."""
        if not idempotency_key:
            return True
        scoped_key = f"{agent_id}:{idempotency_key}"
        with self._lock:
            if scoped_key in self._in_flight_keys:
                return False
            self._in_flight_keys.add(scoped_key)
            return True

    def release_in_flight(self, agent_id: str, idempotency_key: str | None) -> None:
        """Releases lock for an in-flight idempotency key."""
        if not idempotency_key:
            return
        scoped_key = f"{agent_id}:{idempotency_key}"
        with self._lock:
            self._in_flight_keys.discard(scoped_key)

    def get_idempotent_result(self, agent_id: str, idempotency_key: str) -> dict[str, Any] | None:
        """Returns cached execution result for duplicate idempotency key bound to the specific agent_id."""
        if not idempotency_key:
            return None
        scoped_key = f"{agent_id}:{idempotency_key}"
        with self._lock:
            if scoped_key in self._idempotency_records:
                return self._idempotency_records[scoped_key]

        if self.persistent_db:
            try:
                intent = self.persistent_db.get_intent_by_idempotency_key(agent_id, idempotency_key)
                if intent and intent.get("outcome"):
                    return intent["outcome"]
            except Exception:
                pass

        return None

    def record_idempotent_result(self, agent_id: str, idempotency_key: str, result: dict[str, Any]) -> None:
        """Stores execution outcome for an idempotency key bound strictly to agent_id."""
        if idempotency_key:
            scoped_key = f"{agent_id}:{idempotency_key}"
            with self._lock:
                self._idempotency_records[scoped_key] = result

            if self.persistent_db:
                try:
                    self.persistent_db.save_intent(
                        request_id=result.get("request_id", ""),
                        agent_id=agent_id,
                        action=result.get("action", ""),
                        amount=float(result.get("transaction_data", {}).get("amount", 0) if result.get("transaction_data") else 0),
                        idempotency_key=idempotency_key,
                        state="COMPLETED",
                        outcome=result
                    )
                except Exception:
                    pass

