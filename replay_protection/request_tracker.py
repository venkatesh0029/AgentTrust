import datetime
import threading
from typing import Tuple, Set, Dict, Any, Optional
from replay_protection.nonce_manager import NonceManager
from replay_protection.timestamp_validator import TimestampValidator

class RequestTracker:
    """
    Unified Replay and Idempotency Protection Engine tracking Request IDs, Nonces,
    Expiration timestamps, and Idempotency Keys with Thread-Safety and Automatic Eviction.
    """

    def __init__(self, timestamp_window: int = 300):
        self.timestamp_window = timestamp_window
        self.nonce_manager = NonceManager()
        self.timestamp_validator = TimestampValidator(timestamp_window)
        self._processed_request_ids: Dict[str, float] = {}
        self._idempotency_records: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def check_and_track(
        self,
        request_id: str,
        nonce: str,
        timestamp_iso: str,
        expires_at_iso: str = "",
        idempotency_key: Optional[str] = None
    ) -> Tuple[bool, str]:
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

            return True, "FRESH_REQUEST"

    def _evict_expired_entries(self) -> None:
        """Evicts expired nonces and request IDs outside the timestamp window."""
        self.nonce_manager.evict_expired(self.timestamp_window)
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        expired_reqs = [r for r, ts in self._processed_request_ids.items() if ts > 0 and now - ts > self.timestamp_window]
        for r in expired_reqs:
            del self._processed_request_ids[r]

    def get_idempotent_result(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Returns cached execution result for duplicate idempotency key if present."""
        if not idempotency_key:
            return None
        with self._lock:
            return self._idempotency_records.get(idempotency_key)

    def record_idempotent_result(self, idempotency_key: str, result: Dict[str, Any]) -> None:
        """Stores execution outcome for an idempotency key."""
        if idempotency_key:
            with self._lock:
                self._idempotency_records[idempotency_key] = result

