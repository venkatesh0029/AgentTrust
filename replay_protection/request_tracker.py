from typing import Tuple, Set, Dict, Any, Optional
from replay_protection.nonce_manager import NonceManager
from replay_protection.timestamp_validator import TimestampValidator

class RequestTracker:
    """
    Unified Replay and Idempotency Protection Engine tracking Request IDs, Nonces,
    Expiration timestamps, and Idempotency Keys.
    """

    def __init__(self, timestamp_window: int = 300):
        self.nonce_manager = NonceManager()
        self.timestamp_validator = TimestampValidator(timestamp_window)
        self._processed_request_ids: Set[str] = set()
        self._idempotency_records: Dict[str, Dict[str, Any]] = {}

    def check_and_track(
        self,
        request_id: str,
        nonce: str,
        timestamp_iso: str,
        expires_at_iso: str = "",
        idempotency_key: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validates request against replay attacks.
        Returns (is_allowed, reason).
        """
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
        self._processed_request_ids.add(request_id)
        self.nonce_manager.register_nonce(nonce)

        return True, "FRESH_REQUEST"

    def get_idempotent_result(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Returns cached execution result for duplicate idempotency key if present."""
        if not idempotency_key:
            return None
        return self._idempotency_records.get(idempotency_key)

    def record_idempotent_result(self, idempotency_key: str, result: Dict[str, Any]) -> None:
        """Stores execution outcome for an idempotency key."""
        if idempotency_key:
            self._idempotency_records[idempotency_key] = result

