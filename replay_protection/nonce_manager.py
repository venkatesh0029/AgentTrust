import datetime
from typing import Dict

class NonceManager:
    """Tracks seen nonces to prevent replay attacks with automatic eviction."""

    def __init__(self):
        self._used_nonces: Dict[str, float] = {}

    def is_nonce_used(self, nonce: str) -> bool:
        return nonce in self._used_nonces

    def register_nonce(self, nonce: str) -> None:
        self._used_nonces[nonce] = datetime.datetime.now(datetime.timezone.utc).timestamp()

    def evict_expired(self, max_age_seconds: int = 300) -> int:
        """Evicts nonces older than max_age_seconds."""
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        expired = [n for n, ts in self._used_nonces.items() if now - ts > max_age_seconds]
        for n in expired:
            del self._used_nonces[n]
        return len(expired)
