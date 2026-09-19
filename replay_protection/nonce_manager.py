import datetime
from typing import Set

class NonceManager:
    """Tracks seen nonces to prevent replay attacks."""

    def __init__(self):
        self._used_nonces: Set[str] = set()

    def is_nonce_used(self, nonce: str) -> bool:
        return nonce in self._used_nonces

    def register_nonce(self, nonce: str) -> None:
        self._used_nonces.add(nonce)
