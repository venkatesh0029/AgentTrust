"""
Secret Models and Data Structures for Centralized Secret Lifecycle Management.

Enforces redaction invariants so raw cryptographic secrets are NEVER printed,
logged, or leaked in repr/str outputs or management API responses.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class SecretRecord:
    """
    Represents an internal versioned secret record.
    Redacts secret_value from repr and str to prevent leakage in log aggregators.
    """
    key_id: str
    version: int
    secret_value: str
    status: str  # 'ACTIVE', 'PREVIOUS', 'REVOKED'
    created_at: str
    expires_at: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None

    def __repr__(self) -> str:
        return (
            f"SecretRecord(key_id='{self.key_id}', version={self.version}, "
            f"status='{self.status}', secret_value='***REDACTED***', "
            f"created_at='{self.created_at}', expires_at={self.expires_at}, "
            f"revoked_at={self.revoked_at})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def to_metadata(self) -> dict[str, Any]:
        """Returns non-sensitive metadata for auditing and inspection."""
        return {
            "key_id": self.key_id,
            "version": self.version,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason
        }


@dataclass
class ValidationResult:
    """Outcome of constant-time secret validation."""
    is_valid: bool
    key_id: str | None = None
    version: int | None = None
    is_previous: bool = False
    error: str | None = None  # None, 'INVALID_SECRET', 'SECRET_REVOKED', 'GRACE_PERIOD_EXPIRED'

    def __repr__(self) -> str:
        return (
            f"ValidationResult(is_valid={self.is_valid}, key_id='{self.key_id}', "
            f"version={self.version}, is_previous={self.is_previous}, error='{self.error}')"
        )
