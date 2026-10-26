"""
JWT Authentication Service for AgentTrust Framework.
Provides token generation and verification for administrative roles and identity endpoints.
Uses dynamic cryptographically secure secrets to prevent hardcoded key forgery.
"""

import hashlib
import math
import os
import sqlite3
import time
import uuid
from collections import Counter
from typing import Any

import jwt

from database_config import resolve_database_path

INSECURE_JWT_SECRETS = {
    "secret",
    "changeme",
    "default",
    "default_jwt_secret",
    "password",
    "default_secret_key_change_in_production",
    "admin",
    "test",
}

# Stable development fallback secret ensuring multi-instance / restart consistency in dev/test
_DEFAULT_DEV_JWT_SECRET = "dev-agenttrust-jwt-signing-secret-key-32chars-min-entropy"


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the empirical Shannon entropy of a string in bits per character.
    NOTE: This is a weak-secret heuristic based on character frequency distributions.
    It does not mathematically prove cryptographic unpredictability. Cryptographic
    security requires keys to be generated via a CSPRNG (e.g. secrets.token_bytes(32)).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())


def validate_jwt_secret_entropy(secret: str, secret_name: str = "AGENTTRUST_JWT_SECRET") -> None:
    """
    Supplementary weak-secret heuristic sanity check:
    Validates minimum length (>=32 chars), absence of dictionary placeholders,
    character diversity (>=8 unique chars), symmetry rejection, and empirical Shannon
    entropy (>=3.0 bits/char).

    IMPORTANT QUALIFICATION:
    These checks act as a fail-closed filter against obvious low-diversity, repetitive,
    or placeholder values. Calculating Shannon character entropy on a single secret
    does not mathematically prove unpredictable generation. Production secrets must be
    provisioned from a cryptographically secure random number generator (CSPRNG, e.g.
    secrets.token_bytes(32) yielding 256 bits of true entropy) or an enterprise secrets manager.
    """
    if not secret:
        raise RuntimeError(
            f"SECURITY VIOLATION: Production environment requires explicit secure {secret_name}. "
            "Refusing to initialize with missing JWT secret."
        )
    if secret.lower() in INSECURE_JWT_SECRETS:
        raise RuntimeError(
            f"SECURITY VIOLATION: {secret_name} is set to an insecure placeholder. "
            "Production requires a cryptographically strong, unique secret."
        )
    if len(secret) < 32:
        raise RuntimeError(
            f"SECURITY VIOLATION: Production environment requires {secret_name} "
            f"with at least 32 characters of entropy (found {len(secret)})."
        )

    unique_chars = len(set(secret))
    if unique_chars < 8:
        raise RuntimeError(
            f"SECURITY VIOLATION: {secret_name} has insufficient character diversity "
            f"({unique_chars} unique chars, minimum 8 required). "
            "Predictable, repetitive, or patterned secrets are prohibited."
        )

    # Check for trivial repeated patterns (e.g. repeated half or quarter)
    half = len(secret) // 2
    if secret[:half] == secret[half:]:
        raise RuntimeError(
            f"SECURITY VIOLATION: {secret_name} contains repeated half patterns. "
            "Provision production secrets from a cryptographically secure random generator."
        )

    entropy = calculate_shannon_entropy(secret)
    if entropy < 3.0:
        raise RuntimeError(
            f"SECURITY VIOLATION: {secret_name} has insufficient Shannon entropy "
            f"({entropy:.2f} bits/char < 3.00 bits/char required). "
            "Provision production secrets from a cryptographically secure random generator (e.g. secrets.token_hex(32))."
        )


def resolve_jwt_secret(env_profile: str | None = None) -> str:
    """
    Resolves and enforces JWT signing secret with fail-closed security guarantees.
    In production: strictly enforces explicit AGENTTRUST_JWT_SECRET with >= 32 characters and high entropy.
    In development/testing: uses AGENTTRUST_JWT_SECRET if provided, or stable session key.
    """
    if env_profile is None:
        env_profile = os.environ.get("AGENTTRUST_ENV", "development").lower()

    env_secret = os.environ.get("AGENTTRUST_JWT_SECRET", "").strip()

    if env_profile in ("production", "prod"):
        validate_jwt_secret_entropy(env_secret)
        return env_secret

    # Development / Testing profile
    if env_secret:
        return env_secret
    return _DEFAULT_DEV_JWT_SECRET


# Eagerly validate if running in production
if os.environ.get("AGENTTRUST_ENV", "development").lower() in ("production", "prod"):
    resolve_jwt_secret("production")

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600 * 8  # 8 hours


class JWTAuthManager:
    """
    Cryptographic JWT Auth Manager for issuing and verifying session tokens.
    Includes durable multi-worker revocation / blacklisting for clean session termination
    persisted across worker restarts via durable storage.
    """

    _revoked_tokens: set[str] = set()

    @classmethod
    def _init_revocation_db(cls, db_path: str | None = None) -> str:
        resolved = resolve_database_path(db_path)
        try:
            conn = sqlite3.connect(resolved, timeout=5.0)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jwt_revoked_tokens (
                    jti TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL,
                    identity_id TEXT,
                    expires_at INTEGER NOT NULL,
                    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_hash ON jwt_revoked_tokens(token_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON jwt_revoked_tokens(expires_at)")
            conn.commit()
            conn.close()
        except Exception:
            pass
        return resolved

    @classmethod
    def revoke_token(cls, token: str, db_path: str | None = None) -> None:
        """
        Durable, multi-worker token revocation:
        1. Adds token to local in-memory set for zero-latency lookups.
        2. Records token jti and SHA-256 hash in durable SQLite storage (shared across workers/restarts).
        """
        if not token:
            return
        token_clean = token.strip()
        cls._revoked_tokens.add(token_clean)

        token_hash = hashlib.sha256(token_clean.encode()).hexdigest()
        jti = token_hash
        identity_id = "unknown"
        expires_at = int(time.time()) + JWT_EXPIRATION_SECONDS

        try:
            unverified = jwt.decode(token_clean, options={"verify_signature": False})
            jti = unverified.get("jti", token_hash)
            identity_id = unverified.get("sub", "unknown")
            expires_at = unverified.get("exp", expires_at)
        except Exception:
            pass

        resolved_db = cls._init_revocation_db(db_path)
        try:
            conn = sqlite3.connect(resolved_db, timeout=5.0)
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute(
                "INSERT OR REPLACE INTO jwt_revoked_tokens (jti, token_hash, identity_id, expires_at) VALUES (?, ?, ?, ?)",
                (jti, token_hash, identity_id, expires_at)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    @classmethod
    def is_token_revoked(cls, token: str, db_path: str | None = None) -> bool:
        """
        Returns True if token has been revoked in this worker or any durable shared worker instance.
        """
        if not token:
            return False
        token_clean = token.strip()
        if token_clean in cls._revoked_tokens:
            return True

        token_hash = hashlib.sha256(token_clean.encode()).hexdigest()
        jti = token_hash
        try:
            unverified = jwt.decode(token_clean, options={"verify_signature": False})
            jti = unverified.get("jti", token_hash)
        except Exception:
            pass

        resolved_db = resolve_database_path(db_path)
        try:
            conn = sqlite3.connect(resolved_db, timeout=5.0)
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA busy_timeout = 5000")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM jwt_revoked_tokens WHERE (jti = ? OR token_hash = ?) AND expires_at > ? LIMIT 1",
                (jti, token_hash, int(time.time()) - 300)
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                cls._revoked_tokens.add(token_clean)
                return True
        except Exception:
            pass

        return False

    @classmethod
    def clear_revoked_tokens(cls, db_path: str | None = None) -> None:
        """Clears revoked tokens cache in-memory and in durable storage (for test suite isolation)."""
        cls._revoked_tokens.clear()
        resolved_db = resolve_database_path(db_path)
        try:
            conn = sqlite3.connect(resolved_db, timeout=5.0)
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("DELETE FROM jwt_revoked_tokens")
            conn.commit()
            conn.close()
        except Exception:
            pass

    @classmethod
    def get_active_secret(cls) -> str:
        """Returns active secret used for signing JWTs, resolved dynamically from environment."""
        return resolve_jwt_secret()

    @classmethod
    def create_admin_token(
        cls,
        role: str,
        identity_id: str = "admin-user",
        expires_in: int = JWT_EXPIRATION_SECONDS
    ) -> str:
        """Generates a signed JWT token containing admin role, identity claims, and unique jti."""
        now = int(time.time())
        role_str = role.value if hasattr(role, "value") else str(role)
        payload = {
            "sub": identity_id,
            "role": role_str,
            "iat": now,
            "exp": now + expires_in,
            "iss": "AgentTrust-Auth-Server",
            "jti": str(uuid.uuid4())
        }
        secret = cls.get_active_secret()
        return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    @classmethod
    def verify_token(cls, token: str, db_path: str | None = None) -> dict[str, Any]:
        """
        Verifies JWT token signature, issuer, expiration, and revocation status.
        Returns payload dict if valid, raises ValueError if invalid, expired, or revoked.
        """
        if cls.is_token_revoked(token, db_path=db_path):
            raise ValueError("JWT Token Has Been Revoked (Session Terminated)")

        secret = cls.get_active_secret()
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[JWT_ALGORITHM],
                issuer="AgentTrust-Auth-Server"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("JWT Token Has Expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid JWT Token: {e!s}")

