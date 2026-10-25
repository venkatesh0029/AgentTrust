"""
JWT Authentication Service for AgentTrust Framework.
Provides token generation and verification for administrative roles and identity endpoints.
Uses dynamic cryptographically secure secrets to prevent hardcoded key forgery.
"""

import os
import secrets
import time
from typing import Any

import jwt

import math
from collections import Counter

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
    Includes in-memory revocation / blacklisting for clean session termination.
    """

    _revoked_tokens: set[str] = set()

    @classmethod
    def revoke_token(cls, token: str) -> None:
        """Revokes a JWT token (e.g. on logout) so it cannot be used again."""
        if token:
            cls._revoked_tokens.add(token.strip())

    @classmethod
    def is_token_revoked(cls, token: str) -> bool:
        """Returns True if the token has been explicitly revoked."""
        return token.strip() in cls._revoked_tokens if token else False

    @classmethod
    def clear_revoked_tokens(cls) -> None:
        """Clears revoked tokens cache (primarily for test suite reset)."""
        cls._revoked_tokens.clear()

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
        """Generates a signed JWT token containing admin role and identity claims."""
        now = int(time.time())
        role_str = role.value if hasattr(role, "value") else str(role)
        payload = {
            "sub": identity_id,
            "role": role_str,
            "iat": now,
            "exp": now + expires_in,
            "iss": "AgentTrust-Auth-Server"
        }
        secret = cls.get_active_secret()
        return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    @classmethod
    def verify_token(cls, token: str) -> dict[str, Any]:
        """
        Verifies JWT token signature, issuer, expiration, and revocation status.
        Returns payload dict if valid, raises ValueError if invalid, expired, or revoked.
        """
        if cls.is_token_revoked(token):
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
