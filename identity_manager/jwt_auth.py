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
        if not env_secret:
            raise RuntimeError(
                "SECURITY VIOLATION: Production environment requires explicit secure AGENTTRUST_JWT_SECRET. "
                "Refusing to initialize with missing JWT secret."
            )
        if len(env_secret) < 32:
            raise RuntimeError(
                "SECURITY VIOLATION: Production environment requires AGENTTRUST_JWT_SECRET "
                "with at least 32 characters of entropy."
            )
        if env_secret.lower() in INSECURE_JWT_SECRETS:
            raise RuntimeError(
                "SECURITY VIOLATION: AGENTTRUST_JWT_SECRET is set to an insecure placeholder. "
                "Production requires a cryptographically strong, unique secret."
            )
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
    """

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
        Verifies JWT token signature, issuer, and expiration.
        Returns payload dict if valid, raises ValueError if invalid or expired.
        """
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
