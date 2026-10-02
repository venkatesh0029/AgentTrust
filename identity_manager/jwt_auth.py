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

# Load secret key from environment or dynamically generate a strong per-process secret
_ENV_SECRET = os.environ.get("AGENTTRUST_JWT_SECRET")
if not _ENV_SECRET:
    # Generate a cryptographically secure 256-bit secret for runtime process isolation
    JWT_SECRET = secrets.token_hex(32)
else:
    JWT_SECRET = _ENV_SECRET

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600 * 8  # 8 hours

class JWTAuthManager:
    """
    Cryptographic JWT Auth Manager for issuing and verifying session tokens.
    """

    @staticmethod
    def get_active_secret() -> str:
        """Returns active secret used for signing JWTs."""
        return JWT_SECRET

    @staticmethod
    def create_admin_token(
        role: str,
        identity_id: str = "admin-user",
        expires_in: int = JWT_EXPIRATION_SECONDS
    ) -> str:
        """Generates a signed JWT token containing admin role and identity claims."""
        now = int(time.time())
        payload = {
            "sub": identity_id,
            "role": role,
            "iat": now,
            "exp": now + expires_in,
            "iss": "AgentTrust-Auth-Server"
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> dict[str, Any]:
        """
        Verifies JWT token signature, issuer, and expiration.
        Returns payload dict if valid, raises ValueError if invalid or expired.
        """
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                issuer="AgentTrust-Auth-Server"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("JWT Token Has Expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid JWT Token: {e!s}")
