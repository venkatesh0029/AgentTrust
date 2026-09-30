"""
JWT Authentication Service for AgentTrust Framework.
Provides token generation and verification for administrative roles and identity endpoints.
"""

import os
import time
import jwt
from typing import Dict, Any, Optional

# Secret key loaded from environment variable with secure default fallback
JWT_SECRET = os.environ.get("AGENTTRUST_JWT_SECRET", "agenttrust_secret_key_change_in_prod_2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600 * 8  # 8 hours

class JWTAuthManager:

    @staticmethod
    def create_admin_token(role: str, identity_id: str = "admin-user", expires_in: int = JWT_EXPIRATION_SECONDS) -> str:
        """Generates a signed JWT token containing admin role and identity claims."""
        payload = {
            "sub": identity_id,
            "role": role,
            "iat": int(time.time()),
            "exp": int(time.time()) + expires_in,
            "iss": "AgentTrust-Auth-Server"
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """
        Verifies JWT token signature and expiration.
        Returns payload dict if valid, raises ValueError if invalid or expired.
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], issuer="AgentTrust-Auth-Server")
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("JWT Token Has Expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid JWT Token: {str(e)}")
