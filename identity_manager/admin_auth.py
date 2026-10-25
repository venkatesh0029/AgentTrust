"""
Administrative User Authentication and Password Verification Service.
Enforces salted PBKDF2-HMAC-SHA256 password hashing and role binding.
Prevents unauthenticated privilege escalation and unverified role assertions.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Any

from agent_registry.admin_rbac import AdminRole

PBKDF2_ITERATIONS = 600_000
PBKDF2_ALGORITHM = "sha256"

INSECURE_PASSWORDS = {
    "AdminTrust#2026!Secured",
    "PolicyTrust#2026!Secured",
    "FinanceTrust#2026!Secured",
    "AuditorTrust#2026!Secured",
    "admin",
    "password",
    "changeme",
    "secret",
}


@dataclass
class AdminUser:
    username: str
    role: AdminRole
    salt: str
    password_hash: str
    display_name: str = ""


class AdminAuthManager:
    """
    Manages administrator accounts, salted password hashing, and authentication verification.
    """

    _users: dict[str, AdminUser] = {}
    _initialized: bool = False

    @staticmethod
    def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
        """Generate a random salt and compute PBKDF2-HMAC-SHA256 password hash."""
        if not password:
            raise ValueError("Password must not be empty.")
        if salt is None:
            salt = secrets.token_bytes(16)
        derived = hashlib.pbkdf2_hmac(
            PBKDF2_ALGORITHM,
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        return salt.hex(), derived.hex()

    @staticmethod
    def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
        """Verify candidate password against stored salt and hash using constant-time comparison."""
        if not password or not salt_hex or not hash_hex:
            return False
        try:
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            derived = hashlib.pbkdf2_hmac(
                PBKDF2_ALGORITHM,
                password.encode("utf-8"),
                salt,
                PBKDF2_ITERATIONS,
            )
            return secrets.compare_digest(derived, expected)
        except (ValueError, TypeError):
            return False

    @classmethod
    def initialize_default_users(cls, force: bool = False) -> None:
        """Initialize built-in administrator accounts from environment or secure defaults."""
        if cls._initialized and not force:
            return

        cls._users.clear()

        # Configurable credentials via environment variables with strong defaults
        default_accounts = [
            (
                "admin",
                AdminRole.SYSTEM_ADMIN,
                os.environ.get("AGENTTRUST_ADMIN_PASSWORD", "AdminTrust#2026!Secured"),
                "System Administrator",
            ),
            (
                "policy_admin",
                AdminRole.POLICY_ADMIN,
                os.environ.get("AGENTTRUST_POLICY_ADMIN_PASSWORD")
                or os.environ.get("AGENTTRUST_POLICY_PASSWORD")
                or "PolicyTrust#2026!Secured",
                "Security Policy Administrator",
            ),
            (
                "finance_approver",
                AdminRole.FINANCE_APPROVER,
                os.environ.get("AGENTTRUST_FINANCE_APPROVER_PASSWORD")
                or os.environ.get("AGENTTRUST_APPROVER_PASSWORD")
                or "FinanceTrust#2026!Secured",
                "Finance Transaction Approver",
            ),
            (
                "auditor",
                AdminRole.AUDITOR,
                os.environ.get("AGENTTRUST_AUDITOR_PASSWORD", "AuditorTrust#2026!Secured"),
                "Independent Compliance Auditor",
            ),
        ]

        env_profile = os.environ.get("AGENTTRUST_ENV", "development").lower()
        if env_profile in ("production", "prod"):
            for username, role, password, display_name in default_accounts:
                if password in INSECURE_PASSWORDS or len(password) < 16:
                    raise RuntimeError(
                        f"SECURITY VIOLATION: Production environment forbids default or weak password for '{username}'. "
                        f"Configure explicit strong credentials (>= 16 characters) via AGENTTRUST_{username.upper()}_PASSWORD."
                    )

        for username, role, password, display_name in default_accounts:
            salt_hex, hash_hex = cls.hash_password(password)
            cls._users[username] = AdminUser(
                username=username,
                role=role,
                salt=salt_hex,
                password_hash=hash_hex,
                display_name=display_name,
            )

        cls._initialized = True

    @classmethod
    def authenticate(cls, username: str, password: str) -> AdminUser | None:
        """
        Verify credentials and return AdminUser on success, or None on failure.
        Uses constant-time comparison to prevent timing side-channel attacks.
        """
        if not cls._initialized:
            cls.initialize_default_users()

        user = cls._users.get(username.strip())
        if not user:
            # Execute dummy hash to prevent user enumeration timing attacks
            cls.verify_password("dummy_password", "0" * 32, "0" * 64)
            return None

        if cls.verify_password(password, user.salt, user.password_hash):
            return user
        return None

    @classmethod
    def get_user(cls, username: str) -> AdminUser | None:
        """Retrieve user record by username."""
        if not cls._initialized:
            cls.initialize_default_users()
        return cls._users.get(username.strip())

    @classmethod
    def register_or_update_user(
        cls,
        username: str,
        role: AdminRole,
        password: str,
        display_name: str = "",
    ) -> AdminUser:
        """Register or update an administrative user with hashed password."""
        if not cls._initialized:
            cls.initialize_default_users()

        uname = username.strip()
        if not uname:
            raise ValueError("Username must not be empty.")

        salt_hex, hash_hex = cls.hash_password(password)
        user = AdminUser(
            username=uname,
            role=role,
            salt=salt_hex,
            password_hash=hash_hex,
            display_name=display_name or uname,
        )
        cls._users[uname] = user
        return user

    @classmethod
    def list_users(cls) -> list[dict[str, Any]]:
        """List active administrative users without exposing password hashes."""
        if not cls._initialized:
            cls.initialize_default_users()
        return [
            {
                "username": u.username,
                "role": u.role.value,
                "display_name": u.display_name,
            }
            for u in cls._users.values()
        ]


# Initialize default admin users upon module load
AdminAuthManager.initialize_default_users()
