"""
Centralized Secret Lifecycle & Rotation Management Package for AgentTrust.
"""

from secret_manager.secret_models import SecretRecord, ValidationResult
from secret_manager.secret_provider import (
    CrossProcessLock,
    EnvironmentSecretProvider,
    PersistentEncryptedSecretProvider,
    ProductionConfigurationError,
    SecretProvider,
    VaultKmsSecretProvider,
    get_centralized_secret_provider,
)

__all__ = [
    "SecretRecord",
    "ValidationResult",
    "SecretProvider",
    "PersistentEncryptedSecretProvider",
    "EnvironmentSecretProvider",
    "VaultKmsSecretProvider",
    "ProductionConfigurationError",
    "CrossProcessLock",
    "get_centralized_secret_provider",
]
