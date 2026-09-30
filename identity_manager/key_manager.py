import os
from functools import lru_cache
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class KeyManager:
    """
    Manages RSA private and public keys for AI Agents, Root CA, and Gateway.
    Supports Private Key Encryption at Rest and LRU-cached key loading for performance.
    """

    @staticmethod
    def generate_key_pair(key_size: int = 2048):
        """Generates a new RSA private key object."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

    @staticmethod
    def private_key_to_pem(private_key, password: Optional[str] = None) -> str:
        """
        Converts private key object to PEM string.
        Encrypts with BestAvailableEncryption (AES-256) using provided password or environment key storage passphrase.
        """
        passphrase = password or os.environ.get("KEY_STORAGE_PASSPHRASE", "agenttrust_default_aes256_passphrase_2026")
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
        else:
            encryption = serialization.NoEncryption()

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        return pem.decode('utf-8')

    @staticmethod
    @lru_cache(maxsize=1024)
    def pem_to_private_key(pem_str: str, password: Optional[str] = None):
        """Loads RSA private key object from PEM string (supports AES-256 encrypted PEMs). Cached for performance."""
        passphrase = password or os.environ.get("KEY_STORAGE_PASSPHRASE", "agenttrust_default_aes256_passphrase_2026")
        pass_bytes = passphrase.encode('utf-8') if passphrase else None
        try:
            return serialization.load_pem_private_key(
                pem_str.encode('utf-8'),
                password=pass_bytes
            )
        except TypeError:
            # Fallback if unencrypted PEM passed
            return serialization.load_pem_private_key(
                pem_str.encode('utf-8'),
                password=None
            )

    @staticmethod
    def public_key_to_pem(public_key) -> str:
        """Converts public key object to PEM encoded string."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    @lru_cache(maxsize=1024)
    def pem_to_public_key(pem_str: str):
        """Loads RSA public key object from PEM string. Cached for performance."""
        return serialization.load_pem_public_key(
            pem_str.encode('utf-8')
        )

