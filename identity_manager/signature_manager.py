import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from identity_manager.key_manager import KeyManager

class SignatureManager:
    """
    Handles request canonical serialization, payload hashing, digital signature generation and verification.
    """

    @staticmethod
    def canonical_serialize(payload: dict) -> bytes:
        """
        Converts dictionary into deterministic, sorted canonical JSON bytes.
        """
        canonical_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        return canonical_str.encode('utf-8')

    @staticmethod
    def sign_request(payload: dict, private_key_pem: str) -> str:
        """
        Signs canonical request payload using agent private RSA key.
        Returns base64-encoded digital signature string.
        """
        private_key = KeyManager.pem_to_private_key(private_key_pem)
        canonical_data = SignatureManager.canonical_serialize(payload)

        signature = private_key.sign(
            canonical_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(payload: dict, signature_b64: str, public_key_pem: str) -> bool:
        """
        Verifies digital signature against payload using agent public RSA key.
        Returns True if valid, False otherwise.
        """
        try:
            public_key = KeyManager.pem_to_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            canonical_data = SignatureManager.canonical_serialize(payload)

            public_key.verify(
                signature,
                canonical_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
