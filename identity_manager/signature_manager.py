import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from identity_manager.key_manager import KeyManager


class SignatureManager:
    """
    Handles request canonical serialization, payload hashing, digital signature generation and verification.
    Supports both RSA 2048-bit PSS and ECDSA secp256r1 key signatures.
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
        Signs canonical request payload using agent private key (RSA or ECDSA).
        Returns base64-encoded digital signature string.
        """
        private_key = KeyManager.pem_to_private_key(private_key_pem)
        canonical_data = SignatureManager.canonical_serialize(payload)

        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                canonical_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                canonical_data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Unsupported key algorithm for signing")

        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(payload: dict, signature_b64: str, public_key_pem: str) -> bool:
        """
        Verifies digital signature against payload using agent public key (RSA or ECDSA).
        Returns True if valid, False otherwise.
        """
        try:
            public_key = KeyManager.pem_to_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            canonical_data = SignatureManager.canonical_serialize(payload)

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    canonical_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature,
                    canonical_data,
                    ec.ECDSA(hashes.SHA256())
                )
            else:
                return False
            return True
        except Exception:
            return False

