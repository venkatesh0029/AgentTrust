import datetime
import hashlib
from typing import Tuple, Dict, Any, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from identity_manager.key_manager import KeyManager

class CertificateManager:
    """
    Manages Root Certificate Authority (CA) and X.509 Certificate issuance/validation for AI Agents.
    """

    def __init__(self, ca_common_name: str = "AgentTrust Root CA"):
        self.ca_common_name = ca_common_name
        self.ca_private_key = KeyManager.generate_key_pair(2048)
        self.ca_certificate = self._generate_root_ca_certificate()

    def _generate_root_ca_certificate(self) -> x509.Certificate:
        """Generates self-signed X.509 Root CA certificate."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentTrust Framework"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )
        return cert

    def issue_agent_certificate(
        self, agent_id: str, agent_name: str, validity_days: int = 365, start_offset_days: int = 0
    ) -> Tuple[str, str, str]:
        """
        Issues X.509 certificate for an AI agent signed by Root CA.
        Returns: (agent_pem_cert, agent_private_key_pem, cert_fingerprint)
        """
        agent_private_key = KeyManager.generate_key_pair(2048)
        agent_public_key = agent_private_key.public_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentTrust Managed Agent"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.GIVEN_NAME, agent_name)
        ])

        start_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=start_offset_days)
        end_time = start_time + datetime.timedelta(days=validity_days)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_certificate.subject)
            .public_key(agent_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(start_time)
            .not_valid_after(end_time)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        priv_pem = KeyManager.private_key_to_pem(agent_private_key)
        fingerprint = self.calculate_fingerprint(cert_pem)

        return cert_pem, priv_pem, fingerprint

    @staticmethod
    def calculate_fingerprint(cert_pem: str) -> str:
        """Calculates SHA-256 fingerprint string for certificate."""
        cert_bytes = cert_pem.encode('utf-8')
        return "SHA256:" + hashlib.sha256(cert_bytes).hexdigest().upper()

    def verify_agent_certificate(self, cert_pem: str) -> Dict[str, Any]:
        """
        Verifies certificate validity against Root CA signature and expiration.
        Returns dict with status and reason.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            now = datetime.datetime.now(datetime.timezone.utc)

            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                return {"valid": False, "reason": "CERTIFICATE_EXPIRED"}

            # Verify Root CA Signature
            from cryptography.hazmat.primitives.asymmetric import padding
            ca_public_key = self.ca_certificate.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )

            # Extract Subject CN (Agent ID)
            common_name = None
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break

            return {
                "valid": True,
                "agent_id": common_name,
                "reason": "CERTIFICATE_VALID"
            }
        except Exception as e:
            return {"valid": False, "reason": f"INVALID_CERTIFICATE: {str(e)}"}
