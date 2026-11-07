"""
Client-Side Cryptographic Identity and PKCS#10 CSR Module.

Enforces the core security invariant that AgentTrust server never generates,
receives, handles, or persists an AI Agent's private signing key.
The agent client retains its private key within its local cryptographic boundary
(local KMS / SoftHSM2 / secure client process) and submits only PKCS#10
Certificate Signing Requests (CSR) with proof-of-possession.
"""

import datetime
import uuid
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager


def generate_agent_csr(
    private_key: rsa.RSAPrivateKey,
    agent_id: str,
    agent_name: str = "",
    organization: str = "OrgA",
    san_uri: str | None = None
) -> str:
    """
    Generates a standard PKCS#10 Certificate Signing Request (CSR) in PEM format.
    Binds the agent's identity attributes (Common Name, Organization, Given Name)
    and Subject Alternative Name (SAN), signed by the agent's private key.
    """
    subject_attributes = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
    ]
    if agent_name:
        subject_attributes.append(x509.NameAttribute(NameOID.GIVEN_NAME, agent_name))

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(subject_attributes)
    )

    # Subject Alternative Name extension with canonical URN
    effective_uri = san_uri or f"urn:agenttrust:agent:{agent_id}"
    san_extension = x509.SubjectAlternativeName([
        x509.UniformResourceIdentifier(effective_uri)
    ])
    builder = builder.add_extension(san_extension, critical=False)

    # Sign CSR with agent's local private key (Proof-of-Possession)
    csr = builder.sign(private_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class AgentClient:
    """
    Autonomous AI Agent Client representing the client-side cryptographic boundary.
    Owns and retains private keys locally; generates PKCS#10 CSRs for CA enrollment;
    and signs outbound gateway action requests.
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str = "",
        organization: str = "OrgA",
        key_size: int = 2048,
        private_key: rsa.RSAPrivateKey | None = None
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name or agent_id
        self.organization = organization
        self._private_key = private_key or KeyManager.generate_key_pair(key_size)
        self._public_key = self._private_key.public_key()
        self._certificate_pem: str | None = None
        self._certificate_fingerprint: str | None = None
        self._key_version: int = 1

    @property
    def public_key_pem(self) -> str:
        """Returns the public key PEM string (exportable)."""
        return KeyManager.public_key_to_pem(self._public_key)

    @property
    def private_key_pem(self) -> str:
        """Returns local private key PEM (retained within client boundary)."""
        return KeyManager.private_key_to_pem(self._private_key)

    @property
    def certificate_pem(self) -> str | None:
        return self._certificate_pem

    @property
    def certificate_fingerprint(self) -> str | None:
        return self._certificate_fingerprint

    def generate_csr(self, san_uri: str | None = None) -> str:
        """
        Generates a PKCS#10 CSR with proof-of-possession signature
        to be sent to the AgentTrust Certificate Authority.
        """
        return generate_agent_csr(
            private_key=self._private_key,
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            organization=self.organization,
            san_uri=san_uri
        )

    def install_certificate(self, cert_pem: str, fingerprint: str | None = None) -> None:
        """
        Installs the X.509 certificate returned by AgentTrust CA.
        Verifies that the certificate's public key matches the agent's local public key.
        """
        from identity_manager.certificate_manager import CertificateManager

        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        cert_pub_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        local_pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if cert_pub_bytes != local_pub_bytes:
            raise ValueError("CERTIFICATE_KEY_MISMATCH: Issued certificate public key does not match local key.")

        self._certificate_pem = cert_pem
        self._certificate_fingerprint = fingerprint or CertificateManager.calculate_fingerprint(cert_pem)

    def rotate_key(self, key_size: int = 2048) -> str:
        """
        Generates a new local private key pair and increments key version.
        Returns a new PKCS#10 CSR for key rotation.
        """
        self._private_key = KeyManager.generate_key_pair(key_size)
        self._public_key = self._private_key.public_key()
        self._certificate_pem = None
        self._certificate_fingerprint = None
        self._key_version += 1
        return self.generate_csr()

    def sign_request(self, payload: dict[str, Any]) -> str:
        """
        Signs canonical request payload using locally retained private key.
        """
        return SignatureManager.sign_request(payload, self.private_key_pem)

    def build_signed_action_request(
        self,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        amount: float = 0.0,
        request_id: str | None = None,
        nonce: str | None = None,
        idempotency_key: str | None = None,
        key_version: int | None = None
    ) -> dict[str, Any]:
        """
        Helper method to construct a complete, signed action payload
        ready for submission to the Action Gateway.
        """
        req_id = request_id or f"REQ-{uuid.uuid4().hex[:12].upper()}"
        req_nonce = nonce or f"NONCE-{uuid.uuid4().hex[:8].upper()}"
        now_iso = datetime.datetime.now(datetime.UTC).isoformat()
        k_ver = key_version if key_version is not None else self._key_version

        payload = {
            "request_id": req_id,
            "agent_id": self.agent_id,
            "action": action,
            "resource": resource,
            "parameters": parameters,
            "amount": amount,
            "nonce": req_nonce,
            "timestamp": now_iso,
            "key_version": k_ver,
            "idempotency_key": idempotency_key or f"IDEMP-{uuid.uuid4().hex[:12].upper()}"
        }

        # Calculate and bind signature
        signature = self.sign_request(payload)
        payload["signature"] = signature
        return payload
