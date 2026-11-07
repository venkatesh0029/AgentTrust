import datetime
from typing import Any

from agent_registry.identity_store import IdentityStore
from agent_registry.status_manager import AgentStatus
from identity_manager.certificate_manager import CertificateManager


class AgentRegistry:
    """
    High-level manager for AI Agent Registration and lifecycle operations.
    """

    def __init__(self, cert_manager: CertificateManager, store: IdentityStore):
        self.cert_manager = cert_manager
        self.store = store

    def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        owner: str = "Finance Dept",
        capabilities: list[str] | None = None,
        policy_id: str = "FIN-POLICY-001",
        organization: str = "OrgA",
        role: str = "procurement_agent",
        agent_version: str = "1.0",
        validity_days: int = 365,
        public_key_pem: str | None = None,
        csr_pem: str | None = None
    ) -> dict[str, Any]:
        """
        Registers a new AI Agent:
        1. Issues X.509 cert using client CSR (preferred), public key, or legacy server key pair.
        2. Calculates cert fingerprint & serial.
        3. Stores identity record (private key is NEVER persisted in SQLite).
        Returns agent registration record.
        When csr_pem or public_key_pem is supplied, private_key is strictly None.
        """
        capabilities = capabilities or ["CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "TRANSFER_FUNDS"]

        if csr_pem:
            cert_pem, fingerprint = self.cert_manager.issue_agent_certificate_from_csr(
                csr_pem=csr_pem,
                agent_id=agent_id,
                agent_name=agent_name,
                validity_days=validity_days,
                organization=organization
            )
            priv_key_pem = None
            key_ref = f"client-csr://agenttrust/agents/{agent_id}"
        elif public_key_pem:
            cert_pem, fingerprint = self.cert_manager.issue_agent_certificate_from_pubkey(
                agent_id=agent_id,
                agent_name=agent_name,
                public_key_pem=public_key_pem,
                validity_days=validity_days
            )
            priv_key_pem = None
            key_ref = f"client-pubkey://agenttrust/agents/{agent_id}"
        else:
            cert_pem, priv_key_pem, fingerprint = self.cert_manager.issue_agent_certificate(
                agent_id=agent_id,
                agent_name=agent_name,
                validity_days=validity_days
            )
            key_ref = f"kms://agenttrust/agents/{agent_id}"

        serial_str = self._extract_serial_from_cert(cert_pem)
        now = datetime.datetime.now(datetime.UTC).isoformat()

        record = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "owner": owner,
            "organization": organization,
            "role": role,
            "certificate_fingerprint": fingerprint,
            "certificate_serial": serial_str,
            "certificate": cert_pem,
            "public_key": self._extract_public_key_from_cert(cert_pem),
            "key_reference": key_ref,
            "private_key": None,  # Do not persist private keys in identity store
            "key_version": 1,
            "capabilities": capabilities,
            "policy_id": policy_id,
            "status": AgentStatus.ACTIVE.value,
            "agent_version": agent_version,
            "registered_at": now,
            "updated_at": now
        }

        self.store.save_agent(record)

        result = record.copy()
        if priv_key_pem is not None:
            result["private_key"] = priv_key_pem
        return result

    def register_agent_csr(
        self,
        csr_pem: str,
        agent_id: str,
        agent_name: str,
        owner: str = "Finance Dept",
        capabilities: list[str] | None = None,
        policy_id: str = "FIN-POLICY-001",
        organization: str = "OrgA",
        role: str = "procurement_agent",
        agent_version: str = "1.0",
        validity_days: int = 365
    ) -> dict[str, Any]:
        """
        Registers an AI Agent strictly using client-generated PKCS#10 CSR.
        Guarantees that server never receives, handles, or returns agent private keys.
        """
        record = self.register_agent(
            agent_id=agent_id,
            agent_name=agent_name,
            owner=owner,
            capabilities=capabilities,
            policy_id=policy_id,
            organization=organization,
            role=role,
            agent_version=agent_version,
            validity_days=validity_days,
            csr_pem=csr_pem
        )
        record.pop("private_key", None)
        return record

    @staticmethod
    def _extract_public_key_from_cert(cert_pem: str) -> str:
        """Extracts public key PEM string from X.509 Certificate."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        public_key = cert.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @staticmethod
    def _extract_serial_from_cert(cert_pem: str) -> str:
        """Extracts serial number string from X.509 Certificate."""
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        return str(cert.serial_number)

    def rotate_key(
        self,
        agent_id: str,
        validity_days: int = 365,
        public_key_pem: str | None = None,
        csr_pem: str | None = None
    ) -> dict[str, Any] | None:
        """
        Rotates an agent's RSA keypair and X.509 Certificate.
        Supports client CSR, external public key, or CA generation.
        """
        agent = self.get_agent(agent_id)
        if not agent:
            return None

        if csr_pem:
            cert_pem, fingerprint = self.cert_manager.issue_agent_certificate_from_csr(
                csr_pem=csr_pem,
                agent_id=agent_id,
                agent_name=agent.get("agent_name", agent_id),
                validity_days=validity_days,
                organization=agent.get("organization", "OrgA")
            )
            priv_key_pem = None
        elif public_key_pem:
            cert_pem, fingerprint = self.cert_manager.issue_agent_certificate_from_pubkey(
                agent_id=agent_id,
                agent_name=agent["agent_name"],
                public_key_pem=public_key_pem,
                validity_days=validity_days
            )
            priv_key_pem = None
        else:
            cert_pem, priv_key_pem, fingerprint = self.cert_manager.issue_agent_certificate(
                agent_id=agent_id,
                agent_name=agent["agent_name"],
                validity_days=validity_days
            )

        serial_str = self._extract_serial_from_cert(cert_pem)
        now = datetime.datetime.now(datetime.UTC).isoformat()

        agent["key_version"] = agent.get("key_version", 1) + 1
        agent["certificate"] = cert_pem
        agent["certificate_fingerprint"] = fingerprint
        agent["certificate_serial"] = serial_str
        agent["public_key"] = self._extract_public_key_from_cert(cert_pem)
        agent["updated_at"] = now

        self.store.save_agent(agent)

        res = agent.copy()
        if priv_key_pem is not None:
            res["private_key"] = priv_key_pem
        else:
            res.pop("private_key", None)
        return res

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        return self.store.get_agent(agent_id)

    def list_agents(self) -> list[dict[str, Any]]:
        return self.store.list_agents()

    def update_agent_status(self, agent_id: str, new_status: str, reason: str = "") -> bool:
        return self.store.update_status(agent_id, AgentStatus(new_status), reason)

    def revoke_agent(self, agent_id: str, reason: str = "REVOKED_BY_ADMIN") -> bool:
        agent = self.get_agent(agent_id)
        if agent and agent.get("certificate_fingerprint"):
            self.cert_manager.revoke_certificate(agent["certificate_fingerprint"])
        return self.store.update_status(agent_id, AgentStatus.REVOKED, reason)

    def suspend_agent(self, agent_id: str, reason: str = "SUSPENDED_BY_ADMIN") -> bool:
        return self.store.update_status(agent_id, AgentStatus.SUSPENDED, reason)

    def reactivate_agent(self, agent_id: str, reason: str = "REACTIVATED_BY_ADMIN") -> bool:
        return self.store.update_status(agent_id, AgentStatus.ACTIVE, reason)

    def delete_agent(self, agent_id: str) -> bool:
        return self.store.delete_agent(agent_id)
