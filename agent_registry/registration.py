import datetime
from typing import Dict, Any, List, Optional
from identity_manager.certificate_manager import CertificateManager
from agent_registry.identity_store import IdentityStore
from agent_registry.status_manager import AgentStatus

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
        capabilities: List[str] = None,
        policy_id: str = "FIN-POLICY-001",
        organization: str = "OrgA",
        role: str = "procurement_agent",
        agent_version: str = "1.0",
        validity_days: int = 365
    ) -> Dict[str, Any]:
        """
        Registers a new AI Agent:
        1. Issues X.509 cert and RSA keypair.
        2. Calculates cert fingerprint & serial.
        3. Stores identity record.
        Returns complete agent registration payload including private key.
        """
        capabilities = capabilities or ["CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT", "TRANSFER_FUNDS"]
        cert_pem, priv_key_pem, fingerprint = self.cert_manager.issue_agent_certificate(
            agent_id=agent_id,
            agent_name=agent_name,
            validity_days=validity_days
        )

        serial_str = self._extract_serial_from_cert(cert_pem)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

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
        result["private_key"] = priv_key_pem
        return result

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

    def rotate_key(self, agent_id: str, validity_days: int = 365) -> Optional[Dict[str, Any]]:
        """
        Rotates an agent's RSA keypair and X.509 Certificate:
        1. Issues a new X.509 cert and RSA keypair.
        2. Increments key_version.
        3. Updates agent record in store.
        Returns updated agent payload including new private key.
        """
        agent = self.get_agent(agent_id)
        if not agent:
            return None

        cert_pem, priv_key_pem, fingerprint = self.cert_manager.issue_agent_certificate(
            agent_id=agent_id,
            agent_name=agent["agent_name"],
            validity_days=validity_days
        )
        serial_str = self._extract_serial_from_cert(cert_pem)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        agent["key_version"] = agent.get("key_version", 1) + 1
        agent["certificate"] = cert_pem
        agent["certificate_fingerprint"] = fingerprint
        agent["certificate_serial"] = serial_str
        agent["public_key"] = self._extract_public_key_from_cert(cert_pem)
        agent["updated_at"] = now

        self.store.save_agent(agent)

        res = agent.copy()
        res["private_key"] = priv_key_pem
        return res

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get_agent(agent_id)

    def list_agents(self) -> List[Dict[str, Any]]:
        return self.store.list_agents()

    def update_agent_status(self, agent_id: str, new_status: str, reason: str = "") -> bool:
        return self.store.update_status(agent_id, AgentStatus(new_status), reason)

    def revoke_agent(self, agent_id: str, reason: str = "REVOKED_BY_ADMIN") -> bool:
        return self.store.update_status(agent_id, AgentStatus.REVOKED, reason)

    def suspend_agent(self, agent_id: str, reason: str = "SUSPENDED_BY_ADMIN") -> bool:
        return self.store.update_status(agent_id, AgentStatus.SUSPENDED, reason)

    def reactivate_agent(self, agent_id: str, reason: str = "REACTIVATED_BY_ADMIN") -> bool:
        return self.store.update_status(agent_id, AgentStatus.ACTIVE, reason)

    def delete_agent(self, agent_id: str) -> bool:
        return self.store.delete_agent(agent_id)
