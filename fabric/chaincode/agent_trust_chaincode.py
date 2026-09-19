import json
import hashlib
import datetime
from typing import Dict, Any, List, Optional

class AgentTrustChaincode:
    """
    Hyperledger Fabric Smart Contract (Chaincode) logic for AgentTrust.
    Manages World State Key-Value store and transactional audit events on-chain.
    """

    def __init__(self):
        # World State storage (Simulates CouchDB/LevelDB state DB in Fabric Peer)
        self.world_state: Dict[str, str] = {}
        # Transaction History log
        self.tx_history: List[Dict[str, Any]] = []

    def _put_state(self, key: str, value_dict: Dict[str, Any]) -> None:
        """Puts key-value object into World State DB."""
        self.world_state[key] = json.dumps(value_dict, sort_keys=True)

    def _get_state(self, key: str) -> Optional[Dict[str, Any]]:
        """Gets key-value object from World State DB."""
        val = self.world_state.get(key)
        if val:
            return json.loads(val)
        return None

    # --- Agent Lifecycle Functions ---
    def RegisterAgent(self, agent_id: str, owner: str, cert_fingerprint: str, status: str = "ACTIVE") -> Dict[str, Any]:
        key = f"AGENT_{agent_id}"
        agent_data = {
            "docType": "agent",
            "agent_id": agent_id,
            "owner": owner,
            "certificate_fingerprint": cert_fingerprint,
            "status": status,
            "registered_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._put_state(key, agent_data)
        return agent_data

    def GetAgent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self._get_state(f"AGENT_{agent_id}")

    def UpdateAgentStatus(self, agent_id: str, new_status: str) -> bool:
        agent = self.GetAgent(agent_id)
        if not agent:
            return False
        agent["status"] = new_status
        agent["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._put_state(f"AGENT_{agent_id}", agent)
        return True

    def RevokeAgent(self, agent_id: str) -> bool:
        return self.UpdateAgentStatus(agent_id, "REVOKED")

    def SuspendAgent(self, agent_id: str) -> bool:
        return self.UpdateAgentStatus(agent_id, "SUSPENDED")

    # --- Policy Functions ---
    def RegisterPolicy(self, policy_id: str, agent_id: str, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        key = f"POLICY_{policy_id}"
        policy_record = {
            "docType": "policy",
            "policy_id": policy_id,
            "agent_id": agent_id,
            "policy_data": policy_data,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._put_state(key, policy_record)
        return policy_record

    def GetPolicy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        return self._get_state(f"POLICY_{policy_id}")

    # --- Action Event Functions ---
    def RecordActionEvent(
        self,
        event_id: str,
        request_id: str,
        agent_id: str,
        action: str,
        resource: str,
        decision: str,
        reason: str,
        policy_id: str,
        policy_version: str,
        evidence_reference: str,
        evidence_hash: str
    ) -> Dict[str, Any]:
        key = f"EVENT_{event_id}"
        event_record = {
            "docType": "action_event",
            "event_id": event_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "evidence_reference": evidence_reference,
            "evidence_hash": evidence_hash,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._put_state(key, event_record)
        self.tx_history.append(event_record)
        return event_record

    def GetActionEvent(self, event_id: str) -> Optional[Dict[str, Any]]:
        return self._get_state(f"EVENT_{event_id}")

    def QueryEventsByAgent(self, agent_id: str) -> List[Dict[str, Any]]:
        results = []
        for key, val_str in self.world_state.items():
            if key.startswith("EVENT_"):
                data = json.loads(val_str)
                if data.get("agent_id") == agent_id:
                    results.append(data)
        return results

    def QueryEventsByDecision(self, decision: str) -> List[Dict[str, Any]]:
        results = []
        for key, val_str in self.world_state.items():
            if key.startswith("EVENT_"):
                data = json.loads(val_str)
                if data.get("decision") == decision:
                    results.append(data)
        return results

    def recordEvidence(
        self,
        request_id: str,
        agent_id: str,
        evidence_hash: str,
        decision: str,
        policy_version: str = "1.0",
        organization: str = "OrgA",
        caller_org: str = "OrgA"
    ) -> Dict[str, Any]:
        """
        Hyperledger Fabric chaincode function: recordEvidence
        Stores audit evidence hashes on-chain after caller authorization check.
        """
        # Fabric MSP Authorization Check
        if caller_org and caller_org not in {"OrgA", "OrgB", "AgentTrustGatewayMSP"}:
            raise PermissionError(f"Fabric Authorization Failure: MSP '{caller_org}' unauthorized to record evidence.")

        key = f"EVID_{request_id}"
        tx_id = f"FAB-TX-{hashlib.sha256(f'{request_id}:{datetime.datetime.now()}'.encode()).hexdigest()[:12]}"
        
        record = {
            "docType": "evidence_record",
            "tx_id": tx_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "evidence_hash": evidence_hash,
            "decision": decision,
            "policy_version": policy_version,
            "organization": organization,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._put_state(key, record)
        self.tx_history.append(record)
        return record

    def getEvidence(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Hyperledger Fabric chaincode function: getEvidence"""
        return self._get_state(f"EVID_{request_id}")

    def verifyEvidence(self, request_id: str, recalculated_hash: str) -> Dict[str, Any]:
        """Hyperledger Fabric chaincode function: verifyEvidence"""
        record = self.getEvidence(request_id)
        if not record:
            return {"found": False, "verified": False, "status": "NOT_FOUND"}

        stored_hash = record.get("evidence_hash", "")
        is_valid = (stored_hash.lower() == recalculated_hash.lower())
        return {
            "found": True,
            "request_id": request_id,
            "stored_hash": stored_hash,
            "recalculated_hash": recalculated_hash,
            "verified": is_valid,
            "status": "VERIFIED" if is_valid else "TAMPERING_DETECTED"
        }

    def getTransactionMetadata(self, tx_id: str) -> Optional[Dict[str, Any]]:
        """Hyperledger Fabric chaincode function: getTransactionMetadata"""
        for tx in self.tx_history:
            if tx.get("tx_id") == tx_id:
                return tx
        return None

    def GetEvidenceHash(self, request_id: str) -> Optional[str]:
        record = self.getEvidence(request_id)
        if record:
            return record.get("evidence_hash")
        for key, val_str in self.world_state.items():
            if key.startswith("EVENT_"):
                data = json.loads(val_str)
                if data.get("request_id") == request_id:
                    return data.get("evidence_hash")
        return None

    def VerifyEvidenceReference(self, evidence_reference: str, recalculated_hash: str) -> Dict[str, Any]:
        for key, val_str in self.world_state.items():
            if key.startswith("EVENT_") or key.startswith("EVID_"):
                data = json.loads(val_str)
                if data.get("evidence_reference") == evidence_reference or data.get("request_id") in evidence_reference:
                    stored_hash = data.get("evidence_hash")
                    is_valid = (stored_hash.lower() == recalculated_hash.lower())
                    return {
                        "found": True,
                        "stored_hash": stored_hash,
                        "recalculated_hash": recalculated_hash,
                        "verified": is_valid,
                        "status": "VERIFIED" if is_valid else "TAMPERING_DETECTED"
                    }
        return {"found": False, "verified": False, "status": "NOT_FOUND"}
