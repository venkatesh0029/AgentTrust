from typing import Dict, Any, List, Optional
from fabric.ledger_service import FabricLedgerService

class FabricClient:
    """
    Client interface for interacting with Hyperledger Fabric ledger & chaincode.
    """

    def __init__(self):
        self.ledger_service = FabricLedgerService()
        self.chaincode = self.ledger_service.chaincode

    def record_action_event(
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
        return self.ledger_service.record_audit_event(
            event_id=event_id,
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            policy_version=policy_version,
            evidence_reference=evidence_reference,
            evidence_hash=evidence_hash
        )

    def record_evidence(
        self,
        request_id: str,
        agent_id: str,
        evidence_hash: str,
        decision: str,
        policy_version: str = "1.0",
        organization: str = "OrgA",
        caller_org: str = "OrgA"
    ) -> Dict[str, Any]:
        """Invokes chaincode recordEvidence and commits block to ledger."""
        tx_record = self.chaincode.recordEvidence(
            request_id=request_id,
            agent_id=agent_id,
            evidence_hash=evidence_hash,
            decision=decision,
            policy_version=policy_version,
            organization=organization,
            caller_org=caller_org
        )
        block = self.ledger_service.commit_transaction({
            "tx_id": tx_record["tx_id"],
            "channel": "agenttrust-channel",
            "chaincode": "agenttrust-cc",
            "endorsed_by": ["Peer0.Org1.AgentTrust", "Peer0.Org2.AgentTrust"],
            "payload": tx_record
        })
        return {
            "chaincode_result": tx_record,
            "block_index": block.index,
            "block_hash": block.hash,
            "previous_hash": block.previous_hash,
            "committed_at": block.timestamp
        }

    def get_evidence(self, request_id: str) -> Optional[Dict[str, Any]]:
        return self.chaincode.getEvidence(request_id)

    def verify_evidence(self, request_id: str, recalculated_hash: str) -> Dict[str, Any]:
        return self.chaincode.verifyEvidence(request_id, recalculated_hash)

    def get_transaction_metadata(self, tx_id: str) -> Optional[Dict[str, Any]]:
        return self.chaincode.getTransactionMetadata(tx_id)

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        return self.chaincode.GetActionEvent(event_id)

    def query_by_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        return self.chaincode.QueryEventsByAgent(agent_id)

    def query_by_decision(self, decision: str) -> List[Dict[str, Any]]:
        return self.chaincode.QueryEventsByDecision(decision)

    def verify_evidence_hash(self, evidence_reference: str, recalculated_hash: str) -> Dict[str, Any]:
        return self.chaincode.VerifyEvidenceReference(evidence_reference, recalculated_hash)

    def get_blocks(self) -> Dict[str, Any]:
        return self.ledger_service.get_ledger_summary()
