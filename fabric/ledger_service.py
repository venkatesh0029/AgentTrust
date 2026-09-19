import hashlib
import json
import datetime
from typing import List, Dict, Any, Optional
from fabric.chaincode.agent_trust_chaincode import AgentTrustChaincode

class Block:
    """Represents a single immutable block in the Hyperledger Fabric ledger chain."""

    def __init__(
        self,
        index: int,
        transactions: List[Dict[str, Any]],
        previous_hash: str,
        timestamp: Optional[str] = None
    ):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_content = {
            "index": self.index,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp
        }
        json_bytes = json.dumps(block_content, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(json_bytes).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "transactions_count": len(self.transactions),
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "hash": self.hash
        }

class FabricLedgerService:
    """
    Hyperledger Fabric Permissioned Ledger Engine.
    Combines Chaincode Contract Execution with Block-level Append-Only Ledger Immutability.
    """

    def __init__(self):
        self.chaincode = AgentTrustChaincode()
        self.blocks: List[Block] = []
        self._pending_transactions: List[Dict[str, Any]] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        """Creates Block 0 (Genesis Block)."""
        genesis_tx = {
            "tx_id": "TX-GENESIS-000",
            "type": "GENESIS",
            "message": "AgentTrust Permissioned Blockchain Network Initialized",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        genesis_block = Block(
            index=0,
            transactions=[genesis_tx],
            previous_hash="0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.blocks.append(genesis_block)

    def commit_transaction(self, tx_data: Dict[str, Any]) -> Block:
        """
        Commits a transaction into a new block on the Hyperledger Fabric ledger.
        """
        prev_block = self.blocks[-1]
        new_block = Block(
            index=len(self.blocks),
            transactions=[tx_data],
            previous_hash=prev_block.hash
        )
        self.blocks.append(new_block)
        return new_block

    def record_audit_event(
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
        """
        Executes Chaincode RecordActionEvent and commits block to ledger.
        """
        chaincode_res = self.chaincode.RecordActionEvent(
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

        tx_wrapper = {
            "tx_id": f"TX-{event_id}",
            "channel": "agenttrust-channel",
            "chaincode": "agenttrust-cc",
            "endorsed_by": ["Peer0.Org1.AgentTrust", "Peer0.Org2.AgentTrust"],
            "payload": chaincode_res
        }

        block = self.commit_transaction(tx_wrapper)

        return {
            "chaincode_result": chaincode_res,
            "block_index": block.index,
            "block_hash": block.hash,
            "previous_hash": block.previous_hash,
            "committed_at": block.timestamp
        }

    def get_ledger_summary(self) -> Dict[str, Any]:
        return {
            "total_blocks": len(self.blocks),
            "latest_block_hash": self.blocks[-1].hash if self.blocks else None,
            "blocks": [b.to_dict() for b in self.blocks]
        }
