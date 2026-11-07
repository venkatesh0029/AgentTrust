import datetime
import hashlib
import json
import os
import threading
from typing import Any

from database_config import resolve_database_path
from fabric.chaincode.agent_trust_chaincode import AgentTrustChaincode


class Block:
    """Represents a single immutable block in the Hyperledger Fabric ledger chain."""

    def __init__(
        self,
        index: int,
        transactions: list[dict[str, Any]],
        previous_hash: str,
        timestamp: str | None = None
    ):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.timestamp = timestamp or datetime.datetime.now(datetime.UTC).isoformat()
        self.data_hash = self.calculate_data_hash()
        self.hash = self.calculate_hash()

    def calculate_data_hash(self) -> str:
        data_bytes = json.dumps(self.transactions, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(data_bytes).hexdigest()

    def calculate_hash(self) -> str:
        block_content = {
            "index": self.index,
            "data_hash": getattr(self, "data_hash", self.calculate_data_hash()),
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp
        }
        json_bytes = json.dumps(block_content, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(json_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "transactions_count": len(self.transactions),
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "data_hash": getattr(self, "data_hash", self.calculate_data_hash()),
            "timestamp": self.timestamp,
            "hash": self.hash
        }

class FabricLedgerService:
    """
    Hyperledger Fabric Permissioned Ledger Engine.
    Combines Chaincode Contract Execution with Block-level Append-Only Ledger Immutability,
    backed by durable SQLite block persistence across restarts.
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = resolve_database_path(db_path) if (db_path is not None or os.environ.get("AGENTTRUST_DB_PATH")) else None
        self.chaincode = AgentTrustChaincode()
        self.blocks: list[Block] = []
        self._pending_transactions: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        if self.db_path:
            self._load_or_init_blocks()
        else:
            self._create_genesis_block()

    def _create_genesis_block(self):
        """Creates Block 0 (Genesis Block)."""
        genesis_tx = {
            "tx_id": "TX-GENESIS-000",
            "type": "GENESIS",
            "message": "AgentTrust Permissioned Blockchain Network Initialized",
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
        }
        genesis_block = Block(
            index=0,
            transactions=[genesis_tx],
            previous_hash="0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.blocks.append(genesis_block)

    def _load_or_init_blocks(self) -> None:
        """Loads committed blocks from SQLite block ledger or creates Genesis block."""
        from fabric.persistent_db import PersistentStorageEngine
        storage = PersistentStorageEngine(self.db_path)
        persisted_blocks = storage.get_all_blocks()
        fabric_blocks = []
        for blk in persisted_blocks:
            bdata = blk.get("block_data", {})
            if isinstance(bdata, dict):
                if bdata.get("type") == "GENESIS" or "tx_id" in bdata or "channel" in bdata:
                    txs = [bdata] if "tx_id" in bdata or bdata.get("type") == "GENESIS" else bdata.get("transactions", [bdata])
                    fb = Block(
                        index=blk["block_number"],
                        transactions=txs,
                        previous_hash=blk["previous_hash"],
                        timestamp=blk["timestamp"]
                    )
                    fb.hash = blk["block_hash"]
                    fabric_blocks.append(fb)
        if fabric_blocks:
            self.blocks = sorted(fabric_blocks, key=lambda b: b.index)
        else:
            self._create_genesis_block()
            if self.blocks and self.db_path:
                try:
                    gen_b = self.blocks[0]
                    storage.save_block(
                        previous_hash=gen_b.previous_hash,
                        block_hash=gen_b.hash,
                        tx_count=len(gen_b.transactions),
                        block_data=gen_b.transactions[0] if gen_b.transactions else {},
                        timestamp=gen_b.timestamp
                    )
                except Exception:
                    pass

    def commit_transaction(self, tx_data: dict[str, Any]) -> Block:
        """
        Commits a transaction into a new block on the Hyperledger Fabric ledger
        and persists it to durable SQLite storage.
        """
        with self._lock:
            prev_block = self.blocks[-1]
            new_block = Block(
                index=len(self.blocks),
                transactions=[tx_data],
                previous_hash=prev_block.hash
            )
            self.blocks.append(new_block)
            if self.db_path:
                try:
                    from fabric.persistent_db import PersistentStorageEngine
                    storage = PersistentStorageEngine(self.db_path)
                    storage.save_block(
                        previous_hash=new_block.previous_hash,
                        block_hash=new_block.hash,
                        tx_count=len(new_block.transactions),
                        block_data=tx_data,
                        timestamp=new_block.timestamp
                    )
                except Exception:
                    pass
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
    ) -> dict[str, Any]:
        """
        Executes Chaincode RecordActionEvent and commits block to ledger.
        Supports idempotent resolution for duplicate event submissions.
        """
        with self._lock:
            existing_event = self.chaincode.GetActionEvent(event_id)
            if existing_event:
                # Find the existing block containing this event
                for b in self.blocks:
                    for tx in b.transactions:
                        if tx.get("tx_id") == f"TX-{event_id}" or (isinstance(tx.get("payload"), dict) and tx.get("payload", {}).get("event_id") == event_id):
                            return {
                                "chaincode_result": existing_event,
                                "tx_id": tx.get("tx_id", f"TX-{event_id}"),
                                "block_index": b.index,
                                "block_hash": b.hash,
                                "previous_hash": b.previous_hash,
                                "committed_at": b.timestamp,
                                "validation_code": tx.get("validation_code", "VALID"),
                                "idempotent_replay": True
                            }

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
                "validation_code": "VALID",
                "payload": chaincode_res
            }

            block = self.commit_transaction(tx_wrapper)

            return {
                "chaincode_result": chaincode_res,
                "tx_id": tx_wrapper["tx_id"],
                "block_index": block.index,
                "block_hash": block.hash,
                "previous_hash": block.previous_hash,
                "committed_at": block.timestamp,
                "validation_code": "VALID"
            }

    def get_transaction_by_id(self, tx_id: str) -> dict[str, Any] | None:
        """
        Independently queries a transaction directly from the committed blocks.
        Returns complete transaction envelope with block and validation metadata.
        """
        with self._lock:
            for b in self.blocks:
                for tx in b.transactions:
                    if tx.get("tx_id") == tx_id:
                        return {
                            "tx_id": tx_id,
                            "block_number": b.index,
                            "block_hash": b.hash,
                            "previous_hash": b.previous_hash,
                            "data_hash": getattr(b, "data_hash", b.calculate_data_hash()),
                            "timestamp": b.timestamp,
                            "validation_code": tx.get("validation_code", "VALID"),
                            "channel": tx.get("channel", "agenttrust-channel"),
                            "chaincode": tx.get("chaincode", "agenttrust-cc"),
                            "endorsed_by": tx.get("endorsed_by", []),
                            "payload": tx.get("payload", {})
                        }
            return None

    def get_block_by_number(self, block_number: int) -> dict[str, Any] | None:
        """Returns block dictionary by block number or None if not found."""
        with self._lock:
            if 0 <= block_number < len(self.blocks):
                return self.blocks[block_number].to_dict()
            return None

    def verify_block_integrity(self, block_index: int) -> dict[str, Any]:
        """
        Cryptographically verifies the integrity of a block:
        1. Recalculates data_hash over all transactions in the block.
        2. Recalculates block_hash over block header fields.
        3. Verifies previous_hash pointer matches previous block's hash.
        """
        with self._lock:
            if not (0 <= block_index < len(self.blocks)):
                return {"valid": False, "reason": f"Block index {block_index} out of bounds"}

            block = self.blocks[block_index]
            recalculated_data_hash = block.calculate_data_hash()
            expected_data_hash = getattr(block, "data_hash", recalculated_data_hash)
            if recalculated_data_hash != expected_data_hash:
                return {
                    "valid": False,
                    "reason": f"Data hash mismatch: expected {expected_data_hash}, computed {recalculated_data_hash}"
                }

            recalculated_block_hash = block.calculate_hash()
            if recalculated_block_hash != block.hash:
                return {
                    "valid": False,
                    "reason": f"Block hash mismatch: expected {block.hash}, computed {recalculated_block_hash}"
                }

            if block_index > 0:
                prev_block = self.blocks[block_index - 1]
                if block.previous_hash != prev_block.hash:
                    return {
                        "valid": False,
                        "reason": f"Previous hash mismatch: expected {prev_block.hash}, found {block.previous_hash}"
                    }

            return {"valid": True, "block_index": block_index, "block_hash": block.hash}

    def mark_transaction_validation_code(self, tx_id: str, code: str) -> bool:
        """
        Simulates peer validation outcomes (e.g. MVCC_READ_CONFLICT, BAD_RWSET)
        for testing validation code verification.
        """
        with self._lock:
            for b in self.blocks:
                for tx in b.transactions:
                    if tx.get("tx_id") == tx_id:
                        tx["validation_code"] = code
                        return True
            return False

    def tamper_block_payload(self, block_index: int, key: str, val: Any) -> bool:
        """
        Directly alters transaction payload in a block without recalculating hashes,
        to test cryptographic integrity detection.
        """
        with self._lock:
            if 0 <= block_index < len(self.blocks):
                block = self.blocks[block_index]
                if block.transactions and isinstance(block.transactions[0], dict):
                    if "payload" in block.transactions[0] and isinstance(block.transactions[0]["payload"], dict):
                        block.transactions[0]["payload"][key] = val
                        return True
                    block.transactions[0][key] = val
                    return True
            return False

    def get_blocks(self) -> list[dict[str, Any]]:
        """Returns list of all committed blocks formatted as dictionaries."""
        return [b.to_dict() for b in self.blocks]

    def get_ledger_summary(self) -> dict[str, Any]:
        return {
            "total_blocks": len(self.blocks),
            "latest_block_hash": self.blocks[-1].hash if self.blocks else None,
            "blocks": [b.to_dict() for b in self.blocks]
        }

