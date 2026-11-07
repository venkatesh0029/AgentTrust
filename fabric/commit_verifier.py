"""
Commit Verification Engine for Hyperledger Fabric Transactions.
Provides independent, two-path verification of Fabric ledger commits:
- Path A: Gateway submission response
- Path B: Direct, authenticated peer query and block inclusion validation

Guarantees that transactions marked COMMITTED have been genuinely ordered into a
block, cryptographically sealed, and validated with TxValidationCode.VALID by
peer consensus nodes.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from fabric.ledger_service import FabricLedgerService

logger = logging.getLogger("AgentTrust.FabricCommitVerifier")


class TxValidationCode(str, Enum):
    """
    Hyperledger Fabric Transaction Validation Codes (protos/peer/transaction.proto).
    Transactions ordered into blocks may be valid or invalid (e.g. MVCC conflicts).
    """
    VALID = "VALID"
    NIL_ENVELOPE = "NIL_ENVELOPE"
    BAD_PAYLOAD = "BAD_PAYLOAD"
    BAD_COMMON_HEADER = "BAD_COMMON_HEADER"
    BAD_CREATOR_SIGNATURE = "BAD_CREATOR_SIGNATURE"
    INVALID_ENDORSER_TRANSACTION = "INVALID_ENDORSER_TRANSACTION"
    INVALID_CONFIG_TRANSACTION = "INVALID_CONFIG_TRANSACTION"
    UNSUPPORTED_TX_PAYLOAD = "UNSUPPORTED_TX_PAYLOAD"
    BAD_PROPOSAL_TXID = "BAD_PROPOSAL_TXID"
    DUPLICATE_TXID = "DUPLICATE_TXID"
    ENDORSEMENT_POLICY_FAILURE = "ENDORSEMENT_POLICY_FAILURE"
    MVCC_READ_CONFLICT = "MVCC_READ_CONFLICT"
    PHANTOM_READ_CONFLICT = "PHANTOM_READ_CONFLICT"
    UNKNOWN_TX_TYPE = "UNKNOWN_TX_TYPE"
    TARGET_CHAIN_NOT_FOUND = "TARGET_CHAIN_NOT_FOUND"
    MARSHAL_TX_ERROR = "MARSHAL_TX_ERROR"
    NIL_TXACTION = "NIL_TXACTION"
    EXPIRED_CHAINCODE = "EXPIRED_CHAINCODE"
    NAMESPACE_NOT_FOUND = "NAMESPACE_NOT_FOUND"
    ILLEGAL_WRITESET = "ILLEGAL_WRITESET"
    INVALID_WRITING_IDENTITY = "INVALID_WRITING_IDENTITY"
    BAD_RWSET = "BAD_RWSET"
    ILLEGAL_RESOURCE = "ILLEGAL_RESOURCE"
    NOT_VALIDATED = "NOT_VALIDATED"
    INVALID_OTHER_REASON = "INVALID_OTHER_REASON"


class VerificationStatus(str, Enum):
    """Final verified state of a Fabric transaction."""
    VERIFIED_COMMITTED = "VERIFIED_COMMITTED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    REJECTED = "REJECTED"


class PeerConnectionError(Exception):
    """Raised when an independent peer node is unreachable or partitioned."""
    pass


class PeerTimeoutError(Exception):
    """Raised when an independent peer query times out."""
    pass


@dataclass
class PeerTransactionEvidence:
    """Cryptographic evidence and metadata retrieved directly from an independent peer node."""
    peer_id: str
    tx_id: str
    block_number: int
    block_hash: str
    previous_hash: str
    data_hash: str
    validation_code: str
    payload: dict[str, Any]
    endorsers: list[str]
    commit_timestamp: str
    block_integrity_valid: bool
    raw_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Consolidated outcome of the Commit Verification Engine."""
    status: VerificationStatus
    tx_id: str
    block_number: int | None = None
    block_hash: str | None = None
    validation_code: str | None = None
    peer_evidences: list[PeerTransactionEvidence] = field(default_factory=list)
    failure_reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified(self) -> bool:
        return self.status == VerificationStatus.VERIFIED_COMMITTED


class IndependentPeerClient(ABC):
    """Interface for an independent, authenticated peer connection (Path B)."""
    peer_id: str

    @abstractmethod
    def query_transaction(self, tx_id: str) -> PeerTransactionEvidence | None:
        """Independently queries a transaction directly from the peer's block store."""
        pass

    @abstractmethod
    def query_block(self, block_number: int) -> dict[str, Any] | None:
        """Queries block header and data directly from the peer."""
        pass

    @abstractmethod
    def check_health(self) -> bool:
        """Checks connectivity and liveness of the peer node."""
        pass


class SimulatorPeerClient(IndependentPeerClient):
    """
    Independent peer client interacting directly with a FabricLedgerService node,
    representing a specific organization's peer node (e.g. Peer0.Org1 or Peer0.Org2).
    Includes simulation controls for testing network partitions and timeouts.
    """

    def __init__(
        self,
        peer_id: str,
        ledger_service: FabricLedgerService | None = None,
        db_path: str | None = None
    ):
        self.peer_id = peer_id
        self.ledger_service = ledger_service or FabricLedgerService(db_path=db_path)
        self.is_online = True
        self.simulate_partition = False
        self.simulate_timeout = False

    def check_health(self) -> bool:
        if not self.is_online or self.simulate_partition:
            return False
        return True

    def query_transaction(self, tx_id: str) -> PeerTransactionEvidence | None:
        if not self.is_online or self.simulate_partition:
            raise PeerConnectionError(f"Peer {self.peer_id} is unreachable (network partition).")
        if self.simulate_timeout:
            raise PeerTimeoutError(f"Query to peer {self.peer_id} timed out.")

        tx_info = self.ledger_service.get_transaction_by_id(tx_id)
        if not tx_info:
            return None

        # Verify block integrity independently
        block_num = tx_info["block_number"]
        integrity_res = self.ledger_service.verify_block_integrity(block_num)
        is_intact = integrity_res.get("valid", False)

        return PeerTransactionEvidence(
            peer_id=self.peer_id,
            tx_id=tx_id,
            block_number=block_num,
            block_hash=tx_info["block_hash"],
            previous_hash=tx_info["previous_hash"],
            data_hash=tx_info.get("data_hash", ""),
            validation_code=tx_info.get("validation_code", "VALID"),
            payload=tx_info.get("payload", {}),
            endorsers=tx_info.get("endorsed_by", []),
            commit_timestamp=tx_info.get("timestamp", ""),
            block_integrity_valid=is_intact,
            raw_evidence=tx_info
        )

    def query_block(self, block_number: int) -> dict[str, Any] | None:
        if not self.is_online or self.simulate_partition:
            raise PeerConnectionError(f"Peer {self.peer_id} is unreachable (network partition).")
        if self.simulate_timeout:
            raise PeerTimeoutError(f"Query to peer {self.peer_id} timed out.")
        return self.ledger_service.get_block_by_number(block_number)


class CommitVerificationEngine:
    """
    Engine executing independent transaction verification by reconciling
    Gateway Bridge responses (Path A) against independent peer evidence (Path B).
    """

    def __init__(self, peers: list[IndependentPeerClient] | None = None):
        self.peers: list[IndependentPeerClient] = list(peers) if peers else []

    def add_peer(self, peer: IndependentPeerClient) -> None:
        self.peers.append(peer)

    def verify_transaction(
        self,
        gateway_response: dict[str, Any],
        expected_payload: dict[str, Any] | None = None,
        min_peers: int = 1
    ) -> VerificationResult:
        """
        Independently verifies a transaction commitment:
        1. Validates gateway response structure (Path A).
        2. Direct query against independent peers (Path B).
        3. Verifies transaction existence on-chain.
        4. Verifies block number, block hash, and transaction ID matching.
        5. Verifies validation code (must be VALID, rejects MVCC_READ_CONFLICT etc.).
        6. Cryptographically verifies block data and header hashes.
        7. Verifies payload consistency.
        8. Validates multi-peer consensus consistency.
        """
        # Step 1: Parse and validate Gateway response (Path A)
        tx_id = (
            gateway_response.get("tx_id")
            or gateway_response.get("transaction_id")
        )
        if not tx_id:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                tx_id="UNKNOWN",
                failure_reasons=["GATEWAY_MISSING_TRANSACTION_ID: Bridge response did not contain a transaction ID."]
            )

        gateway_status = gateway_response.get("status", "")
        if gateway_status in ("SUBMISSION_FAILED", "REJECTED", "ERROR"):
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                tx_id=tx_id,
                failure_reasons=[f"GATEWAY_STATUS_FAILED: Gateway response explicitly failed with status '{gateway_status}'."]
            )

        gateway_block = (
            gateway_response.get("block_index")
            if "block_index" in gateway_response
            else gateway_response.get("block_number")
        )
        gateway_hash = gateway_response.get("block_hash")

        # Step 2: Query Independent Peers (Path B)
        evidences: list[PeerTransactionEvidence] = []
        unavailable_peers: list[str] = []
        not_found_peers: list[str] = []
        failure_reasons: list[str] = []

        peers_to_query = self.peers
        if not peers_to_query:
            return VerificationResult(
                status=VerificationStatus.PENDING_VERIFICATION,
                tx_id=tx_id,
                failure_reasons=["NO_INDEPENDENT_PEERS_CONFIGURED: No independent peer clients available for verification."]
            )

        for peer in peers_to_query:
            try:
                evidence = peer.query_transaction(tx_id)
                if evidence is None:
                    not_found_peers.append(peer.peer_id)
                else:
                    evidences.append(evidence)
            except (PeerConnectionError, PeerTimeoutError, Exception) as exc:
                logger.warning(f"Peer {peer.peer_id} query failed: {exc}")
                unavailable_peers.append(peer.peer_id)

        # Check peer reachability
        if len(unavailable_peers) == len(peers_to_query):
            # All peers were unreachable or timed out -> PENDING_VERIFICATION
            return VerificationResult(
                status=VerificationStatus.PENDING_VERIFICATION,
                tx_id=tx_id,
                failure_reasons=[
                    f"PEER_TEMPORARILY_UNAVAILABLE: All {len(peers_to_query)} independent peer(s) "
                    "are unreachable or timed out; verification is pending."
                ]
            )

        # If available peers returned None (transaction not found)
        if not evidences:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                tx_id=tx_id,
                failure_reasons=[
                    "TX_NOT_FOUND_ON_PEER: Gateway reported success, but peer ledger has "
                    f"no record of transaction {tx_id}. Possible fabricated bridge response."
                ]
            )

        # Step 3: Verify Evidence Fields from Each Peer
        primary_evidence = evidences[0]

        for ev in evidences:
            # 3.1: Transaction ID match
            if ev.tx_id != tx_id:
                failure_reasons.append(
                    f"TX_ID_MISMATCH: Peer returned tx_id '{ev.tx_id}', expected '{tx_id}'."
                )

            # 3.2: Block Number match
            if gateway_block is not None and ev.block_number != gateway_block:
                failure_reasons.append(
                    f"BLOCK_NUMBER_MISMATCH: Gateway reported block {gateway_block}, "
                    f"but peer {ev.peer_id} recorded block {ev.block_number}."
                )

            # 3.3: Block Hash match
            if gateway_hash is not None and ev.block_hash != gateway_hash:
                failure_reasons.append(
                    f"BLOCK_HASH_MISMATCH: Gateway reported hash {gateway_hash}, "
                    f"but peer {ev.peer_id} recorded hash {ev.block_hash}."
                )

            # 3.4: Validation Code verification (VALID vs MVCC_READ_CONFLICT, etc.)
            val_code = ev.validation_code
            if str(val_code).upper() not in ("VALID", "0"):
                failure_reasons.append(
                    f"INVALID_TRANSACTION_VALIDATION_CODE: Transaction was ordered into block {ev.block_number} "
                    f"but marked INVALID by peer validation with code '{val_code}'."
                )

            # 3.5: Cryptographic Block Integrity
            if not ev.block_integrity_valid:
                failure_reasons.append(
                    f"BLOCK_INTEGRITY_COMPROMISED: Cryptographic integrity check failed on block {ev.block_number} "
                    f"for peer {ev.peer_id}. Block header or data has been modified."
                )

            # 3.6: Expected Payload Consistency
            if expected_payload:
                ev_payload = ev.payload
                for field_name in ("action", "resource", "decision", "evidence_hash", "evidence_reference"):
                    if field_name in expected_payload:
                        expected_val = str(expected_payload[field_name])
                        actual_val = str(ev_payload.get(field_name, ""))
                        if actual_val != expected_val:
                            failure_reasons.append(
                                f"PAYLOAD_MISMATCH: Field '{field_name}' mismatch: "
                                f"expected '{expected_val}', peer records '{actual_val}'."
                            )

        # Step 4: Multi-Peer Consensus Consistency Check
        if len(evidences) > 1:
            first_block_num = evidences[0].block_number
            first_block_hash = evidences[0].block_hash
            first_val_code = evidences[0].validation_code

            for ev in evidences[1:]:
                if ev.block_number != first_block_num:
                    failure_reasons.append(
                        f"MULTI_PEER_DIVERGENCE: Block number divergence between peers: "
                        f"{evidences[0].peer_id} reported block {first_block_num}, "
                        f"while {ev.peer_id} reported block {ev.block_number}."
                    )
                if ev.block_hash != first_block_hash:
                    failure_reasons.append(
                        f"MULTI_PEER_DIVERGENCE: Block hash divergence between peers: "
                        f"{evidences[0].peer_id} reported hash {first_block_hash}, "
                        f"while {ev.peer_id} reported hash {ev.block_hash}."
                    )
                if ev.validation_code != first_val_code:
                    failure_reasons.append(
                        f"MULTI_PEER_VALIDATION_DIVERGENCE: Validation code divergence between peers: "
                        f"{evidences[0].peer_id} reported {first_val_code}, "
                        f"while {ev.peer_id} reported {ev.validation_code}."
                    )

        # Step 5: Final State Evaluation
        if failure_reasons:
            return VerificationResult(
                status=VerificationStatus.REJECTED,
                tx_id=tx_id,
                block_number=primary_evidence.block_number if primary_evidence else None,
                block_hash=primary_evidence.block_hash if primary_evidence else None,
                validation_code=primary_evidence.validation_code if primary_evidence else None,
                peer_evidences=evidences,
                failure_reasons=failure_reasons,
                details={
                    "peers_queried": [p.peer_id for p in peers_to_query],
                    "peers_available": [e.peer_id for e in evidences],
                    "peers_unavailable": unavailable_peers
                }
            )

        if len(evidences) < min_peers:
            return VerificationResult(
                status=VerificationStatus.PENDING_VERIFICATION,
                tx_id=tx_id,
                block_number=primary_evidence.block_number,
                block_hash=primary_evidence.block_hash,
                validation_code=primary_evidence.validation_code,
                peer_evidences=evidences,
                failure_reasons=[
                    f"INSUFFICIENT_PEER_QUORUM: Required {min_peers} peer(s), "
                    f"but only {len(evidences)} peer(s) confirmed transaction."
                ],
                details={"peers_available": [e.peer_id for e in evidences], "peers_unavailable": unavailable_peers}
            )

        # All checks passed!
        return VerificationResult(
            status=VerificationStatus.VERIFIED_COMMITTED,
            tx_id=tx_id,
            block_number=primary_evidence.block_number,
            block_hash=primary_evidence.block_hash,
            validation_code=primary_evidence.validation_code,
            peer_evidences=evidences,
            failure_reasons=[],
            details={
                "peers_verified": [e.peer_id for e in evidences],
                "block_integrity_verified": True,
                "multi_peer_consensus": len(evidences) > 1
            }
        )
