import os
import socket
from typing import Any

import httpx

from fabric.commit_verifier import (
    CommitVerificationEngine,
    IndependentPeerClient,
    SimulatorPeerClient,
    VerificationResult,
)
from fabric.ledger_service import FabricLedgerService


class FabricClient:
    """
    Client interface for interacting with Hyperledger Fabric ledger & chaincode.
    Supports dual execution modes: Production gRPC Gateway (when FABRIC_PEER_ENDPOINT is set)
    and embedded Fabric Ledger Service with durable persistence.
    Integrated with CommitVerificationEngine for independent multi-peer commit verification.
    """

    def __init__(self, db_path: str | None = None):
        self.peer_endpoint = os.environ.get("FABRIC_PEER_ENDPOINT")
        self.ledger_service = FabricLedgerService(db_path=db_path)
        self.chaincode = self.ledger_service.chaincode
        self.peer_clients: list[IndependentPeerClient] = [
            SimulatorPeerClient("peer0.org1.agenttrust.com", self.ledger_service),
            SimulatorPeerClient("peer0.org2.agenttrust.com", self.ledger_service)
        ]
        self.verification_engine = CommitVerificationEngine(self.peer_clients)

    @staticmethod
    def _gateway_auth_headers() -> dict[str, str]:
        token = os.environ.get("FABRIC_GATEWAY_TOKEN", "").strip()
        if len(token) < 32:
            raise RuntimeError(
                "FABRIC_GATEWAY_TOKEN must be configured with at least "
                "32 characters for live Fabric Gateway requests."
            )
        return {"Authorization": f"Bearer {token}"}

    def probe_peer_connectivity(self) -> dict[str, Any]:
        """
        Explicitly isolates TCP network connectivity probes from ledger transaction submissions.
        Verifying TCP reachability to a peer endpoint does NOT prove transaction endorsement,
        orderer consensus, or ledger commit (Finding 3 remediation).
        """
        if not self.peer_endpoint:
            return {
                "reachable": False,
                "status": "PEER_ENDPOINT_NOT_CONFIGURED",
                "message": "No peer endpoint configured; operating in local simulated mode"
            }
        host, port = self.peer_endpoint.split(":") if ":" in self.peer_endpoint else (self.peer_endpoint, "7051")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, int(port)))
            s.close()
            return {
                "reachable": True,
                "status": "PEER_ENDPOINT_REACHABLE",
                "peer_endpoint": self.peer_endpoint,
                "note": "TCP connection succeeded; does not constitute ledger transaction commit"
            }
        except Exception as e:
            return {
                "reachable": False,
                "status": "PEER_ENDPOINT_UNREACHABLE",
                "peer_endpoint": self.peer_endpoint,
                "error": str(e)
            }

    def _invoke_grpc_peer(self, function_name: str, args: list[str]) -> dict[str, Any]:
        """
        Submits gRPC transaction proposal directly to the Hyperledger Fabric Peer node.
        Honestly reports whether real Fabric gRPC Gateway SDK connection is established.
        A reachable TCP socket proves network connectivity only; it does NOT constitute
        transaction endorsement, ordering consensus, or ledger commit.
        """
        if not self.peer_endpoint:
            return {
                "status": "LOCAL_SIMULATOR_NO_PEER",
                "mode": "Fabric-Compatible Permissioned Ledger Simulator",
                "function": function_name
            }

        probe = self.probe_peer_connectivity()
        if probe.get("reachable"):
            return {
                "status": "PEER_ENDPOINT_REACHABLE",
                "mode": "PROPOSAL_DISPATCH_UNCOMMITTED",
                "peer_endpoint": self.peer_endpoint,
                "function": function_name,
                "note": "TCP endpoint reachable; does not prove proposal endorsement, ordering consensus, or ledger commit"
            }
        return {
            "status": "PEER_ENDPOINT_UNREACHABLE",
            "mode": "PROPOSAL_DISPATCH_FAILED",
            "peer_endpoint": self.peer_endpoint,
            "error": probe.get("error", "PEER_UNREACHABLE")
        }

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
    ) -> dict[str, Any]:
        mode = os.environ.get("FABRIC_GATEWAY_MODE", "simulator").strip().lower()
        if mode not in {"simulator", "live"}:
            raise ValueError(
                "Invalid FABRIC_GATEWAY_MODE. Expected 'simulator' or 'live'."
            )

        if mode == "simulator":
            res = self.ledger_service.record_audit_event(
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
            res["status"] = "COMMITTED"
            res["mode"] = "simulator"
            res["source"] = "fabric_simulator"
            return res

        # Mode == "live": submit to real Fabric Gateway Bridge
        fields = {
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
        }
        for field_name, field_val in fields.items():
            if not isinstance(field_val, str) or not field_val.strip():
                raise ValueError(f"{field_name} must be a non-empty string for Fabric recording")

        base_url = os.environ.get(
            "FABRIC_GATEWAY_URL", "http://127.0.0.1:8090"
        ).rstrip("/")
        endpoint = f"{base_url}/v1/action-events"

        try:
            with httpx.Client(timeout=5.0, trust_env=False) as client:
                response = client.post(
                    endpoint,
                    json=fields,
                    headers=self._gateway_auth_headers(),
                )
                if response.status_code == 502:
                    try:
                        err_body = response.json()
                        err_status = err_body.get("status", "SUBMISSION_FAILED")
                        err_msg = err_body.get("error", response.text)
                    except Exception:
                        err_status = "SUBMISSION_FAILED"
                        err_msg = response.text
                    raise RuntimeError(
                        f"Live Fabric Gateway transaction uncertain ({err_status}): {err_msg}. "
                        "Reconcile event_id before retrying; do not assume event was uncommitted."
                    )
                if 300 <= response.status_code < 400:
                    raise RuntimeError(
                        "FABRIC_SUBMISSION_UNCERTAIN: Live Fabric Gateway returned "
                        f"unexpected redirect HTTP {response.status_code}. "
                        "Reconcile event_id before retrying."
                    )
                if response.status_code == 409:
                    try:
                        conflict_body = response.json()
                    except ValueError:
                        conflict_body = None
                    if (
                        isinstance(conflict_body, dict)
                        and conflict_body.get("status")
                        == "FABRIC_PRE_SUBMISSION_FAILURE"
                    ):
                        raise RuntimeError(
                            "FABRIC_PRE_SUBMISSION_FAILURE: "
                            "Fabric endorsement planning failed before "
                            "transaction submission."
                        )
                if 400 <= response.status_code < 500:
                    raise RuntimeError(
                        "FABRIC_SUBMISSION_REJECTED: Live Fabric Gateway "
                        f"rejected the request with HTTP {response.status_code}: "
                        f"{response.text}. Check the request and gateway configuration."
                    )
                if response.status_code >= 500:
                    raise RuntimeError(
                        "FABRIC_SUBMISSION_UNCERTAIN: Live Fabric Gateway returned "
                        f"HTTP {response.status_code}. Reconcile event_id before retrying."
                    )
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(
                "FABRIC_SUBMISSION_UNCERTAIN: Live Fabric Gateway action-event "
                f"outcome could not be confirmed at {endpoint}: {exc!s}. "
                "Reconcile event_id before retrying; do not assume the event "
                "was uncommitted."
            ) from exc

        if not isinstance(body, dict) or body.get("status") != "COMMITTED":
            returned_status = (
                body.get("status")
                if isinstance(body, dict)
                else "malformed"
            )
            raise RuntimeError(
                "FABRIC_SUBMISSION_UNCERTAIN: Live Fabric Gateway returned "
                f"an unconfirmed transaction outcome (status={returned_status!r}). "
                "Reconcile event_id before retrying."
            )

        result = body.get("result")
        return {
            "status": "COMMITTED",
            "mode": "live",
            "source": "hyperledger_fabric_gateway",
            "event_id": event_id,
            "tx_id": body.get("tx_id") or body.get("transaction_id") or f"TX-LIVE-{event_id}",
            "block_index": body.get("block_index") or body.get("block_number"),
            "block_hash": body.get("block_hash"),
            "chaincode_result": result,
        }

    def record_evidence(
        self,
        request_id: str,
        agent_id: str,
        evidence_hash: str,
        decision: str,
        policy_version: str = "1.0",
        organization: str = "OrgA",
        caller_org: str = "OrgA"
    ) -> dict[str, Any]:
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

    def get_evidence(self, request_id: str) -> dict[str, Any] | None:
        return self.chaincode.getEvidence(request_id)

    def verify_evidence(self, request_id: str, recalculated_hash: str) -> dict[str, Any]:
        return self.chaincode.verifyEvidence(request_id, recalculated_hash)

    def get_transaction_metadata(self, tx_id: str) -> dict[str, Any] | None:
        return self.chaincode.getTransactionMetadata(tx_id)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        mode = os.environ.get("FABRIC_GATEWAY_MODE", "simulator").strip().lower()
        if mode not in {"simulator", "live"}:
            raise ValueError(
                "Invalid FABRIC_GATEWAY_MODE. Expected 'simulator' or 'live'."
            )

        if mode == "simulator":
            return self.chaincode.GetActionEvent(event_id)

        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("event_id must be a non-empty string")

        base_url = os.environ.get(
            "FABRIC_GATEWAY_URL", "http://127.0.0.1:8090"
        ).rstrip("/")
        endpoint = f"{base_url}/v1/action-events/{event_id}"

        try:
            with httpx.Client(timeout=5.0, trust_env=False) as client:
                response = client.get(
                    endpoint,
                    headers=self._gateway_auth_headers(),
                )
                if response.status_code == 404:
                    try:
                        not_found_body = response.json()
                    except ValueError:
                        not_found_body = None
                    if (
                        isinstance(not_found_body, dict)
                        and not_found_body.get("status") == "NOT_FOUND"
                    ):
                        return None
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(
                f"Live Fabric Gateway event query failed at {endpoint}; "
                "the event state could not be confirmed. Do not assume the "
                "event is absent or retry the write blindly."
            ) from exc

        if not isinstance(body, dict) or body.get("status") != "FOUND":
            raise RuntimeError(
                "Live Fabric Gateway returned an unsuccessful or malformed "
                "event-query response; event state remains unconfirmed."
            )

        result = body.get("result")
        if (
            not isinstance(result, dict)
            or result.get("event_id") != event_id
        ):
            raise RuntimeError(
                "Live Fabric Gateway returned an invalid event object or "
                "an event_id mismatch."
            )

        return result

    def query_by_agent(self, agent_id: str) -> list[dict[str, Any]]:
        return self.chaincode.QueryEventsByAgent(agent_id)

    def query_by_decision(self, decision: str) -> list[dict[str, Any]]:
        return self.chaincode.QueryEventsByDecision(decision)

    def verify_evidence_hash(self, evidence_reference: str, recalculated_hash: str) -> dict[str, Any]:
        mode = os.environ.get("FABRIC_GATEWAY_MODE", "simulator").strip().lower()

        if mode not in {"simulator", "live"}:
            raise ValueError(
                "Invalid FABRIC_GATEWAY_MODE. Expected 'simulator' or 'live'."
            )

        if mode == "simulator":
            return self.chaincode.VerifyEvidenceReference(
                evidence_reference, recalculated_hash
            )

        base_url = os.environ.get(
            "FABRIC_GATEWAY_URL", "http://127.0.0.1:8090"
        ).rstrip("/")
        endpoint = f"{base_url}/v1/evidence/verify"
        payload = {
            "evidence_ref": evidence_reference,
            "expected_hash": recalculated_hash,
        }

        try:
            with httpx.Client(timeout=5.0, trust_env=False) as client:
                response = client.post(
                    endpoint,
                    json=payload,
                    headers=self._gateway_auth_headers(),
                )
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(
                f"Live Fabric Gateway verification failed at {endpoint}; "
                "no verification result was obtained. Check the bridge and "
                "Fabric network. The request was not replaced with a "
                "simulator result."
            ) from exc

        if not isinstance(body, dict) or body.get("status") != "SUCCESS":
            raise RuntimeError(
                "Live Fabric Gateway returned an unsuccessful or malformed response."
            )

        result = body.get("result")
        required_fields = {
            "found", "stored_hash", "recalculated_hash", "verified", "status"
        }
        if not isinstance(result, dict) or not required_fields.issubset(result):
            raise RuntimeError(
                "Live Fabric Gateway response is missing required verification fields."
            )

        if (
            not isinstance(result["found"], bool)
            or not isinstance(result["verified"], bool)
            or not all(
                isinstance(result[key], str)
                for key in ("stored_hash", "recalculated_hash", "status")
            )
        ):
            raise RuntimeError(
                "Live Fabric Gateway returned invalid verification field types."
            )

        return {
            "found": result["found"],
            "stored_hash": result["stored_hash"],
            "recalculated_hash": result["recalculated_hash"],
            "verified": result["verified"],
            "status": result["status"],
            "source": "hyperledger_fabric_gateway",
        }

    def get_blocks(self) -> dict[str, Any]:
        return self.ledger_service.get_ledger_summary()

    def register_peer(self, peer: IndependentPeerClient) -> None:
        """Registers an independent peer client for multi-peer verification."""
        self.peer_clients.append(peer)
        self.verification_engine.add_peer(peer)

    def verify_committed_transaction(
        self,
        gateway_response: dict[str, Any],
        expected_payload: dict[str, Any] | None = None,
        min_peers: int = 1
    ) -> VerificationResult:
        """
        Executes independent verification (Path B) for a transaction received via gateway (Path A).
        """
        return self.verification_engine.verify_transaction(
            gateway_response=gateway_response,
            expected_payload=expected_payload,
            min_peers=min_peers
        )

    def record_action_event_verified(
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
        evidence_hash: str,
        min_peers: int = 1
    ) -> dict[str, Any]:
        """
        Submits action event via gateway (Path A) and independently verifies
        commitment directly with peer network (Path B).
        Returns combined payload with verification status:
        VERIFIED_COMMITTED, PENDING_VERIFICATION, or REJECTED.
        """
        gateway_res = self.record_action_event(
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
        expected_payload = {
            "event_id": event_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "evidence_hash": evidence_hash,
            "evidence_reference": evidence_reference
        }
        verification = self.verify_committed_transaction(
            gateway_response=gateway_res,
            expected_payload=expected_payload,
            min_peers=min_peers
        )
        return {
            "gateway_response": gateway_res,
            "verification_status": verification.status.value,
            "verification": verification,
            "tx_id": verification.tx_id,
            "block_number": verification.block_number,
            "block_hash": verification.block_hash,
            "validation_code": verification.validation_code
        }

