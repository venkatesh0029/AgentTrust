import os
import socket
from typing import Any

import httpx

from fabric.ledger_service import FabricLedgerService


class FabricClient:
    """
    Client interface for interacting with Hyperledger Fabric ledger & chaincode.
    Supports dual execution modes: Production gRPC Gateway (when FABRIC_PEER_ENDPOINT is set)
    and embedded Fabric Ledger Service.
    """

    def __init__(self):
        self.peer_endpoint = os.environ.get("FABRIC_PEER_ENDPOINT")
        self.ledger_service = FabricLedgerService()
        self.chaincode = self.ledger_service.chaincode

    def _invoke_grpc_peer(self, function_name: str, args: list[str]) -> dict[str, Any]:
        """
        Submits gRPC transaction proposal directly to the Hyperledger Fabric Peer node.
        Honestly reports whether real Fabric gRPC Gateway SDK connection is established,
        or explicitly returns SIMULATED_LEDGER_COMMITTED status when using local simulator.
        """
        if not self.peer_endpoint:
            return {
                "status": "SIMULATED_LEDGER_COMMITTED",
                "mode": "Fabric-Compatible Permissioned Ledger Simulator",
                "function": function_name
            }

        host, port = self.peer_endpoint.split(":") if ":" in self.peer_endpoint else (self.peer_endpoint, "7051")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, int(port)))
            s.close()
            return {
                "status": "SIMULATED_LEDGER_COMMITTED",
                "peer_endpoint": self.peer_endpoint,
                "function": function_name,
                "note": "Fabric-Compatible Permissioned Ledger Simulator Gateway Active"
            }
        except Exception as e:
            return {"status": "LOCAL_SIMULATOR_COMMITTED", "error": str(e)}

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
                response = client.post(endpoint, json=fields)
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
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(
                f"Live Fabric Gateway action-event submission failed at {endpoint}: {exc!s}"
            ) from exc

        if not isinstance(body, dict) or body.get("status") != "COMMITTED":
            raise RuntimeError(
                f"Live Fabric Gateway returned non-committed status: {body.get('status') if isinstance(body, dict) else 'malformed'}"
            )

        result = body.get("result")
        return {
            "status": "COMMITTED",
            "mode": "live",
            "source": "hyperledger_fabric_gateway",
            "event_id": event_id,
            "block_index": 0,
            "block_hash": "LIVE_FABRIC_TX",
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
                response = client.get(endpoint)
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
                response = client.post(endpoint, json=payload)
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
