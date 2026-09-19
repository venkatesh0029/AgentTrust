import datetime
from typing import Dict, Any, Optional, List, Tuple
from action_gateway.request_validator import RequestValidator
from identity_manager.certificate_manager import CertificateManager
from identity_manager.signature_manager import SignatureManager
from agent_registry.registration import AgentRegistry
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_models import PolicyDecision, DecisionReason
from replay_protection.request_tracker import RequestTracker
from protected_api.finance_api import ProtectedFinanceAPI
from human_approval.approval_manager import HumanApprovalManager
from evidence_manager.evidence_store import EvidenceStore
from evidence_manager.provenance import ProvenanceBuilder
from fabric.fabric_client import FabricClient

from risk_engine.risk_evaluator import RiskEvaluator
from audit_writer.chain_writer import AuditChainWriter

class ActionGateway:
    """
    Mandatory Security Action Gateway enforcing 13-stage pipeline:
    Format Validation -> Certificate & Signature Verification -> Agent Status & Key-Version Check ->
    Timestamp, Nonce, Replay & Idempotency Check -> Trusted Risk Evaluation -> Policy Evaluation ->
    Decision Branching -> Protected API Execution -> Evidence Generation -> Audit Chain Writer -> Fabric Commit.
    """

    def __init__(
        self,
        registry: AgentRegistry,
        cert_manager: CertificateManager,
        policy_evaluator: PolicyEvaluator,
        replay_tracker: RequestTracker,
        finance_api: ProtectedFinanceAPI,
        approval_manager: HumanApprovalManager,
        evidence_store: EvidenceStore,
        fabric_client: FabricClient,
        chain_writer: Optional[AuditChainWriter] = None
    ):
        self.registry = registry
        self.cert_manager = cert_manager
        self.policy_evaluator = policy_evaluator
        self.replay_tracker = replay_tracker
        self.finance_api = finance_api
        self.approval_manager = approval_manager
        self.evidence_store = evidence_store
        self.fabric_client = fabric_client
        self.chain_writer = chain_writer or AuditChainWriter()
        self._event_counter = 1000

    def process_request(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for processing signed AI agent requests."""
        # Step 1: Validate payload format & schema
        valid_struct, struct_msg = RequestValidator.validate_structure(request_payload)
        if not valid_struct:
            return self._build_immediate_rejection(
                request_id=request_payload.get("request_id", "REQ-UNKNOWN"),
                agent_id=request_payload.get("agent_id", "UNKNOWN-AGENT"),
                action=request_payload.get("action", "UNKNOWN"),
                resource=request_payload.get("resource", "UNKNOWN"),
                decision=PolicyDecision.BLOCKED.value,
                reason="INVALID_REQUEST_FORMAT"
            )

        request_id = request_payload["request_id"]
        agent_id = request_payload["agent_id"]
        action = request_payload["action"]
        resource = request_payload["resource"]
        parameters = request_payload.get("parameters", {})

        # Extract amount from parameters or top-level payload
        amount = float(request_payload.get("amount", parameters.get("amount", 0)))
        if "amount" not in parameters and amount > 0:
            parameters["amount"] = amount

        nonce = request_payload["nonce"]
        timestamp = request_payload["timestamp"]
        expires_at = request_payload.get("expires_at", "")
        key_version = request_payload.get("key_version")
        idempotency_key = request_payload.get("idempotency_key") or request_payload.get("X-Idempotency-Key") or request_id
        signature_b64 = request_payload["signature"]

        # Step 2: Verify Agent Identity & Registration
        agent_record = self.registry.get_agent(agent_id)
        if not agent_record:
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.UNKNOWN_AGENT.value,
                policy_id="NONE",
                policy_version="1.0",
                agent_version="1.0",
                api_result="NOT_EXECUTED",
                nonce=nonce
            )

        agent_status = agent_record["status"]
        if agent_status == "REVOKED":
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.CERTIFICATE_REVOKED.value,
                policy_id=agent_record.get("policy_id", "NONE"),
                policy_version="1.0",
                agent_version=agent_record.get("agent_version", "1.0"),
                api_result="NOT_EXECUTED",
                cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
                nonce=nonce
            )
        elif agent_status == "SUSPENDED":
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.AGENT_SUSPENDED.value,
                policy_id=agent_record.get("policy_id", "NONE"),
                policy_version="1.0",
                agent_version=agent_record.get("agent_version", "1.0"),
                api_result="NOT_EXECUTED",
                cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
                nonce=nonce
            )

        # Step 3: Validate Certificate Validity & Expiration
        if agent_record.get("certificate"):
            cert_val = self.cert_manager.verify_agent_certificate(agent_record["certificate"])
            if not cert_val.get("valid"):
                return self._finalize_gateway_outcome(
                    request_id=request_id,
                    agent_id=agent_id,
                    action=action,
                    resource=resource,
                    parameters=parameters,
                    decision=PolicyDecision.BLOCKED.value,
                    reason=cert_val.get("reason", "INVALID_CERTIFICATE"),
                    policy_id=agent_record.get("policy_id", "NONE"),
                    policy_version="1.0",
                    agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="DENIED",
                    cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
                    nonce=nonce
                )

        # Step 4: Validate Key Version (if provided)
        if key_version is not None:
            expected_key_ver = agent_record.get("key_version", 1)
            if int(key_version) != int(expected_key_ver):
                return self._finalize_gateway_outcome(
                    request_id=request_id,
                    agent_id=agent_id,
                    action=action,
                    resource=resource,
                    parameters=parameters,
                    decision=PolicyDecision.BLOCKED.value,
                    reason="INVALID_KEY_VERSION",
                    policy_id=agent_record.get("policy_id", "NONE"),
                    policy_version="1.0",
                    agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="DENIED",
                    cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
                    nonce=nonce
                )

        # Step 5: Verify Digital Signature
        payload_to_verify = request_payload.copy()
        payload_to_verify.pop("signature", None)

        public_key_pem = agent_record["public_key"]
        sig_valid = SignatureManager.verify_signature(payload_to_verify, signature_b64, public_key_pem)
        if not sig_valid:
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.INVALID_SIGNATURE.value,
                policy_id=agent_record.get("policy_id", "NONE"),
                policy_version="1.0",
                agent_version=agent_record.get("agent_version", "1.0"),
                api_result="DENIED",
                cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
                nonce=nonce
            )

        # Step 6: Check Replay Protection & Idempotency
        replay_ok, replay_reason = self.replay_tracker.check_and_track(
            request_id=request_id,
            nonce=nonce,
            timestamp_iso=timestamp,
            expires_at_iso=expires_at,
            idempotency_key=idempotency_key
        )
        if not replay_ok:
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=replay_reason,
                policy_id=agent_record.get("policy_id", "NONE"),
                policy_version="1.0",
                agent_version=agent_record.get("agent_version", "1.0"),
                api_result="NOT_EXECUTED",
                cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
                nonce=nonce
            )

        # Step 7: Trusted Risk Engine Evaluation (Executed BEFORE Policy Engine)
        risk_result = RiskEvaluator.evaluate(
            agent_id=agent_id,
            action=action,
            resource=resource,
            amount=amount,
            agent_record=agent_record,
            request_timestamp_iso=timestamp
        )

        # Step 8: Versioned Policy Engine Evaluation
        policy_id = agent_record.get("policy_id", "NONE")
        decision, reason, policy_version, matched_rules = self.policy_evaluator.evaluate(
            policy_id=policy_id,
            action=action,
            resource=resource,
            amount=amount,
            request_timestamp_iso=timestamp,
            risk_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"]
        )

        # Step 9: Decision Execution / Branching
        api_result = "NOT_EXECUTED"
        tx_data = None
        approval_ticket = None

        if decision == PolicyDecision.ALLOWED:
            # Create signed service auth headers
            auth_headers = self.finance_api.create_gateway_auth_headers(request_id)
            exec_res = self.finance_api.execute_action(
                action=action,
                parameters=parameters,
                gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
                request_id=request_id,
                agent_id=agent_id,
                auth_headers=auth_headers,
                idempotency_key=idempotency_key
            )
            if exec_res.get("success"):
                api_result = "EXECUTED"
                tx_data = exec_res.get("transaction_data")
            else:
                api_result = f"FAILED: {exec_res.get('error')}"

        elif decision == PolicyDecision.PENDING_HUMAN_APPROVAL:
            # Route to Human Approval Queue
            raw_hash = SignatureManager.canonical_serialize(payload_to_verify).hex()
            approval_ticket = self.approval_manager.create_approval_request(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                reason=reason.value,
                policy_id=policy_id,
                request_hash=raw_hash,
                policy_version=policy_version
            )
            api_result = "HELD_FOR_HUMAN_APPROVAL"

        # Step 10, 11, 12 & 13: Evidence Generation, Hash Chain Writer, Blockchain Commit
        return self._finalize_gateway_outcome(
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=parameters,
            decision=decision.value,
            reason=reason.value,
            policy_id=policy_id,
            policy_version=policy_version,
            agent_version=agent_record.get("agent_version", "1.0"),
            api_result=api_result,
            approval_ticket=approval_ticket,
            tx_data=tx_data,
            cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
            nonce=nonce,
            risk_result=risk_result,
            matched_rules=matched_rules
        )

    def process_human_approval_resume(self, approval_id: str, approver_id: str) -> Dict[str, Any]:
        """Resumes processing after human supervisor approves a pending request."""
        ok, app_record, msg = self.approval_manager.approve_request(approval_id, approver_id)
        if not ok or not app_record:
            return {"success": False, "message": msg}

        request_id = app_record["request_id"]
        agent_id = app_record["agent_id"]
        action = app_record["action"]
        resource = app_record["resource"]
        parameters = app_record["parameters"]
        policy_id = app_record["policy_id"]
        approval_ref = app_record["approval_reference"]

        auth_headers = self.finance_api.create_gateway_auth_headers(request_id)
        exec_res = self.finance_api.execute_action(
            action=action,
            parameters=parameters,
            gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
            request_id=request_id,
            agent_id=agent_id,
            approval_ref=approval_ref,
            auth_headers=auth_headers
        )

        agent_record = self.registry.get_agent(agent_id)
        agent_ver = agent_record.get("agent_version", "1.0") if agent_record else "1.0"
        cert_fp = agent_record.get("certificate_fingerprint", "") if agent_record else ""

        return self._finalize_gateway_outcome(
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=parameters,
            decision=PolicyDecision.ALLOWED_AFTER_APPROVAL.value,
            reason="APPROVED_BY_HUMAN_SUPERVISOR",
            policy_id=policy_id,
            policy_version="1.0",
            agent_version=agent_ver,
            api_result="EXECUTED",
            tx_data=exec_res.get("transaction_data"),
            approval_ref=approval_ref,
            cert_fingerprint=cert_fp,
            nonce=f"N-RESUME-{request_id}"
        )

    def _finalize_gateway_outcome(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        resource: str,
        parameters: Dict[str, Any],
        decision: str,
        reason: str,
        policy_id: str,
        policy_version: str,
        agent_version: str,
        api_result: str,
        approval_ticket: Optional[Dict[str, Any]] = None,
        tx_data: Optional[Dict[str, Any]] = None,
        approval_ref: Optional[str] = None,
        cert_fingerprint: str = "SHA256:DEFAULT",
        nonce: str = "",
        risk_result: Optional[Dict[str, Any]] = None,
        matched_rules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Creates off-chain evidence, records hash-chain audit log, and commits audit event to Fabric blockchain safely.
        """
        self._event_counter += 1
        event_id = f"EVENT-{self._event_counter}"

        risk_eval = risk_result or {
            "risk_score": 0.0,
            "risk_level": "LOW",
            "risk_factors": [],
            "risk_model_version": "risk-v1"
        }
        rules = matched_rules or []

        # 1. Build Off-chain Evidence Record (Schema v2.0)
        evidence_record = ProvenanceBuilder.build_evidence(
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=parameters,
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            policy_version=policy_version,
            agent_version=agent_version,
            api_result=api_result,
            cert_fingerprint=cert_fingerprint,
            nonce=nonce,
            approval_reference=approval_ref
        )

        evidence_record["risk_score"] = risk_eval["risk_score"]
        evidence_record["risk_level"] = risk_eval["risk_level"]
        evidence_record["risk_factors"] = risk_eval["risk_factors"]
        evidence_record["matched_rules"] = rules

        # 2. Save Evidence Off-chain & compute SHA-256 Hash
        evidence_hash = self.evidence_store.save_evidence(evidence_record)
        evidence_ref = evidence_record["evidence_id"]

        # 3. Write Atomic Hash Chain Record (Concurrency-Safe)
        chain_record = self.chain_writer.write_event(
            event_type=f"ACTION_{decision}",
            request_id=request_id,
            agent_id=agent_id,
            request_hash=evidence_record.get("input_hash", evidence_hash),
            risk_score=risk_eval["risk_score"],
            policy_version=policy_version,
            decision=decision,
            execution_result=api_result,
            event_id=event_id
        )

        evidence_record["sequence_number"] = chain_record.sequence_number
        evidence_record["previous_record_hash"] = chain_record.previous_record_hash
        evidence_record["record_hash"] = chain_record.record_hash

        # 4. Commit Audit Event onto Hyperledger Fabric Blockchain Ledger with Failure Handling
        ledger_status = "COMMITTED"
        blockchain_commit = None

        try:
            blockchain_commit = self.fabric_client.record_action_event(
                event_id=event_id,
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=decision,
                reason=reason,
                policy_id=policy_id,
                policy_version=policy_version,
                evidence_reference=evidence_ref,
                evidence_hash=evidence_hash
            )
        except Exception as e:
            # Failure Recovery: Preserve local evidence safely, do NOT silently claim success!
            ledger_status = f"COMMIT_FAILED: {str(e)}"
            blockchain_commit = {
                "block_index": -1,
                "block_hash": "PENDING_RETRY",
                "status": ledger_status
            }

        return {
            "gateway_status": "PROCESSED",
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "risk_score": risk_eval["risk_score"],
            "risk_level": risk_eval["risk_level"],
            "risk_factors": risk_eval["risk_factors"],
            "matched_rules": rules,
            "protected_api_result": api_result,
            "approval_reference": approval_ref,
            "approval_ticket": approval_ticket,
            "transaction_data": tx_data,
            "evidence": {
                "evidence_id": evidence_ref,
                "evidence_hash": evidence_hash,
                "sequence_number": chain_record.sequence_number,
                "previous_record_hash": chain_record.previous_record_hash,
                "record_hash": chain_record.record_hash,
                "off_chain_status": "STORED"
            },
            "blockchain": {
                "event_id": event_id,
                "block_index": blockchain_commit["block_index"],
                "block_hash": blockchain_commit["block_hash"],
                "status": ledger_status
            }
        }

    def _build_immediate_rejection(self, request_id: str, agent_id: str, action: str, resource: str, decision: str, reason: str) -> Dict[str, Any]:
        return {
            "gateway_status": "PROCESSED",
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "risk_score": 100.0,
            "risk_level": "HIGH",
            "protected_api_result": "NOT_EXECUTED"
        }
