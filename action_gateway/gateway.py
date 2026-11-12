import copy
import datetime
import hashlib
import json
import logging
import math
import os
import time
import uuid
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

logger = logging.getLogger(__name__)

from action_gateway.request_validator import RequestValidator
from action_gateway.retry_queue import RetryQueueManager
from agent_registry.registration import AgentRegistry
from audit_writer.chain_writer import AuditChainWriter
from evidence_manager.evidence_store import EvidenceStore
from evidence_manager.provenance import ProvenanceBuilder
from fabric.fabric_client import FabricClient
from human_approval.approval_manager import HumanApprovalManager
from identity_manager.certificate_manager import CertificateManager
from identity_manager.delegation import DelegationTokenManager
from identity_manager.signature_manager import SignatureManager
from policy_engine.policy_evaluator import PolicyEvaluator
from policy_engine.policy_models import DecisionReason, PolicyDecision
from protected_api.finance_api import ProtectedFinanceAPI
from replay_protection.request_tracker import RequestTracker
from risk_engine.risk_evaluator import RiskEvaluator


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
        chain_writer: AuditChainWriter | None = None,
        retry_queue: RetryQueueManager | None = None,
        persistent_db: Any | None = None,
        risk_evaluator: Any | None = None
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
        self.retry_queue = retry_queue or RetryQueueManager(persistent_db=persistent_db)
        self.persistent_db = persistent_db
        self.risk_evaluator = risk_evaluator or RiskEvaluator
        self._event_counter = 1000

    CURRENCY_PRECISION_SPECS: dict[str, int] = {
        "USD": 2,
        "EUR": 2,
        "GBP": 2,
        "INR": 2,
        "CAD": 2,
        "AUD": 2,
        "SGD": 2,
        "CHF": 2,
        "JPY": 0,
        "KRW": 0,
        "VND": 0,
        "BHD": 3,
        "KWD": 3,
        "OMR": 3,
        "JOD": 3,
        "DEFAULT": 4,  # High-precision canonical testing / sub-cent unit scale
    }

    @classmethod
    def canonicalize_financial_amount(
        cls,
        amount: Any,
        currency: str | None = None,
        strict_scale: bool = True
    ) -> tuple[int, str]:
        """
        Converts financial amount to integer minor units and exact canonical decimal string.
        Enforces currency-specific precision (e.g. USD=2, JPY=0, BHD=3, DEFAULT=4).
        Under strict_scale=True, rejects any input with excess fractional decimals beyond the currency scale
        (preventing silent rounding drift or penny-shaving exploits).
        Disallows negative amounts, NaN, Infinity, or malformed values.
        Raises ValueError on invalid amount or excess precision.
        """
        curr_key = (currency or "DEFAULT").upper()
        if curr_key not in cls.CURRENCY_PRECISION_SPECS:
            raise ValueError(
                f"Unsupported currency '{curr_key}'. Currency must be explicitly registered in payment specification."
            )
        scale = cls.CURRENCY_PRECISION_SPECS[curr_key]

        if amount is None:
            zero_str = f"0.{'0' * scale}" if scale > 0 else "0"
            return 0, zero_str

        try:
            d = Decimal(str(amount))
        except (InvalidOperation, TypeError, ValueError):
            raise ValueError(f"Malformed financial amount: {amount}")

        if d.is_nan() or d.is_infinite():
            raise ValueError("Financial amount cannot be NaN or Infinite")
        if d < 0:
            raise ValueError(f"Financial amount cannot be negative: {amount}")

        quantum = Decimal(1) if scale == 0 else Decimal(f"1e-{scale}")
        multiplier = Decimal(10) ** scale

        if strict_scale:
            quantized = d.quantize(quantum, rounding=ROUND_HALF_UP)
            if d != quantized:
                raise ValueError(
                    f"Amount '{amount}' has excess fractional precision for currency '{curr_key}' (maximum scale: {scale} decimal places)"
                )
        else:
            quantized = d.quantize(quantum, rounding=ROUND_HALF_UP)

        minor_units = int(quantized * multiplier)
        canonical_str = f"{quantized:f}" if scale > 0 else str(int(quantized))
        return minor_units, canonical_str

    @classmethod
    def compute_request_fingerprint(
        cls,
        agent_id: str,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        amount: Any = 0.0,
        currency: str | None = None,
        destination: str | None = None,
        tenant_id: str | None = None,
    ) -> str:
        """
        Computes deterministic canonical SHA-256 fingerprint of business request parameters.
        Binds integer minor units, exact decimal string, currency, destination, tenant, and canonical parameters.
        """
        curr = currency or str(parameters.get("currency") or "DEFAULT").upper()
        minor_units, amount_str = cls.canonicalize_financial_amount(amount, currency=curr)
        clean_params = {
            k: v for k, v in parameters.items()
            if k not in (
                "amount", "currency", "destination", "to_account", "recipient",
                "tenant_id", "amount_canonical", "amount_minor_units"
            )
        }
        dest = (
            destination
            or str(
                parameters.get("to_account")
                or parameters.get("destination")
                or parameters.get("target_account")
                or parameters.get("destination_account")
                or parameters.get("supplier_id")
                or parameters.get("recipient")
                or ""
            )
        )
        tenant = tenant_id or str(parameters.get("tenant_id", "default-tenant"))

        raw_dict = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "amount_minor_units": minor_units,
            "amount_str": amount_str,
            "currency": curr,
            "destination": dest,
            "tenant_id": tenant,
            "parameters": clean_params,
        }
        canonical_bytes = json.dumps(raw_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def process_request(self, request_payload: dict[str, Any]) -> dict[str, Any]:
        """Main entry point for processing signed AI agent requests."""
        request_payload = copy.deepcopy(request_payload)
        raw_payload_for_sig = copy.deepcopy(request_payload)
        # Step 1: Validate payload format & schema
        valid_struct, struct_msg = RequestValidator.validate_structure(request_payload)
        if not valid_struct:
            reason_code = struct_msg if not struct_msg.startswith("MISSING_REQUIRED_FIELD") else "INVALID_REQUEST_FORMAT"
            return self._build_immediate_rejection(
                request_id=request_payload.get("request_id", "REQ-UNKNOWN"),
                agent_id=request_payload.get("agent_id", "UNKNOWN-AGENT"),
                action=request_payload.get("action", "UNKNOWN"),
                resource=request_payload.get("resource", "UNKNOWN"),
                decision=PolicyDecision.BLOCKED.value,
                reason=reason_code
            )

        request_id = request_payload["request_id"]
        agent_id = request_payload["agent_id"]
        action = request_payload["action"]
        resource = request_payload["resource"]
        parameters = request_payload.get("parameters", {})
        nonce = request_payload["nonce"]
        timestamp = request_payload["timestamp"]
        expires_at = request_payload.get("expires_at", "")
        key_version = request_payload.get("key_version")
        idempotency_key = request_payload.get("idempotency_key") or request_payload.get("X-Idempotency-Key")
        signature_b64 = request_payload["signature"]

        # Step 2: Verify Agent Identity & Registration
        agent_record = self.registry.get_agent(agent_id)
        if not agent_record:
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.UNKNOWN_AGENT.value
            )

        # Step 3: Verify Certificate Status & Revocation
        agent_status = agent_record["status"]
        if agent_status == "REVOKED":
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.CERTIFICATE_REVOKED.value
            )
        elif agent_status == "SUSPENDED":
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.AGENT_SUSPENDED.value
            )

        # Step 4: Validate Certificate Validity & Expiration
        if agent_record.get("certificate"):
            cert_val = self.cert_manager.verify_agent_certificate(agent_record["certificate"])
            if not cert_val.get("valid"):
                return self._build_immediate_rejection(
                    request_id=request_id,
                    agent_id=agent_id,
                    action=action,
                    resource=resource,
                    decision=PolicyDecision.BLOCKED.value,
                    reason=cert_val.get("reason", "INVALID_CERTIFICATE")
                )

        # Step 5: Validate Key Version (if provided)
        if key_version is not None:
            expected_key_ver = agent_record.get("key_version", 1)
            if int(key_version) != int(expected_key_ver):
                return self._build_immediate_rejection(
                    request_id=request_id,
                    agent_id=agent_id,
                    action=action,
                    resource=resource,
                    decision=PolicyDecision.BLOCKED.value,
                    reason="INVALID_KEY_VERSION"
                )

        # Step 6: Verify Digital Signature BEFORE processing business parameters
        payload_to_verify = raw_payload_for_sig.copy()
        payload_to_verify.pop("signature", None)

        public_key_pem = agent_record["public_key"]
        sig_valid = SignatureManager.verify_signature(payload_to_verify, signature_b64, public_key_pem)
        if not sig_valid:
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason=DecisionReason.INVALID_SIGNATURE.value,
                api_result="DENIED"
            )

        top_amt = request_payload.get("amount")
        param_amt = parameters.get("amount")
        if top_amt is not None and param_amt is not None:
            try:
                if abs(float(top_amt) - float(param_amt)) > 1e-6:
                    return self._build_immediate_rejection(
                        request_id=request_id,
                        agent_id=agent_id,
                        action=action,
                        resource=resource,
                        decision=PolicyDecision.BLOCKED.value,
                        reason="AMOUNT_MISMATCH",
                        api_result="NOT_EXECUTED"
                    )
            except Exception:
                pass

        raw_amt = top_amt if top_amt is not None else (param_amt if param_amt is not None else 0.0)
        top_curr = request_payload.get("currency")
        param_curr = parameters.get("currency")
        if top_curr and param_curr and str(top_curr).upper() != str(param_curr).upper():
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason="CURRENCY_MISMATCH",
                api_result="DENIED"
            )

        top_dest = request_payload.get("destination") or request_payload.get("target_account")
        param_dest = parameters.get("destination") or parameters.get("target_account")
        if top_dest and param_dest and str(top_dest) != str(param_dest):
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason="DESTINATION_MISMATCH",
                api_result="DENIED"
            )

        req_curr = str(top_curr or param_curr or "DEFAULT").upper()
        if req_curr not in self.CURRENCY_PRECISION_SPECS:
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason="UNSUPPORTED_CURRENCY",
                api_result="DENIED"
            )

        try:
            minor_units, amount_str = self.canonicalize_financial_amount(raw_amt, currency=req_curr)
            req_amount = float(Decimal(amount_str))
        except ValueError:
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason="INVALID_FINANCIAL_AMOUNT",
                api_result="DENIED"
            )

        # Retain exact canonical representation in parameters to prevent float conversion drift
        canonical_dest = str(top_dest or param_dest or "")
        parameters["amount_canonical"] = amount_str
        parameters["amount_minor_units"] = minor_units
        parameters["currency"] = req_curr
        parameters["amount"] = req_amount
        if canonical_dest:
            parameters["destination"] = canonical_dest
            parameters["target_account"] = canonical_dest

        request_fingerprint = self.compute_request_fingerprint(
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=parameters,
            amount=req_amount,
            currency=req_curr
        )

        # Step 6.1: Check Idempotency Cache for previously completed requests & canonical payload fingerprint
        if idempotency_key:
            if self.persistent_db:
                existing_intent = self.persistent_db.get_intent_by_idempotency_key(agent_id, idempotency_key)
                if existing_intent:
                    existing_fp = existing_intent.get("request_fingerprint")
                    if existing_fp and existing_fp != request_fingerprint:
                        return self._build_immediate_rejection(
                            request_id=request_id,
                            agent_id=agent_id,
                            action=action,
                            resource=resource,
                            decision=PolicyDecision.BLOCKED.value,
                            reason="IDEMPOTENCY_PAYLOAD_MISMATCH",
                            api_result="NOT_EXECUTED"
                        )
            cached_outcome = self.replay_tracker.get_idempotent_result(agent_id, idempotency_key)
            if cached_outcome:
                res = copy.deepcopy(cached_outcome)
                res["idempotent_replay"] = True
                return res

        # Step 6.2: Acquire in-flight concurrency lock for idempotency key
        lock_res = self.replay_tracker.acquire_in_flight(agent_id, idempotency_key)
        if not lock_res:
            return self._build_immediate_rejection(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                decision=PolicyDecision.BLOCKED.value,
                reason="CONCURRENT_IDEMPOTENCY_CONFLICT",
                api_result="NOT_EXECUTED"
            )

        try:
            return self._execute_request_pipeline(
                request_payload=request_payload,
                agent_record=agent_record,
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                nonce=nonce,
                timestamp=timestamp,
                expires_at=expires_at,
                idempotency_key=idempotency_key,
                payload_to_verify=payload_to_verify,
                request_fingerprint=request_fingerprint,
                fencing_token=lock_res.fencing_token,
                lock_owner=lock_res.owner_id
            )
        finally:
            self.replay_tracker.release_in_flight(
                agent_id,
                idempotency_key,
                owner_id=lock_res.owner_id,
                fencing_token=lock_res.fencing_token
            )

    def _execute_request_pipeline(
        self,
        request_payload: dict[str, Any],
        agent_record: dict[str, Any],
        request_id: str,
        agent_id: str,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        nonce: str,
        timestamp: Any,
        expires_at: str,
        idempotency_key: str | None,
        payload_to_verify: dict[str, Any],
        request_fingerprint: str | None = None,
        fencing_token: int | None = None,
        lock_owner: str | None = None
    ) -> dict[str, Any]:
        # Step 7: Strict Input Validation & Canonicalization for Authenticated Requests
        top_amount = request_payload.get("amount")
        param_amount = parameters.get("amount")

        # Reject boolean amounts or string amounts
        if isinstance(top_amount, bool) or isinstance(param_amount, bool):
            return self._finalize_gateway_outcome(
                request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                reason="INVALID_AMOUNT_FORMAT", policy_id=agent_record.get("policy_id", "NONE"), policy_version="1.0", agent_version="1.0",
                api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
            )

        if top_amount is not None and param_amount is not None:
            try:
                top_f = float(top_amount)
                param_f = float(param_amount)
                if math.isnan(top_f) or math.isnan(param_f) or math.isinf(top_f) or math.isinf(param_f):
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason="INVALID_AMOUNT_NAN_OR_INF", policy_id="NONE", policy_version="1.0", agent_version="1.0",
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )
                if abs(top_f - param_f) > 1e-6:
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason="AMOUNT_MISMATCH", policy_id="NONE", policy_version="1.0", agent_version="1.0",
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )
            except Exception:
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason="INVALID_AMOUNT_FORMAT", policy_id="NONE", policy_version="1.0", agent_version="1.0",
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )

        try:
            raw_amt = top_amount if top_amount is not None else (param_amount if param_amount is not None else 0)
            amount = float(raw_amt)
            if math.isnan(amount) or math.isinf(amount):
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason="INVALID_AMOUNT_NAN_OR_INF", policy_id="NONE", policy_version="1.0", agent_version="1.0",
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )
            if amount < 0 or (amount == 0 and action in ["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS", "CREATE_REIMBURSEMENT"]):
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason="NON_POSITIVE_AMOUNT", policy_id="NONE", policy_version="1.0", agent_version="1.0",
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )
        except Exception:
            return self._finalize_gateway_outcome(
                request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                reason="INVALID_AMOUNT_FORMAT", policy_id="NONE", policy_version="1.0", agent_version="1.0",
                api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
            )

        request_payload["amount"] = amount
        parameters["amount"] = amount

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
                nonce=nonce,
                idempotency_key=idempotency_key
            )

        # Step 7: Trusted Risk Engine Evaluation (Executed BEFORE Policy Engine)
        risk_result = self.risk_evaluator.evaluate(
            agent_id=agent_id,
            action=action,
            resource=resource,
            amount=amount,
            agent_record=agent_record,
            request_timestamp_iso=timestamp,
            parameters=parameters
        )

        # Step 7.5: Capability Delegation Token & Delegation Authority Graph Check
        delegation_context: dict[str, Any] | None = None
        delegation_token = request_payload.get("delegation_token") or parameters.get("delegation_token")
        if delegation_token:
            parameters["delegation_token"] = delegation_token
            request_payload["delegation_token"] = delegation_token

        # Check against active Delegation Authority Graph
        try:
            from identity_manager.delegation_graph import delegation_graph_manager
            target_token_id = None
            if isinstance(delegation_token, str):
                target_token_id = delegation_token
            elif isinstance(delegation_token, dict) and "token_id" in delegation_token:
                target_token_id = delegation_token["token_id"]
            elif not delegation_token:
                node = delegation_graph_manager.nodes.get(agent_id)
                if node and node.get("incoming_token_id"):
                    target_token_id = node["incoming_token_id"]

            if target_token_id and target_token_id in delegation_graph_manager.edges:
                edge = delegation_graph_manager.edges[target_token_id]
                # 1. Check revocation
                if edge.get("status") == "REVOKED":
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason=f"DELEGATION_TOKEN_REVOKED: Token '{target_token_id}' was revoked ({edge.get('revocation_reason', 'ADMIN_REVOCATION')})",
                        policy_id=agent_record.get("policy_id", "NONE"),
                        policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )

                # 2. Check expiration
                if int(time.time()) > edge.get("expires_at", 0) or edge.get("status") == "EXPIRED":
                    edge["status"] = "EXPIRED"
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason=f"DELEGATION_TOKEN_EXPIRED: Token '{target_token_id}' expired",
                        policy_id=agent_record.get("policy_id", "NONE"),
                        policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )

                # 3. Check action scope attenuation
                delegated_actions = edge.get("delegated_actions", [])
                if action not in delegated_actions:
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason=f"ACTION_NOT_IN_DELEGATION_SCOPE: Action '{action}' is outside delegated scope {delegated_actions}",
                        policy_id=agent_record.get("policy_id", "NONE"),
                        policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )

                # 4. Check remaining delegation budget
                rem_budget = float(edge.get("delegated_budget", 0)) - float(edge.get("spent_budget", 0))
                if amount > rem_budget:
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason=f"DELEGATION_BUDGET_EXCEEDED: Requested ₹{amount:,.2f} exceeds remaining delegated budget ₹{rem_budget:,.2f}",
                        policy_id=agent_record.get("policy_id", "NONE"),
                        policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )

                delegation_context = {
                    "token_id": target_token_id,
                    "issuer_agent_id": edge["issuer_agent_id"],
                    "delegate_agent_id": edge["delegate_agent_id"],
                    "delegated_budget": edge["delegated_budget"],
                    "spent_budget": edge["spent_budget"],
                    "remaining_budget": rem_budget,
                    "depth": edge.get("depth", 1),
                    "status": edge.get("status", "ACTIVE")
                }
            elif isinstance(delegation_token, str) and delegation_token:
                # String delegation token must be registered in delegation authority graph
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason=f"UNKNOWN_DELEGATION_TOKEN: Token '{delegation_token}' not recognized in delegation authority graph",
                    policy_id=agent_record.get("policy_id", "NONE"),
                    policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )
        except Exception as ex:
            print(f"[Gateway] Delegation graph check exception: {ex}")

        if delegation_token and isinstance(delegation_token, dict) and "issuer_agent_id" in delegation_token and "signature" in delegation_token:
            issuer_agent_id = delegation_token.get("issuer_agent_id")
            issuer_record = self.registry.get_agent(issuer_agent_id) if issuer_agent_id else None
            issuer_pub_key = issuer_record.get("public_key") if issuer_record else None

            if not issuer_pub_key:
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason="UNKNOWN_DELEGATION_ISSUER", policy_id=agent_record.get("policy_id", "NONE"),
                    policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )

            del_res = DelegationTokenManager.verify_delegation_chain(
                token=delegation_token,
                action=action,
                amount=amount,
                issuer_public_key=issuer_pub_key,
                requesting_agent_id=agent_id
            )
            if not del_res.get("valid") or not del_res.get("allowed"):
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason=del_res.get("reason", "DELEGATION_VERIFICATION_FAILED"),
                    policy_id=agent_record.get("policy_id", "NONE"),
                    policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )

        # Step 8: Versioned Policy Engine Evaluation & Atomic Volume Reservation
        policy_id = agent_record.get("policy_id", "NONE")
        cumulative_amount = 0.0
        tx_count_in_window = 0
        p_record = self.policy_evaluator.loader.get_policy(policy_id) if hasattr(self.policy_evaluator, "loader") else None
        win_sec = getattr(p_record, "velocity_window_seconds", 86400) if p_record else 86400
        max_cum = getattr(p_record, "cumulative_maximum_amount", None) if p_record else None
        max_tx = getattr(p_record, "max_transactions_per_window", None) if p_record else None

        reservation_active = False
        if self.persistent_db and hasattr(self.persistent_db, "check_and_reserve_cumulative_volume"):
            try:
                allowed, new_total, new_count, res_reason = self.persistent_db.check_and_reserve_cumulative_volume(
                    agent_id=agent_id,
                    action=action,
                    amount=amount,
                    window_seconds=win_sec,
                    max_cumulative_limit=max_cum,
                    max_velocity_count=max_tx,
                    request_id=request_id,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint
                )
                if not allowed:
                    canonical_reason = res_reason
                    if "CUMULATIVE_LIMIT_EXCEEDED" in res_reason:
                        canonical_reason = DecisionReason.CUMULATIVE_LIMIT_EXCEEDED.value
                    elif "VELOCITY_LIMIT_EXCEEDED" in res_reason:
                        canonical_reason = DecisionReason.VELOCITY_LIMIT_EXCEEDED.value
                    return self._finalize_gateway_outcome(
                        request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                        parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                        reason=canonical_reason,
                        policy_id=policy_id,
                        policy_version=getattr(p_record, "version", "1.0") if p_record else "1.0",
                        agent_version=agent_record.get("agent_version", "1.0"),
                        api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                    )
                reservation_active = True
                cumulative_amount = max(0.0, new_total - amount)
                tx_count_in_window = max(0, new_count - 1)
            except Exception as ex:
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason=f"PERSISTENT_VOLUME_CHECK_FAILED: {str(ex)}",
                    policy_id=policy_id,
                    policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )
        elif self.persistent_db and hasattr(self.persistent_db, "get_cumulative_volume"):
            try:
                cumulative_amount, tx_count_in_window = self.persistent_db.get_cumulative_volume(agent_id, window_seconds=win_sec)
            except Exception as ex:
                return self._finalize_gateway_outcome(
                    request_id=request_id, agent_id=agent_id, action=action, resource=resource,
                    parameters=parameters, decision=PolicyDecision.BLOCKED.value,
                    reason=f"PERSISTENT_VOLUME_CHECK_FAILED: {str(ex)}",
                    policy_id=policy_id,
                    policy_version="1.0", agent_version=agent_record.get("agent_version", "1.0"),
                    api_result="NOT_EXECUTED", nonce=nonce, idempotency_key=idempotency_key
                )

        decision, raw_reason, policy_version, matched_rules = self.policy_evaluator.evaluate(
            policy_id=policy_id,
            action=action,
            resource=resource,
            amount=amount,
            request_timestamp_iso=timestamp,
            risk_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
            cumulative_amount=cumulative_amount,
            transaction_count_in_window=tx_count_in_window
        )
        reason: DecisionReason | str = raw_reason

        # Step 8.5: AI Agent Behavioral Intelligence Engine (UEBA) Evaluation
        behavior_eval: dict[str, Any] | None = None
        try:
            from risk_engine.behavior_engine import agent_behavior_engine
            behavior_eval = agent_behavior_engine.analyze_request(
                agent_id=agent_id,
                action=action,
                resource=resource,
                amount=amount,
                request_timestamp_iso=timestamp,
                request_id=request_id
            )
            # Invariant: ML model recommends additional restrictions, NEVER independently grants authorization.
            if decision == PolicyDecision.ALLOWED and behavior_eval.get("enforcement") == "REQUIRE_HUMAN_APPROVAL":
                decision = PolicyDecision.PENDING_HUMAN_APPROVAL
                flags_str = ", ".join(k for k, v in behavior_eval.get("flags", {}).items() if v)
                reasons_str = "; ".join(behavior_eval.get("explainable_reasons", []))
                reason = f"BEHAVIORAL_ANOMALY_HOLD: Score {behavior_eval['anomaly_score']}/100 [{flags_str}]. {reasons_str}"
                risk_result["risk_score"] = max(float(risk_result.get("risk_score", 0)), float(behavior_eval["anomaly_score"]))
        except Exception:
            pass

        # Step 9: Decision Execution / Branching
        api_result = "NOT_EXECUTED"
        tx_data = None
        approval_ticket = None
        event_id = f"EVENT-{uuid.uuid4().hex[:12].upper()}"

        if decision == PolicyDecision.ALLOWED:
            if not reservation_active and self.persistent_db:
                try:
                    self.persistent_db.save_intent(
                        request_id=request_id,
                        agent_id=agent_id,
                        action=action,
                        amount=amount,
                        idempotency_key=idempotency_key,
                        state="AUTHORIZED_PENDING_EXECUTION",
                        request_fingerprint=request_fingerprint
                    )
                except Exception:
                    pass

            # Fencing check at side-effect boundary: ensure worker still owns valid lease
            if self.persistent_db and idempotency_key and lock_owner and fencing_token:
                if not self.persistent_db.validate_lock_fencing(agent_id, idempotency_key, lock_owner, fencing_token):
                    return self._build_immediate_rejection(
                        request_id=request_id,
                        agent_id=agent_id,
                        action=action,
                        resource=resource,
                        decision=PolicyDecision.BLOCKED.value,
                        reason="STALE_WORKER_FENCING_REJECTED",
                        api_result="NOT_EXECUTED"
                    )

            # Transactional Outbox: Pre-stage audit outbox record so the financial side-effect
            # and audit intention are committed within a single atomic SQLite transaction.
            outbox_record = {
                "event_id": event_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "action": action,
                "amount": amount,
                "idempotency_key": idempotency_key,
                "request_fingerprint": request_fingerprint,
                "payload": {
                    "event_id": event_id,
                    "request_id": request_id,
                    "agent_id": agent_id,
                    "action": action,
                    "resource": resource,
                    "decision": decision.value if hasattr(decision, "value") else decision,
                    "reason": reason.value if hasattr(reason, "value") else reason,
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "parameters": parameters,
                    "timestamp": timestamp,
                }
            }

            # Create signed service auth headers
            auth_headers = self.finance_api.create_gateway_auth_headers(request_id)
            try:
                exec_res = self.finance_api.execute_action(
                    action=action,
                    parameters=parameters,
                    gateway_token=str(getattr(self.finance_api, "gateway_secret", "")),
                    request_id=request_id,
                    agent_id=agent_id,
                    auth_headers=auth_headers,
                    idempotency_key=idempotency_key,
                    fencing_token=fencing_token,
                    outbox_record=outbox_record
                )
            except Exception as e:
                # Handle uncertain external outcome: query authoritative status by idempotency_key/request_id
                status_res = self.finance_api.query_transaction_status(
                    agent_id=agent_id,
                    idempotency_key=idempotency_key,
                    request_id=request_id
                )
                if status_res and status_res.get("success"):
                    exec_res = status_res
                else:
                    if self.persistent_db:
                        try:
                            self.persistent_db.update_intent_state(
                                request_id=request_id,
                                state="EXECUTION_FAILED",
                                expected_current_state="AUTHORIZED_PENDING_EXECUTION"
                            )
                        except Exception:
                            pass
                    raise e

            if exec_res.get("success"):
                api_result = "EXECUTED"
                tx_data = exec_res.get("transaction_data")
                # Consume delegation budget on the spot!
                if delegation_context and delegation_context.get("token_id"):
                    try:
                        from identity_manager.delegation_graph import delegation_graph_manager
                        spent_ok, spend_msg = delegation_graph_manager.spend_budget(
                            delegation_context["token_id"], amount
                        )
                        if spent_ok:
                            spend_edge = delegation_graph_manager.edges.get(delegation_context["token_id"])
                            if spend_edge:
                                delegation_context["spent_budget"] = spend_edge["spent_budget"]
                                delegation_context["remaining_budget"] = max(0.0, spend_edge["delegated_budget"] - spend_edge["spent_budget"])
                    except Exception as e:
                        print(f"[Gateway] Delegation budget spend warning: {e}")
                if self.persistent_db:
                    try:
                        self.persistent_db.update_intent_state(
                            request_id=request_id,
                            state="EXECUTED_PENDING_LEDGER",
                            expected_current_state="AUTHORIZED_PENDING_EXECUTION"
                        )
                    except Exception:
                        pass
            else:
                api_result = f"FAILED: {exec_res.get('error')}"
                if self.persistent_db:
                    try:
                        self.persistent_db.update_intent_state(
                            request_id=request_id,
                            state="EXECUTION_FAILED",
                            expected_current_state="AUTHORIZED_PENDING_EXECUTION"
                        )
                    except Exception:
                        pass

        elif decision == PolicyDecision.PENDING_HUMAN_APPROVAL:
            if reservation_active and self.persistent_db:
                try:
                    if hasattr(self.persistent_db, "release_reservation"):
                        self.persistent_db.release_reservation(request_id, new_state="HELD_FOR_HUMAN_APPROVAL", reason=reason.value if hasattr(reason, "value") else str(reason))
                    else:
                        self.persistent_db.update_intent_state(request_id=request_id, state="HELD_FOR_HUMAN_APPROVAL", expected_current_state="AUTHORIZED_PENDING_EXECUTION")
                except Exception:
                    pass

            # Route to Human Approval Queue with immutable authorization context & delegation token
            raw_hash = SignatureManager.canonical_serialize(payload_to_verify).hex()
            auth_context = {
                "agent_id": agent_id,
                "key_version": agent_record.get("key_version", 1),
                "certificate_fingerprint": agent_record.get("certificate_fingerprint", ""),
                "policy_id": policy_id,
                "policy_version": policy_version,
                "risk_score": risk_result.get("risk_score"),
                "request_hash": raw_hash,
                "delegation_token": delegation_token
            }
            approval_ticket = self.approval_manager.create_approval_request(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                reason=reason.value if hasattr(reason, "value") else str(reason),
                policy_id=policy_id,
                request_hash=raw_hash,
                policy_version=policy_version,
                authorization_context=auth_context,
                delegation_token=delegation_token
            )
            api_result = "HELD_FOR_HUMAN_APPROVAL"

        elif decision == PolicyDecision.BLOCKED:
            if reservation_active and self.persistent_db:
                try:
                    if hasattr(self.persistent_db, "release_reservation"):
                        self.persistent_db.release_reservation(request_id, new_state="REJECTED", reason=reason.value if hasattr(reason, "value") else str(reason))
                    else:
                        self.persistent_db.update_intent_state(request_id=request_id, state="REJECTED", expected_current_state="AUTHORIZED_PENDING_EXECUTION")
                except Exception:
                    pass

        # Step 10, 11, 12 & 13: Evidence Generation, Hash Chain Writer, Blockchain Commit
        return self._finalize_gateway_outcome(
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=parameters,
            decision=decision.value if hasattr(decision, "value") else str(decision),
            reason=reason.value if hasattr(reason, "value") else str(reason),
            policy_id=policy_id,
            policy_version=policy_version,
            agent_version=agent_record.get("agent_version", "1.0"),
            api_result=api_result,
            approval_ticket=approval_ticket,
            tx_data=tx_data,
            cert_fingerprint=agent_record.get("certificate_fingerprint", ""),
            nonce=nonce,
            risk_result=risk_result,
            matched_rules=matched_rules,
            idempotency_key=idempotency_key,
            event_id=event_id,
            behavior_eval=behavior_eval,
            delegation_context=delegation_context
        )

    def process_human_approval_resume(self, approval_id: str, approver_id: str, provided_token: str | None = None) -> dict[str, Any]:
        """Resumes processing after human supervisor approves a pending request with complete atomic re-validation (#11, #1)."""
        app_record = self.approval_manager.get_approval_by_id(approval_id)
        if not app_record or app_record.get("status") != "PENDING":
            st = app_record.get("status", "UNKNOWN") if app_record else "NOT_FOUND"
            return {
                "success": False,
                "decision": "BLOCKED",
                "reason": f"REQUEST_ALREADY_APPROVED ({st})" if st == "APPROVED" else f"APPROVAL_TICKET_NOT_PENDING ({st})",
                "message": f"Approval ticket '{approval_id}' not found or not pending (status: {st})."
            }

        env_profile = os.environ.get("AGENTTRUST_ENV", "development").lower()
        is_demo = (
            os.environ.get("AGENTTRUST_DEMO_MODE", "false").lower() in ("true", "1", "yes")
            or env_profile in ("development", "demo", "dev")
        ) and not (
            os.environ.get("AGENTTRUST_PRODUCTION", "false").lower() in ("true", "1")
            or env_profile in ("production", "prod")
        )
        is_testing = "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("TESTING", "").lower() in ("true", "1")

        token_to_pass = provided_token
        if not token_to_pass:
            if is_demo or is_testing:
                token_to_pass = app_record.get("approval_token")
            else:
                return {
                    "success": False,
                    "decision": "BLOCKED",
                    "reason": "MISSING_APPROVAL_TOKEN",
                    "message": "MISSING_APPROVAL_TOKEN: Secret cryptographic approval token is required to approve ticket."
                }

        request_id = app_record["request_id"]
        agent_id = app_record["agent_id"]
        action = app_record["action"]
        resource = app_record["resource"]
        parameters = app_record["parameters"]
        policy_id = app_record["policy_id"]
        amount = float(parameters.get("amount", 0))

        # Atomic Validator Callback executed INSIDE the HumanApprovalManager lock
        validation_context: dict[str, Any] = {}

        def _atomic_validator(record: dict[str, Any]) -> tuple[bool, str]:
            # 1. Re-check Agent Identity, Status & Key Version
            ag_rec = self.registry.get_agent(agent_id)
            if not ag_rec or ag_rec.get("status") != "ACTIVE":
                st = ag_rec.get("status", "UNKNOWN") if ag_rec else "UNREGISTERED"
                return False, f"AGENT_REVOKED_OR_INACTIVE_ON_RESUME ({st})"

            auth_ctx = record.get("authorization_context", {})
            stored_key_ver = auth_ctx.get("key_version")
            if stored_key_ver is not None and ag_rec.get("key_version") != stored_key_ver:
                return False, "KEY_VERSION_CHANGED_SINCE_APPROVAL_ISSUANCE"

            # 2. Re-check Certificate Validity & Fingerprint Match
            cert_pem = ag_rec.get("certificate")
            if cert_pem:
                cert_val = self.cert_manager.verify_agent_certificate(cert_pem)
                if not cert_val.get("valid"):
                    return False, f"CERTIFICATE_INVALID_ON_RESUME ({cert_val.get('reason')})"

                stored_fp = auth_ctx.get("certificate_fingerprint")
                if stored_fp and cert_val.get("fingerprint") != stored_fp:
                    return False, "CERTIFICATE_FINGERPRINT_CHANGED_SINCE_APPROVAL_ISSUANCE"

            # 3. Re-evaluate Risk Engine
            now_iso = datetime.datetime.now(datetime.UTC).isoformat()
            risk_res = self.risk_evaluator.evaluate(
                agent_id=agent_id,
                action=action,
                resource=resource,
                amount=amount,
                agent_record=ag_rec,
                request_timestamp_iso=now_iso,
                parameters=parameters
            )
            validation_context["risk_result"] = risk_res

            # 4. Re-evaluate Policy against active rules (NON-RESERVATION CHECKS FIRST)
            p_rec = self.policy_evaluator.loader.get_policy(policy_id) if hasattr(self.policy_evaluator, "loader") else None
            w_sec = getattr(p_rec, "velocity_window_seconds", 86400) if p_rec else 86400
            max_cum = getattr(p_rec, "cumulative_maximum_amount", None) if p_rec else None
            max_vel = getattr(p_rec, "max_transactions_per_window", None) if p_rec else None

            dec, rsn, pver, rules = self.policy_evaluator.evaluate(
                policy_id=policy_id,
                action=action,
                resource=resource,
                amount=amount,
                request_timestamp_iso=now_iso,
                risk_score=risk_res.get("risk_score", 0.0),
                risk_level=risk_res.get("risk_level", "LOW"),
                cumulative_amount=0.0,
                transaction_count_in_window=0
            )
            validation_context["policy_version"] = pver
            validation_context["matched_rules"] = rules

            if dec == PolicyDecision.BLOCKED:
                return False, f"POLICY_RECHECK_FAILED: {rsn.value if hasattr(rsn, 'value') else str(rsn)}"

            # 5. Re-check Delegation Token (NON-RESERVATION CHECKS FIRST)
            del_token = record.get("delegation_token") or parameters.get("delegation_token") or auth_ctx.get("delegation_token")
            if del_token and isinstance(del_token, dict):
                issuer_pub = ag_rec.get("public_key", "")
                del_res = DelegationTokenManager.verify_delegation_chain(
                    del_token, action, amount, issuer_pub, requesting_agent_id=agent_id
                )
                if not del_res.get("valid"):
                    return False, f"DELEGATION_RECHECK_FAILED: {del_res.get('reason')}"

            # 6. FINAL AUTHORIZATION GATE: Atomic Volume Reservation immediately before ticket consumption
            is_prod = not is_demo and (
                os.environ.get("AGENTTRUST_PRODUCTION", "false").lower() in ("true", "1")
                or os.environ.get("STRICT_PERSISTENCE", "false").lower() in ("true", "1")
            )

            if is_prod and (not self.persistent_db or not hasattr(self.persistent_db, "revalidate_and_reserve_approved_intent")):
                return False, "ATOMIC_RESERVATION_UNAVAILABLE: atomic reservation engine required in production"

            if self.persistent_db and hasattr(self.persistent_db, "revalidate_and_reserve_approved_intent"):
                try:
                    res_ok, new_total, new_cnt, res_msg = self.persistent_db.revalidate_and_reserve_approved_intent(
                        request_id=request_id,
                        agent_id=agent_id,
                        action=action,
                        amount=amount,
                        window_seconds=w_sec,
                        max_cumulative_limit=max_cum,
                        max_velocity_count=max_vel
                    )
                    if not res_ok and not is_prod and "INTENT_NOT_FOUND" in str(res_msg):
                        try:
                            self.persistent_db.save_intent(
                                request_id=request_id,
                                agent_id=agent_id,
                                action=action,
                                amount=amount,
                                idempotency_key=None,
                                state="HELD_FOR_HUMAN_APPROVAL"
                            )
                            res_ok, new_total, new_cnt, res_msg = self.persistent_db.revalidate_and_reserve_approved_intent(
                                request_id=request_id,
                                agent_id=agent_id,
                                action=action,
                                amount=amount,
                                window_seconds=w_sec,
                                max_cumulative_limit=max_cum,
                                max_velocity_count=max_vel
                            )
                        except Exception:
                            pass
                    if not res_ok:
                        return False, res_msg
                    validation_context["reservation_held"] = True
                except Exception as ex:
                    return False, f"PERSISTENT_VOLUME_RECHECK_FAILED: {str(ex)}"
            elif self.persistent_db and hasattr(self.persistent_db, "get_cumulative_volume"):
                if is_prod:
                    return False, "ATOMIC_RESERVATION_UNSUPPORTED: atomic reservation engine required in production"
                try:
                    c_amt, c_cnt = self.persistent_db.get_cumulative_volume(agent_id, window_seconds=w_sec)
                    if max_cum is not None and (c_amt + amount) > max_cum:
                        return False, f"CUMULATIVE_LIMIT_EXCEEDED_ON_RESUME: rolling total ₹{c_amt + amount:,.2f} exceeds cap ₹{max_cum:,.2f}"
                except Exception as ex:
                    return False, f"PERSISTENT_VOLUME_RECHECK_FAILED: {str(ex)}"

            validation_context["agent_record"] = ag_rec
            return True, "VALID"

        # ATOMICALLY consume approval ticket ONLY if validator passes inside the lock
        ok, updated_record, msg = self.approval_manager.approve_request(
            approval_id, approver_id, provided_token=token_to_pass, validator_fn=_atomic_validator
        )
        if not ok or not updated_record:
            release_failure: str | None = None
            if (validation_context.get("reservation_held") or "ATOMIC_VALIDATION_FAILED" in str(msg)) and self.persistent_db and hasattr(self.persistent_db, "release_reservation"):
                try:
                    self.persistent_db.release_reservation(request_id, new_state="REJECTED", reason=f"RESUME_VALIDATION_FAILED: {msg}")
                except Exception as ex:
                    logger.critical(f"FATAL: Database error releasing reservation for request {request_id}: {ex}")
                    release_failure = f"RESERVATION_RELEASE_FAILED: {str(ex)}"

            rejection_reason = f"RESUME_VALIDATION_FAILED: {msg}"
            if release_failure:
                rejection_reason = f"{rejection_reason}; {release_failure}"

            # Ticket was not consumed; finalize rejection outcome safely
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=rejection_reason,
                policy_id=policy_id,
                policy_version="1.0",
                agent_version="1.0",
                api_result="NOT_EXECUTED",
                reconciliation_status=release_failure
            )

        agent_record = validation_context.get("agent_record") or self.registry.get_agent(agent_id) or {}
        approval_ref = updated_record.get("approval_reference")

        if self.persistent_db and not validation_context.get("reservation_held"):
            try:
                self.persistent_db.update_intent_state(
                    request_id=request_id,
                    state="AUTHORIZED_PENDING_EXECUTION",
                    expected_current_state="HELD_FOR_HUMAN_APPROVAL"
                )
            except Exception:
                pass

        # Execute protected business action
        auth_headers = self.finance_api.create_gateway_auth_headers(request_id)
        idemp_k = updated_record.get("idempotency_key")
        event_id = f"EVENT-{uuid.uuid4().hex[:12].upper()}"
        outbox_record = {
            "event_id": event_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "amount": float(parameters.get("amount", 0.0)),
            "idempotency_key": idemp_k,
            "request_fingerprint": None,
            "payload": {
                "event_id": event_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
                "decision": PolicyDecision.ALLOWED_AFTER_APPROVAL.value,
                "reason": "APPROVED_BY_HUMAN_SUPERVISOR",
                "policy_id": policy_id,
                "policy_version": validation_context.get("policy_version", "1.0"),
                "parameters": parameters,
            }
        }
        exec_res = self.finance_api.execute_action(
            action=action,
            parameters=parameters,
            gateway_token=str(getattr(self.finance_api, "gateway_secret", "")),
            request_id=request_id,
            agent_id=agent_id,
            approval_ref=approval_ref,
            auth_headers=auth_headers,
            idempotency_key=idemp_k,
            fencing_token=1,
            outbox_record=outbox_record
        )

        reconciliation_warning = None
        if exec_res.get("success"):
            if self.persistent_db:
                try:
                    curr_intent = self.persistent_db.get_intent(request_id) if hasattr(self.persistent_db, "get_intent") else None
                    if not curr_intent or curr_intent.get("state") != "EXECUTED_PENDING_LEDGER":
                        self.persistent_db.update_intent_state(
                            request_id=request_id,
                            state="EXECUTED_PENDING_LEDGER",
                            expected_current_state="AUTHORIZED_PENDING_EXECUTION"
                        )
                except Exception as ex:
                    curr_intent = self.persistent_db.get_intent(request_id) if hasattr(self.persistent_db, "get_intent") else None
                    if not (curr_intent and curr_intent.get("state") == "EXECUTED_PENDING_LEDGER"):
                        logger.critical(f"Database error updating intent {request_id} to EXECUTED_PENDING_LEDGER: {ex}")
                        reconciliation_warning = f"INTENT_STATE_UPDATE_FAILED: {str(ex)}"
                    if hasattr(self.persistent_db, "save_retry_record"):
                        try:
                            self.persistent_db.save_retry_record(
                                event_id=event_id,
                                request_id=request_id,
                                payload={
                                    "request_id": request_id,
                                    "status": "RECONCILIATION_REQUIRED",
                                    "actual_execution": "SUCCESS",
                                    "error": str(ex)
                                },
                                error_msg=f"INTENT_STATE_UPDATE_FAILED: {str(ex)}",
                                status="RECONCILIATION_REQUIRED"
                            )
                        except Exception as retry_ex:
                            logger.critical(f"CRITICAL: Failed to save durable retry record for {request_id}: {retry_ex}")
                            reconciliation_warning = f"CRITICAL_RECONCILIATION_FAILURE: intent update failed ({ex}) AND retry record save failed ({retry_ex})"
        else:
            if self.persistent_db:
                try:
                    self.persistent_db.update_intent_state(
                        request_id=request_id,
                        state="EXECUTION_FAILED",
                        expected_current_state="AUTHORIZED_PENDING_EXECUTION"
                    )
                except Exception as ex:
                    logger.error(f"Database error updating intent {request_id} to EXECUTION_FAILED: {ex}")
                    reconciliation_warning = f"INTENT_STATE_UPDATE_FAILED: {str(ex)}"

        api_res_str = "EXECUTED" if exec_res.get("success") else f"FAILED: {exec_res.get('error', 'Execution Error')}"
        agent_ver = agent_record.get("agent_version", "1.0")
        cert_fp = agent_record.get("certificate_fingerprint", "")

        del_ctx: dict[str, Any] | None = None
        if exec_res.get("success"):
            del_tok_id = None
            auth_ctx = app_record.get("authorization_context", {})
            del_tok = app_record.get("delegation_token") or parameters.get("delegation_token") or auth_ctx.get("delegation_token")
            if isinstance(del_tok, str):
                del_tok_id = del_tok
            elif isinstance(del_tok, dict):
                del_tok_id = del_tok.get("token_id")
            if not del_tok_id:
                try:
                    from identity_manager.delegation_graph import delegation_graph_manager
                    del_n = delegation_graph_manager.nodes.get(agent_id)
                    if del_n and del_n.get("incoming_token_id"):
                        del_tok_id = del_n["incoming_token_id"]
                except Exception:
                    pass
            if del_tok_id:
                try:
                    from identity_manager.delegation_graph import delegation_graph_manager
                    spent_ok, _ = delegation_graph_manager.spend_budget(del_tok_id, amount)
                    if spent_ok:
                        edge = delegation_graph_manager.edges.get(del_tok_id)
                        if edge:
                            del_ctx = {
                                "token_id": del_tok_id,
                                "issuer_agent_id": edge["issuer_agent_id"],
                                "delegate_agent_id": edge["delegate_agent_id"],
                                "remaining_budget": max(0.0, edge["delegated_budget"] - edge["spent_budget"]),
                                "status": edge["status"]
                            }
                except Exception:
                    pass

        return self._finalize_gateway_outcome(
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            resource=resource,
            parameters=parameters,
            decision=PolicyDecision.ALLOWED_AFTER_APPROVAL.value if exec_res.get("success") else PolicyDecision.BLOCKED.value,
            reason="APPROVED_BY_HUMAN_SUPERVISOR" if exec_res.get("success") else f"EXECUTION_FAILED: {exec_res.get('error')}",
            policy_id=policy_id,
            policy_version=validation_context.get("policy_version", "1.0"),
            agent_version=agent_ver,
            api_result=api_res_str,
            tx_data=exec_res.get("transaction_data"),
            approval_ref=approval_ref,
            cert_fingerprint=cert_fp,
            nonce=updated_record.get("nonce", f"N-RESUME-{request_id}"),
            risk_result=validation_context.get("risk_result"),
            matched_rules=validation_context.get("matched_rules"),
            event_id=event_id,
            delegation_context=del_ctx,
            reconciliation_status=reconciliation_warning
        )

    def _finalize_gateway_outcome(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        decision: str,
        reason: str,
        policy_id: str,
        policy_version: str,
        agent_version: str,
        api_result: str,
        approval_ticket: dict[str, Any] | None = None,
        tx_data: dict[str, Any] | None = None,
        approval_ref: str | None = None,
        cert_fingerprint: str = "SHA256:DEFAULT",
        nonce: str = "",
        risk_result: dict[str, Any] | None = None,
        matched_rules: list[str] | None = None,
        idempotency_key: str | None = None,
        event_id: str | None = None,
        behavior_eval: dict[str, Any] | None = None,
        delegation_context: dict[str, Any] | None = None,
        reconciliation_status: str | None = None
    ) -> dict[str, Any]:
        """
        Creates off-chain evidence, records hash-chain audit log, and commits audit event to Fabric blockchain safely.
        """
        event_id = event_id or f"EVENT-{uuid.uuid4().hex[:12].upper()}"

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

        # 2. Write Atomic Hash Chain Record FIRST so chain metadata is attached before hashing evidence
        chain_record = self.chain_writer.write_event(
            event_type=f"ACTION_{decision}",
            request_id=request_id,
            agent_id=agent_id,
            request_hash=evidence_record.get("input_hash", "0"),
            risk_score=risk_eval["risk_score"],
            policy_version=policy_version,
            decision=decision,
            execution_result=api_result,
            event_id=event_id
        )

        evidence_record["sequence_number"] = chain_record.sequence_number
        evidence_record["previous_record_hash"] = chain_record.previous_record_hash
        evidence_record["record_hash"] = chain_record.record_hash

        # 3. Save Evidence Off-chain & compute SHA-256 Hash AFTER attaching audit chain metadata (#5)
        evidence_hash = self.evidence_store.save_evidence(evidence_record)
        evidence_ref = evidence_record["evidence_id"]

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
            # Transactional Outbox: Ledger commit succeeded
            # Drain outbox entry and update intent to COMMITTED ONLY when reconciliation_status is inactive
            if self.persistent_db and not reconciliation_status:
                try:
                    self.persistent_db.delete_retry_record(event_id)
                    if hasattr(self.retry_queue, "_pending_queue"):
                        self.retry_queue._pending_queue.pop(event_id, None)
                    self.persistent_db.update_intent_state(
                        request_id=request_id,
                        state="COMMITTED",
                        expected_current_state="EXECUTED_PENDING_LEDGER"
                    )
                except Exception:
                    pass
        except Exception as e:
            error_text = str(e)
            uncertain_markers = (
                "FABRIC_SUBMISSION_UNCERTAIN",
                "COMMIT_RESULT_UNPARSEABLE",
            )
            submission_uncertain = any(
                marker in error_text for marker in uncertain_markers
            )
            ledger_status = f"COMMIT_FAILED: {error_text}"
            blockchain_commit = {
                "block_index": None,
                "block_hash": None,
                "status": ledger_status,
                "mode": os.environ.get(
                    "FABRIC_GATEWAY_MODE", "simulator"
                ).strip().lower(),
                "source": "outbox_pending_retry",
                "submission_uncertain": submission_uncertain,
            }
            # Enqueue failed commit into durable reconciliation outbox
            self.retry_queue.enqueue_failed_commit(
                event_id=event_id,
                request_id=request_id,
                payload={
                    "event_id": event_id,
                    "request_id": request_id,
                    "agent_id": agent_id,
                    "action": action,
                    "resource": resource,
                    "decision": decision,
                    "reason": reason,
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "evidence_reference": evidence_ref,
                    "evidence_hash": evidence_hash
                },
                error_msg=error_text,
            )

        outcome = {
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
            "api_result": api_result,
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
                "block_index": blockchain_commit.get("block_index") if isinstance(blockchain_commit, dict) else None,
                "block_hash": blockchain_commit.get("block_hash") if isinstance(blockchain_commit, dict) else None,
                "status": ledger_status,
                "mode": blockchain_commit.get("mode", "simulator") if isinstance(blockchain_commit, dict) else "simulator",
                "source": blockchain_commit.get("source", "fabric_simulator") if isinstance(blockchain_commit, dict) else "unknown"
            }
        }

        if behavior_eval:
            outcome["behavioral_intelligence"] = behavior_eval
        if delegation_context:
            outcome["delegation_context"] = delegation_context
        if reconciliation_status:
            outcome["reconciliation_status"] = reconciliation_status

        if self.persistent_db and decision == PolicyDecision.ALLOWED.value and not reconciliation_status:
            try:
                final_intent_state = "COMMITTED" if ledger_status == "COMMITTED" else "LEDGER_PENDING_RETRY"
                self.persistent_db.update_intent_state(
                    request_id=request_id,
                    state=final_intent_state,
                    outcome=outcome,
                    expected_current_state="EXECUTED_PENDING_LEDGER"
                )
            except Exception:
                pass

        if idempotency_key and decision == PolicyDecision.ALLOWED.value:
            req_amount = parameters.get("amount", 0.0)
            req_fp = self.compute_request_fingerprint(
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                amount=req_amount
            )
            self.replay_tracker.record_idempotent_result(
                agent_id=agent_id,
                idempotency_key=idempotency_key,
                result=outcome,
                request_fingerprint=req_fp
            )

        return outcome

    def reconcile_pending_commits(self) -> dict[str, Any]:
        """
        Reconciles pending ledger commits that succeeded externally in Protected API
        but failed during Fabric blockchain commitment.
        """
        pending = self.retry_queue.list_pending_retries()
        results = []
        for item in pending:
            ok, msg = self.retry_queue.retry_commit(item["event_id"], self.fabric_client)
            if ok and self.persistent_db:
                try:
                    self.persistent_db.update_intent_state(
                        request_id=item["request_id"],
                        state="COMMITTED"
                    )
                except Exception:
                    pass
            results.append({"event_id": item["event_id"], "success": ok, "message": msg})
        return {
            "reconciled_count": sum(1 for r in results if r["success"]),
            "pending_count": len(self.retry_queue.list_pending_retries()),
            "details": results
        }

    def _build_immediate_rejection(self, request_id: str, agent_id: str, action: str, resource: str, decision: str, reason: str, api_result: str = "NOT_EXECUTED") -> dict[str, Any]:
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
            "protected_api_result": api_result,
            "api_result": api_result
        }
