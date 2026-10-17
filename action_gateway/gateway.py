import copy
import datetime
import hashlib
import json
import math
import os
import uuid
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

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
        persistent_db: Any | None = None
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

        quantum = Decimal("1") if scale == 0 else Decimal(f"1e-{scale}")
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
        risk_result = RiskEvaluator.evaluate(
            agent_id=agent_id,
            action=action,
            resource=resource,
            amount=amount,
            agent_record=agent_record,
            request_timestamp_iso=timestamp
        )

        # Step 7.5: Capability Delegation Token Chain Check (Normalize top-level delegation token)
        delegation_token = request_payload.get("delegation_token") or parameters.get("delegation_token")
        if delegation_token:
            parameters["delegation_token"] = delegation_token
            request_payload["delegation_token"] = delegation_token

        if delegation_token and isinstance(delegation_token, dict):
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
            if self.persistent_db:
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

            # Create signed service auth headers
            auth_headers = self.finance_api.create_gateway_auth_headers(request_id)
            try:
                exec_res = self.finance_api.execute_action(
                    action=action,
                    parameters=parameters,
                    gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
                    request_id=request_id,
                    agent_id=agent_id,
                    auth_headers=auth_headers,
                    idempotency_key=idempotency_key,
                    fencing_token=fencing_token
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
                reason=reason.value,
                policy_id=policy_id,
                request_hash=raw_hash,
                policy_version=policy_version,
                authorization_context=auth_context,
                delegation_token=delegation_token
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
            matched_rules=matched_rules,
            idempotency_key=idempotency_key
        )

    def process_human_approval_resume(self, approval_id: str, approver_id: str, provided_token: str | None = None) -> dict[str, Any]:
        """Resumes processing after human supervisor approves a pending request with complete atomic re-validation (#11, #1)."""
        app_record = self.approval_manager.get_approval_by_id(approval_id)
        if not app_record or app_record.get("status") != "PENDING":
            return {"success": False, "message": f"Approval ticket '{approval_id}' not found or not pending."}

        token_to_pass = provided_token or app_record.get("approval_token")

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
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            risk_res = RiskEvaluator.evaluate(
                agent_id=agent_id,
                action=action,
                resource=resource,
                amount=amount,
                agent_record=ag_rec,
                request_timestamp_iso=now_iso
            )
            validation_context["risk_result"] = risk_res

            # 4. Re-evaluate Policy against active policy rules & risk
            dec, rsn, pver, rules = self.policy_evaluator.evaluate(
                policy_id=policy_id,
                action=action,
                resource=resource,
                amount=amount,
                request_timestamp_iso=now_iso,
                risk_score=risk_res.get("risk_score", 0.0),
                risk_level=risk_res.get("risk_level", "LOW")
            )
            validation_context["policy_version"] = pver
            validation_context["matched_rules"] = rules

            if dec == PolicyDecision.BLOCKED:
                return False, f"POLICY_RECHECK_FAILED: {rsn.value}"

            # 5. Re-check Delegation Token (using stored delegation token or parameters)
            del_token = record.get("delegation_token") or parameters.get("delegation_token") or auth_ctx.get("delegation_token")
            if del_token and isinstance(del_token, dict):
                issuer_pub = ag_rec.get("public_key", "")
                del_res = DelegationTokenManager.verify_delegation_chain(
                    del_token, action, amount, issuer_pub, requesting_agent_id=agent_id
                )
                if not del_res.get("valid"):
                    return False, f"DELEGATION_RECHECK_FAILED: {del_res.get('reason')}"

            validation_context["agent_record"] = ag_rec
            return True, "VALID"

        # ATOMICALLY consume approval ticket ONLY if validator passes inside the lock
        ok, updated_record, msg = self.approval_manager.approve_request(
            approval_id, approver_id, provided_token=token_to_pass, validator_fn=_atomic_validator
        )
        if not ok or not updated_record:
            # Ticket was not consumed; finalize rejection outcome safely
            return self._finalize_gateway_outcome(
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                parameters=parameters,
                decision=PolicyDecision.BLOCKED.value,
                reason=f"RESUME_VALIDATION_FAILED: {msg}",
                policy_id=policy_id,
                policy_version="1.0",
                agent_version="1.0",
                api_result="NOT_EXECUTED"
            )

        agent_record = validation_context.get("agent_record") or self.registry.get_agent(agent_id) or {}
        approval_ref = updated_record.get("approval_reference")

        # Execute protected business action
        auth_headers = self.finance_api.create_gateway_auth_headers(request_id)
        idemp_k = updated_record.get("idempotency_key")
        exec_res = self.finance_api.execute_action(
            action=action,
            parameters=parameters,
            gateway_token=ProtectedFinanceAPI.GATEWAY_SECRET,
            request_id=request_id,
            agent_id=agent_id,
            approval_ref=approval_ref,
            auth_headers=auth_headers,
            idempotency_key=idemp_k,
            fencing_token=1
        )

        api_res_str = "EXECUTED" if exec_res.get("success") else f"FAILED: {exec_res.get('error', 'Execution Error')}"
        agent_ver = agent_record.get("agent_version", "1.0")
        cert_fp = agent_record.get("certificate_fingerprint", "")

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
            matched_rules=validation_context.get("matched_rules")
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
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        """
        Creates off-chain evidence, records hash-chain audit log, and commits audit event to Fabric blockchain safely.
        """
        event_id = f"EVENT-{uuid.uuid4().hex[:12].upper()}"

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
        except Exception as e:
            # Failure Recovery: Preserve local evidence safely, do NOT silently claim success!
            ledger_status = f"COMMIT_FAILED: {e!s}"
            blockchain_commit = {
                "block_index": -1,
                "block_hash": "PENDING_RETRY",
                "status": ledger_status,
                "mode": os.environ.get("FABRIC_GATEWAY_MODE", "simulator").strip().lower(),
                "source": "outbox_pending_retry"
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
                error_msg=str(e)
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
                "block_index": blockchain_commit["block_index"],
                "block_hash": blockchain_commit["block_hash"],
                "status": ledger_status,
                "mode": blockchain_commit.get("mode", "simulator") if isinstance(blockchain_commit, dict) else "simulator",
                "source": blockchain_commit.get("source", "fabric_simulator") if isinstance(blockchain_commit, dict) else "unknown"
            }
        }

        if self.persistent_db and decision == PolicyDecision.ALLOWED.value:
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
                        state="COMMITTED",
                        expected_current_state="LEDGER_PENDING_RETRY"
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
