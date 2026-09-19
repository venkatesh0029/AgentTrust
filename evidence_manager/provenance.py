import hashlib
import json
import datetime
from typing import Dict, Any, Optional

class ProvenanceBuilder:
    """
    Constructs canonical Schema v2.0 off-chain evidence context records.
    """

    @staticmethod
    def build_evidence(
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
        cert_fingerprint: str = "SHA256:DEFAULT",
        nonce: str = "",
        approval_reference: Optional[str] = None,
        error_details: Optional[str] = None,
        execution_trace: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        evidence_id = f"EVIDENCE-{request_id}"

        # Compute deterministic hashes for input parameters and output results
        input_bytes = json.dumps(parameters, sort_keys=True, separators=(',', ':')).encode('utf-8')
        input_hash = hashlib.sha256(input_bytes).hexdigest()

        output_bytes = json.dumps({"api_result": api_result}, sort_keys=True, separators=(',', ':')).encode('utf-8')
        output_hash = hashlib.sha256(output_bytes).hexdigest()

        record = {
            "evidence_schema_version": "2.0",
            "evidence_id": evidence_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "certificate_fingerprint": cert_fingerprint,
            "action": action,
            "resource": resource,
            "input": parameters,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "decision": decision,
            "decision_reason": reason,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "agent_version": agent_version,
            "model_version": "AgentTrust-FinanceAgent-v2.1",
            "tool_version": "AgentTrust-Gateway-v1.0",
            "nonce": nonce,
            "approval_reference": approval_reference,
            "api_execution_result": api_result,
            "error_details": error_details,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "execution_trace": execution_trace or {"prompt_tokens": 120, "model": "AgentTrust-FinanceAgent-v2"}
        }
        return record
