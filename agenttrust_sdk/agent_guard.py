"""
AgentTrust Python SDK & AI Framework Middleware.
Provides native decorator (@agenttrust_guarded) for integrating autonomous AI agents
(LangChain, CrewAI, AutoGen, LlamaIndex, OpenAI Tool Calling) with AgentTrust Security Gateway.
"""

import functools
import datetime
import uuid
import requests
from typing import Dict, Any, Callable, Optional
from identity_manager.signature_manager import SignatureManager

class AgentTrustSDK:
    """
    Client SDK for AI Agents interacting with the AgentTrust Action Gateway.
    """

    def __init__(self, gateway_url: str = "http://127.0.0.1:8000", admin_role: Optional[str] = None, use_local_gateway: bool = False):
        self.gateway_url = gateway_url.rstrip("/")
        self.admin_role = admin_role or "FINANCE_APPROVER"
        self.use_local_gateway = use_local_gateway

    def submit_action(
        self,
        agent_id: str,
        private_key_pem: str,
        action: str,
        resource: str,
        parameters: Dict[str, Any],
        amount: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Constructs a cryptographically signed payload and submits it to the AgentTrust Gateway.
        """
        request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"
        nonce = f"N-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        req_amount = amount if amount is not None else parameters.get("amount", 0.0)

        payload = {
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "amount": req_amount,
            "parameters": parameters,
            "nonce": nonce,
            "timestamp": timestamp,
            "key_version": 1
        }

        # Generate RSA-PSS Digital Signature
        sig = SignatureManager.sign_request(payload, private_key_pem)
        payload["signature"] = sig

        if self.use_local_gateway:
            from server import action_gateway
            return action_gateway.process_request(payload)

        headers = {"Content-Type": "application/json"}
        if self.admin_role:
            headers["X-Admin-Role"] = self.admin_role

        try:
            response = requests.post(f"{self.gateway_url}/gateway/submit", json=payload, headers=headers, timeout=2.0)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # Agent registered locally, fallback to in-memory action_gateway
                from server import action_gateway
                return action_gateway.process_request(payload)
            else:
                return {
                    "decision": "BLOCKED",
                    "status_code": response.status_code,
                    "reason": response.json().get("detail", "HTTP_REQUEST_FAILED"),
                    "protected_api_result": "DENIED"
                }
        except Exception:
            from server import action_gateway
            return action_gateway.process_request(payload)

def agenttrust_guarded(
    agent_id: str,
    private_key_pem: str,
    action: str,
    resource: str,
    gateway_url: str = "http://127.0.0.1:8000"
):
    """
    Decorator for AI Agent tool functions. Intercepts tool executions and passes
    them through the AgentTrust Action Gateway before real execution.
    """
    sdk = AgentTrustSDK(gateway_url=gateway_url)

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract parameters from function kwargs or positional args
            parameters = kwargs.copy()
            if args:
                parameters["args"] = list(args)

            amount = parameters.get("amount")

            # Route through Gateway
            res = sdk.submit_action(
                agent_id=agent_id,
                private_key_pem=private_key_pem,
                action=action,
                resource=resource,
                parameters=parameters,
                amount=amount
            )

            if res.get("decision") in ["ALLOWED", "ALLOWED_AFTER_APPROVAL"]:
                # Proceed to execute actual underlying tool function
                return func(*args, **kwargs)
            else:
                # Intercepted and blocked by Gateway
                raise PermissionError(
                    f"AgentTrust Enforcement Intercepted Action '{action}': {res.get('reason')} "
                    f"(Decision: {res.get('decision')})"
                )
        return wrapper
    return decorator
