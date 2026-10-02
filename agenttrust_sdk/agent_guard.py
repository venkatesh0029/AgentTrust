"""
AgentTrust Python SDK & AI Framework Middleware.
Provides native decorator (@agenttrust_guarded) for integrating autonomous AI agents
(LangChain, CrewAI, AutoGen, LlamaIndex, OpenAI Tool Calling) with AgentTrust Security Gateway.
"""

import datetime
import functools
import uuid
from collections.abc import Callable
from typing import Any

import requests  # type: ignore[import-untyped]

from identity_manager.signature_manager import SignatureManager


class AgentTrustSDK:
    """
    Client SDK for AI Agents interacting with the AgentTrust Action Gateway.
    """

    def __init__(self, gateway_url: str = "http://127.0.0.1:8000", admin_role: str | None = None, use_local_gateway: bool = False):
        self.gateway_url = gateway_url.rstrip("/")
        self.admin_role = admin_role
        self.use_local_gateway = use_local_gateway

    def submit_action(
        self,
        agent_id: str,
        private_key_pem: str,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        amount: float | None = None
    ) -> dict[str, Any]:
        """
        Constructs a cryptographically signed payload and submits it to the AgentTrust Gateway.
        Fails closed on network failures when remote gateway mode is enabled.
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
            else:
                return {
                    "decision": "BLOCKED",
                    "status_code": response.status_code,
                    "reason": response.json().get("detail", "HTTP_REQUEST_FAILED") if response.headers.get("content-type") == "application/json" else "HTTP_REQUEST_FAILED",
                    "protected_api_result": "DENIED"
                }
        except Exception as e:
            # Fail Closed: Return BLOCKED decision and log network failure error
            return {
                "decision": "BLOCKED",
                "reason": f"SDK_NETWORK_ERROR: Unable to reach AgentTrust Gateway ({e!s})",
                "protected_api_result": "DENIED"
            }

def agenttrust_guarded(
    agent_id: str,
    private_key_pem: str,
    action: str,
    resource: str,
    gateway_url: str = "http://127.0.0.1:8000",
    use_local_gateway: bool = False
):
    """
    Decorator for AI Agent tool functions. Intercepts tool executions and passes
    them through the AgentTrust Action Gateway before real execution.
    """
    sdk = AgentTrustSDK(gateway_url=gateway_url, use_local_gateway=use_local_gateway)

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
