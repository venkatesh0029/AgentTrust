"""
Model Context Protocol (MCP) & Agent-to-Agent (A2A) Governance Gateway.
Proxies MCP tool-call requests through the AgentTrust Action Gateway before tool execution.
Enforces Intent-Bound Execution: verifies that executed tool_name and arguments
are cryptographically bound to the signed agenttrust_payload.
"""

import json
from typing import Dict, Any, Callable, Optional
from action_gateway.gateway import ActionGateway

class MCPGovernanceGateway:
    """
    Governance interceptor for Model Context Protocol (MCP) servers and A2A agents.
    Enforces AgentTrust policy, signature checks, intent-binding, and ledger logging.
    """

    def __init__(self, action_gateway: ActionGateway):
        self.action_gateway = action_gateway

    def handle_mcp_tool_call(
        self,
        mcp_request: Dict[str, Any],
        tool_executor: Callable[[str, Dict[str, Any]], Any]
    ) -> Dict[str, Any]:
        """
        Processes an incoming MCP tool call with Intent-Bound Execution.
        """
        params = mcp_request.get("params", {})
        top_tool_name = params.get("name", "UNKNOWN_TOOL")
        top_arguments = params.get("arguments", {})
        payload = params.get("agenttrust_payload")

        if not payload or not isinstance(payload, dict):
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "error": {
                    "code": -32600,
                    "message": "AgentTrust Governance Failure: Missing or invalid 'agenttrust_payload' signature in MCP request."
                }
            }

        # 1. INTENT-BOUND EXECUTION CHECK: Compare top-level tool_name & arguments with signed payload
        signed_action = payload.get("action", "")
        signed_params = payload.get("parameters", {}) if isinstance(payload.get("parameters"), dict) else {}

        # Normalize action names (e.g. transfer_funds vs TRANSFER_FUNDS)
        norm_top_tool = str(top_tool_name).strip().upper()
        norm_signed_action = str(signed_action).strip().upper()

        if norm_top_tool != norm_signed_action:
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "error": {
                    "code": -32002,
                    "message": f"Confused Deputy Attack Prevented: Top-level tool name '{top_tool_name}' does not match signed payload action '{signed_action}'."
                }
            }

        # Verify arguments match signed parameters
        if isinstance(top_arguments, dict):
            top_amt = top_arguments.get("amount")
            signed_amt = payload.get("amount") if payload.get("amount") is not None else signed_params.get("amount")

            if top_amt is not None and signed_amt is not None:
                try:
                    if abs(float(top_amt) - float(signed_amt)) > 1e-6:
                        return {
                            "jsonrpc": "2.0",
                            "id": mcp_request.get("id"),
                            "error": {
                                "code": -32002,
                                "message": f"Confused Deputy Attack Prevented: Top-level tool amount '{top_amt}' does not match signed payload amount '{signed_amt}'."
                            }
                        }
                except Exception:
                    pass

        # 2. Process request through 13-stage Action Gateway
        gw_result = self.action_gateway.process_request(payload)

        if gw_result.get("decision") in ["ALLOWED", "ALLOWED_AFTER_APPROVAL"]:
            # Execute actual tool ONLY using the verified signed payload action & parameters
            verified_tool_name = signed_action
            verified_arguments = signed_params.copy()
            if payload.get("amount") is not None:
                verified_arguments["amount"] = payload.get("amount")

            tool_output = tool_executor(verified_tool_name, verified_arguments)
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "result": {
                    "content": [{"type": "text", "text": str(tool_output)}],
                    "agenttrust_evidence": gw_result.get("evidence"),
                    "intent_bound_verified": True
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "error": {
                    "code": -32001,
                    "message": f"AgentTrust Governance Intercepted MCP Tool '{signed_action}': {gw_result.get('reason')} (Decision: {gw_result.get('decision')})"
                }
            }
