"""
Model Context Protocol (MCP) & Agent-to-Agent (A2A) Governance Gateway.
Proxies MCP tool-call requests through the AgentTrust Action Gateway before tool execution.
"""

from typing import Dict, Any, Callable, Optional
from action_gateway.gateway import ActionGateway

class MCPGovernanceGateway:
    """
    Governance interceptor for Model Context Protocol (MCP) servers and A2A agents.
    Enforces AgentTrust policy, signature checks, and ledger logging on MCP tool calls.
    """

    def __init__(self, action_gateway: ActionGateway):
        self.action_gateway = action_gateway

    def handle_mcp_tool_call(
        self,
        mcp_request: Dict[str, Any],
        tool_executor: Callable[[str, Dict[str, Any]], Any]
    ) -> Dict[str, Any]:
        """
        Processes an incoming MCP tool call:
        Format: {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "transfer_funds",
                "arguments": {"recipient_account": "ACC-123", "amount": 500.0},
                "agenttrust_payload": { ... }
            }
        }
        """
        params = mcp_request.get("params", {})
        tool_name = params.get("name", "UNKNOWN_TOOL")
        arguments = params.get("arguments", {})
        payload = params.get("agenttrust_payload")

        if not payload:
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "error": {
                    "code": -32600,
                    "message": "AgentTrust Governance Failure: Missing 'agenttrust_payload' signature in MCP request."
                }
            }

        # Process request through 13-stage Action Gateway
        gw_result = self.action_gateway.process_request(payload)

        if gw_result.get("decision") in ["ALLOWED", "ALLOWED_AFTER_APPROVAL"]:
            # Execute actual underlying MCP tool
            tool_output = tool_executor(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "result": {
                    "content": [{"type": "text", "text": str(tool_output)}],
                    "agenttrust_evidence": gw_result.get("evidence")
                }
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": mcp_request.get("id"),
                "error": {
                    "code": -32001,
                    "message": f"AgentTrust Governance Intercepted MCP Tool '{tool_name}': {gw_result.get('reason')} (Decision: {gw_result.get('decision')})"
                }
            }
