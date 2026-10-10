"""
13-Stage Action Gateway & MCP Governance Router.
Executes agent payloads through zero-trust security checks in non-blocking async threads.
"""

import asyncio
from typing import Any
from fastapi import APIRouter, Body

from routers.health import increment_request_metrics

router = APIRouter(tags=["13-Stage Action Gateway & MCP"])


def get_action_gateway():
    from server import action_gateway
    return action_gateway


def get_mcp_gateway():
    from server import mcp_gateway
    return mcp_gateway


@router.post("/execute", summary="Execute Signed Agent Action via 13-Stage Gateway")
async def execute_action(payload: dict[str, Any] = Body(...)):
    """
    Main Action Gateway Endpoint.
    Enforces 13-Stage Pipeline: Identity -> Cert & Signature -> Status -> Replay/Nonce -> Policy -> Risk -> Approval -> Direct API Execution -> Evidence Store -> Audit Log -> Ledger Commit.
    Runs crypto operations in worker thread pool via asyncio.to_thread to prevent event loop blocking.
    """
    gateway = get_action_gateway()
    # Offload blocking crypto verification to worker thread pool
    result = await asyncio.to_thread(gateway.process_request, payload)
    
    decision = result.get("decision", "BLOCKED")
    increment_request_metrics(decision)
    return result


@router.post("/mcp/v1/tools/call", summary="MCP Tool Governance Gateway Endpoint")
async def mcp_tool_call(mcp_request: dict[str, Any] = Body(...)):
    """
    MCP (Model Context Protocol) Governance Proxy Endpoint.
    Prevents Confused Deputy attacks by verifying tool name and parameter intent binding against signed agent payload.
    """
    mcp_gw = get_mcp_gateway()
    
    # Simple dummy executor for test tool calls
    def dummy_tool_executor(name: str, args: dict[str, Any]):
        return {"executed_tool": name, "arguments": args, "status": "COMPLETED"}

    result = await asyncio.to_thread(mcp_gw.handle_mcp_tool_call, mcp_request, dummy_tool_executor)
    return result
