"""
Agent Management & Identity Lifecycle Router.
Handles Agent Registration, X.509 Certificate Issuance, Status Changes, and Delegation Tokens.
"""

from typing import Any
from fastapi import APIRouter, Body, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/agents", tags=["Agent Identity & Lifecycle"])


class RegisterAgentRequest(BaseModel):
    agent_id: str = Field(...)
    agent_name: str = Field("Unnamed Agent")
    owner: str = Field("Enterprise User")
    organization: str = Field("OrgA")
    roles: list[str] = Field(default_factory=lambda: ["finance_agent"])
    policy_id: str = Field("FIN-POL-001")
    public_key_pem: str | None = None


class AgentStatusUpdateRequest(BaseModel):
    agent_id: str
    status: str = Field(...)  # ACTIVE, SUSPENDED, REVOKED
    reason: str = Field("Administrative update")


class KeyRotationRequest(BaseModel):
    agent_id: str
    new_public_key_pem: str | None = None


def get_agent_registry():
    from server import agent_registry
    return agent_registry


def check_perm(perm: str, x_admin_role: str | None, authorization: str | None):
    from server import check_admin_permission
    return check_admin_permission(perm, x_admin_role, authorization)


@router.post("/register", summary="Register New Agent & Issue X.509 Certificate")
def register_agent(
    req: RegisterAgentRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    check_perm("register_agent", x_admin_role, authorization)
    registry = get_agent_registry()
    result = registry.register_agent(
        agent_id=req.agent_id,
        agent_name=req.agent_name,
        owner=req.owner,
        organization=req.organization,
        policy_id=req.policy_id,
        public_key_pem=req.public_key_pem
    )
    return {"status": "SUCCESS", "agent": result}


@router.get("", summary="List All Registered Agents")
def list_agents(
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    registry = get_agent_registry()
    return {"agents": registry.list_agents(), "total": len(registry.list_agents())}


@router.get("/{agent_id}", summary="Get Agent Information & Status")
def get_agent(agent_id: str):
    registry = get_agent_registry()
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return agent


@router.put("/status", summary="Update Agent Status (ACTIVE / SUSPENDED / REVOKED)")
def update_agent_status(
    req: AgentStatusUpdateRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    perm = "revoke_agent" if req.status == "REVOKED" else ("suspend_agent" if req.status == "SUSPENDED" else "reactivate_agent")
    check_perm(perm, x_admin_role, authorization)
    registry = get_agent_registry()
    success, msg = registry.update_status(req.agent_id, req.status, req.reason)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "SUCCESS", "message": msg, "agent_id": req.agent_id, "new_status": req.status}


@router.post("/rotate-key", summary="Rotate Agent Public/Private Key Pair")
def rotate_key(
    req: KeyRotationRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    check_perm("rotate_agent_key", x_admin_role, authorization)
    registry = get_agent_registry()
    res = registry.rotate_key(req.agent_id, req.new_public_key_pem)
    return res
