"""
Agent Management & Identity Lifecycle Router.
Handles Agent Registration, X.509 Certificate Issuance, Status Changes, and Delegation Tokens.
"""

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/agents", tags=["Agent Identity & Lifecycle"])


class RegisterAgentRequest(BaseModel):
    agent_id: str = Field(...)
    agent_name: str = Field("Unnamed Agent")
    owner: str = Field("Enterprise User")
    organization: str = Field("OrgA")
    role: str = Field("finance_agent")
    roles: list[str] | None = None
    capabilities: list[str] = Field(default_factory=lambda: ["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS"])
    policy_id: str = Field("FIN-POLICY-001")
    agent_version: str = Field("1.0")
    public_key: str | None = None
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
    role = check_perm("register_agent", x_admin_role, authorization)
    registry = get_agent_registry()
    caps = req.capabilities if req.capabilities else (req.roles if req.roles else ["finance_agent"])
    role_name = req.role if req.role else (req.roles[0] if req.roles else "finance_agent")
    pub_key = req.public_key or req.public_key_pem

    result = registry.register_agent(
        agent_id=req.agent_id,
        agent_name=req.agent_name,
        owner=req.owner,
        capabilities=caps,
        policy_id=req.policy_id,
        agent_version=req.agent_version,
        organization=req.organization,
        role=role_name,
        public_key_pem=pub_key
    )
    from server import fabric_client, cache_manager
    try:
        fabric_client.chaincode.RegisterAgent(req.agent_id, req.owner, result["certificate_fingerprint"])
        cache_manager.delete("agents:list")
        cache_manager.delete(f"agent:{req.agent_id}")
    except Exception:
        pass
    return {"status": "SUCCESS", "success": True, "agent": result, "authorized_by": role.value}


@router.get("", summary="List All Registered Agents")
def list_agents(
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    from server import agent_registry, cache_manager
    cached = cache_manager.get("agents:list")
    if cached:
        return {"agents": cached, "total": len(cached)}
    agents = agent_registry.list_agents()
    cache_manager.set("agents:list", agents, ttl=5)
    return {"agents": agents, "total": len(agents)}


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
