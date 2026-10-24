"""
Policy Engine & Version Control Router.
Manages versioned agent authorization policies, limits, working hours, and rollbacks.
"""

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from policy_engine.policy_models import PolicyRecord, WorkingHours

router = APIRouter(prefix="/policies", tags=["Policy Engine & Versioning"])


class PolicyCreateRequest(BaseModel):
    policy_id: str = Field(...)
    agent_id: str = Field("*")
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_resource: str = Field("*")
    allowed_resources: list[str] | None = None
    maximum_amount: float = Field(100000.0)
    max_amount_per_action: float | None = None
    human_approval_above: float = Field(10000.0)
    human_approval_threshold: float | None = None
    working_hours_start: str | int = Field("00:00")
    working_hours_end: str | int = Field("23:59")
    version: str = Field("1.0")


class PolicyRollbackRequest(BaseModel):
    policy_id: str
    target_version: str = Field(...)
    author: str = Field("POLICY_ADMIN")


def get_policy_loader():
    from server import policy_loader
    return policy_loader


def check_perm(perm: str, x_admin_role: str | None, authorization: str | None):
    from server import check_admin_permission
    return check_admin_permission(perm, x_admin_role, authorization)


@router.get("", summary="List All Active Security Policies")
def list_policies():
    loader = get_policy_loader()
    policies = loader.list_policies()
    return {"policies": [p.model_dump() for p in policies], "total": len(policies)}


@router.get("/{policy_id}", summary="Get Policy Details & Version History")
def get_policy(policy_id: str):
    loader = get_policy_loader()
    pol = loader.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    return {"policy": pol.model_dump(), "version_history": [h.model_dump() for h in pol.version_history]}


@router.post("", summary="Create or Update Versioned Policy")
def create_or_update_policy(
    req: PolicyCreateRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    role = check_perm("create_policy", x_admin_role, authorization)
    role_val = role.value if hasattr(role, "value") else str(role)

    resource = req.allowed_resource
    if (not resource or resource == "*") and req.allowed_resources:
        resource = req.allowed_resources[0] if len(req.allowed_resources) == 1 else ",".join(req.allowed_resources)

    max_amt = req.max_amount_per_action if req.max_amount_per_action is not None else req.maximum_amount
    human_thresh = req.human_approval_threshold if req.human_approval_threshold is not None else req.human_approval_above

    wh_start = str(req.working_hours_start)
    if ":" not in wh_start:
        try:
            wh_start = f"{int(wh_start):02d}:00"
        except ValueError:
            wh_start = "00:00"
    wh_end = str(req.working_hours_end)
    if ":" not in wh_end:
        try:
            wh_end = f"{int(wh_end):02d}:00"
        except ValueError:
            wh_end = "23:59"

    policy = PolicyRecord(
        policy_id=req.policy_id,
        agent_id=req.agent_id,
        allowed_actions=req.allowed_actions,
        allowed_resource=resource,
        maximum_amount=max_amt,
        human_approval_above=human_thresh,
        working_hours=WorkingHours(start=wh_start, end=wh_end),
        version=req.version,
        status="ACTIVE"
    )

    loader = get_policy_loader()
    loader.save_policy(policy, author=role_val, reason="Policy API Create/Update")

    from server import fabric_client
    try:
        fabric_client.chaincode.RegisterPolicy(req.policy_id, req.agent_id, policy.model_dump())
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "success": True,
        "policy": policy.model_dump(),
        "authorized_by": role_val
    }


@router.post("/rollback", summary="Roll Back Policy to Previous Version")
def rollback_policy(
    req: PolicyRollbackRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    role = check_perm("rollback_policy", x_admin_role, authorization)
    role_val = role.value if hasattr(role, "value") else str(role)

    loader = get_policy_loader()
    res = loader.rollback_policy(req.policy_id, req.target_version, author=role_val)
    if not res:
        raise HTTPException(
            status_code=400,
            detail=f"Rollback failed. Policy or version '{req.target_version}' not found."
        )

    from server import fabric_client
    try:
        fabric_client.chaincode.RegisterPolicy(req.policy_id, res.agent_id, res.model_dump())
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "success": True,
        "message": f"Policy rolled back to version {req.target_version}",
        "policy": res.model_dump(),
        "authorized_by": role_val
    }
