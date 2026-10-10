"""
Policy Engine & Version Control Router.
Manages versioned agent authorization policies, limits, working hours, and rollbacks.
"""

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/policies", tags=["Policy Engine & Versioning"])


class PolicyCreateRequest(BaseModel):
    policy_id: str = Field(...)
    allowed_actions: list[str] = Field(...)
    allowed_resources: list[str] = Field(default_factory=lambda: ["*"])
    max_amount_per_action: float = Field(10000.0)
    human_approval_threshold: float = Field(5000.0)
    working_hours_start: int = Field(0)
    working_hours_end: int = Field(24)


class PolicyRollbackRequest(BaseModel):
    policy_id: str
    target_version: str = Field(...)


def get_policy_loader():
    from server import policy_loader
    return policy_loader


def check_perm(perm: str, x_admin_role: str | None, authorization: str | None):
    from server import check_admin_permission
    return check_admin_permission(perm, x_admin_role, authorization)


@router.get("", summary="List All Active Security Policies")
def list_policies():
    loader = get_policy_loader()
    return {"policies": loader.list_policies(), "total": len(loader.list_policies())}


@router.get("/{policy_id}", summary="Get Policy Details & Version History")
def get_policy(policy_id: str):
    loader = get_policy_loader()
    pol = loader.get_policy(policy_id)
    if not pol:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
    history = loader.get_policy_history(policy_id)
    return {"policy": pol.dict(), "version_history": history}


@router.post("", summary="Create or Update Versioned Policy")
def create_or_update_policy(
    req: PolicyCreateRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    check_perm("create_policy", x_admin_role, authorization)
    loader = get_policy_loader()
    new_policy = loader.update_policy(
        policy_id=req.policy_id,
        allowed_actions=req.allowed_actions,
        allowed_resources=req.allowed_resources,
        max_amount_per_action=req.max_amount_per_action,
        human_approval_threshold=req.human_approval_threshold,
        working_hours_start=req.working_hours_start,
        working_hours_end=req.working_hours_end
    )
    return {"status": "SUCCESS", "policy": new_policy.dict()}


@router.post("/rollback", summary="Roll Back Policy to Previous Version")
def rollback_policy(
    req: PolicyRollbackRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    check_perm("rollback_policy", x_admin_role, authorization)
    loader = get_policy_loader()
    success, msg = loader.rollback_policy(req.policy_id, req.target_version)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "SUCCESS", "message": msg}
