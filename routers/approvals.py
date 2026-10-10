"""
Human-in-the-Loop Approval Ticket Router.
Manages approval queue, ticket inspection, and single-use resumption validation.
"""

from typing import Any
from fastapi import APIRouter, Body, Header, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/approvals", tags=["Human-in-the-Loop Approval"])


class TicketActionRequest(BaseModel):
    ticket_id: str = Field(...)
    approver_id: str = Field("human-supervisor-01")
    reason: str = Field("Approved after manual risk inspection")


class ResumeExecutionRequest(BaseModel):
    ticket_id: str = Field(...)
    original_payload: dict[str, Any] = Body(...)


def get_approval_manager():
    from server import approval_manager
    return approval_manager


def get_action_gateway():
    from server import action_gateway
    return action_gateway


def check_perm(perm: str, x_admin_role: str | None, authorization: str | None):
    from server import check_admin_permission
    return check_admin_permission(perm, x_admin_role, authorization)


@router.get("/pending", summary="List Pending Approval Tickets")
def list_pending_tickets():
    mgr = get_approval_manager()
    return {"pending_tickets": mgr.get_pending_tickets()}


@router.get("/{ticket_id}", summary="Get Ticket Details")
def get_ticket(ticket_id: str):
    mgr = get_approval_manager()
    t = mgr.get_ticket(ticket_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Ticket '{ticket_id}' not found.")
    return t


@router.post("/approve", summary="Approve High-Risk Ticket")
def approve_ticket(
    req: TicketActionRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    check_perm("approve_transaction", x_admin_role, authorization)
    mgr = get_approval_manager()
    success, message = mgr.approve_ticket(req.ticket_id, req.approver_id, req.reason)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "APPROVED", "message": message, "ticket_id": req.ticket_id}


@router.post("/reject", summary="Reject High-Risk Ticket")
def reject_ticket(
    req: TicketActionRequest,
    x_admin_role: str | None = Header(None, alias="X-Admin-Role"),
    authorization: str | None = Header(None)
):
    check_perm("reject_transaction", x_admin_role, authorization)
    mgr = get_approval_manager()
    success, message = mgr.reject_ticket(req.ticket_id, req.approver_id, req.reason)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "REJECTED", "message": message, "ticket_id": req.ticket_id}


@router.post("/resume", summary="Resume Execution for Approved Ticket (TOCTOU Safe)")
def resume_execution(req: ResumeExecutionRequest):
    gateway = get_action_gateway()
    payload = req.original_payload.copy()
    payload["approval_ticket_id"] = req.ticket_id
    res = gateway.process_request(payload)
    return res
