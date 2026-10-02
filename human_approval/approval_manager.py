import datetime
import hashlib
import threading
import uuid
from typing import Any


class HumanApprovalManager:
    """
    Manages human-in-the-loop review queue for high-risk or high-value transactions.
    Generates single-use approval tokens bound to request_id, request_hash, agent_id, and policy_version.
    Thread-safe concurrency protection.
    """

    def __init__(self):
        self._pending_approvals: dict[str, dict[str, Any]] = {}
        self._approval_counter = 100
        self._used_approval_tokens: set[str] = set()
        self._lock = threading.Lock()

    def create_approval_request(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        resource: str,
        parameters: dict[str, Any],
        reason: str,
        policy_id: str,
        request_hash: str = "",
        policy_version: str = "1.0",
        expires_in_seconds: int = 3600
    ) -> dict[str, Any]:
        """Creates a pending human approval ticket with bound approval token."""
        with self._lock:
            self._approval_counter += 1
            approval_id = f"APPR-REQ-{self._approval_counter}"
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            expires_dt = now_dt + datetime.timedelta(seconds=expires_in_seconds)

            raw_token_data = f"{approval_id}:{request_id}:{agent_id}:{policy_version}:{uuid.uuid4().hex}"
            approval_token = f"APPR-TOKEN-{hashlib.sha256(raw_token_data.encode()).hexdigest()[:16].upper()}"

            record = {
                "approval_id": approval_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
                "parameters": parameters,
                "reason": reason,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "request_hash": request_hash,
                "approval_token": approval_token,
                "expires_at": expires_dt.isoformat(),
                "status": "PENDING",
                "created_at": now_dt.isoformat(),
                "approver_id": None,
                "decision_timestamp": None,
                "rejection_reason": None,
                "approval_reference": None
            }
            self._pending_approvals[approval_id] = record
            return record

    def get_approval_by_id(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._pending_approvals.get(approval_id)

    def get_approval_by_request_id(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            for record in self._pending_approvals.values():
                if record["request_id"] == request_id:
                    return record
            return None

    def list_pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return [r for r in self._pending_approvals.values() if r["status"] == "PENDING"]

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._pending_approvals.values())

    def approve_request(
        self,
        approval_id: str,
        approver_id: str = "HUMAN_SUPERVISOR_01",
        provided_token: str | None = None
    ) -> tuple[bool, dict[str, Any] | None, str]:
        """
        Human approver signs off on request using single-use bound approval token.
        Prohibits self-approval where approver_id equals requesting agent_id.
        Returns: (success, approval_record, message)
        """
        with self._lock:
            record = self._pending_approvals.get(approval_id)
            if not record:
                return False, None, "APPROVAL_NOT_FOUND"

            if record["status"] != "PENDING":
                return False, None, f"REQUEST_ALREADY_{record['status']}"

            # Prevent Self-Approval (Approver == Requester Agent)
            if approver_id == record.get("agent_id"):
                return False, None, "SELF_APPROVAL_PROHIBITED: Requester agent cannot self-approve requests"

            token = record["approval_token"]
            if token in self._used_approval_tokens:
                return False, None, "APPROVAL_TOKEN_ALREADY_USED"

            if not provided_token:
                return False, None, "MISSING_APPROVAL_TOKEN"
            if provided_token != token:
                return False, None, "INVALID_APPROVAL_TOKEN"

            # Check expiration
            expires_at = record.get("expires_at")
            if expires_at:
                exp_dt = datetime.datetime.fromisoformat(expires_at)
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                if now_dt > exp_dt:
                    record["status"] = "EXPIRED"
                    return False, None, "APPROVAL_TOKEN_EXPIRED"

            ref_id = f"APPROVAL-2026-{self._approval_counter:03d}"
            record["status"] = "APPROVED"
            record["approver_id"] = approver_id
            record["approved_by"] = approver_id
            record["approval_reference"] = ref_id
            record["decision_timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Mark token as single-use consumed
            self._used_approval_tokens.add(token)

            return True, record, "APPROVED_SUCCESSFULLY"

    def reject_request(self, approval_id: str, approver_id: str = "HUMAN_SUPERVISOR_01", reason: str = "REJECTED_BY_HUMAN") -> tuple[bool, dict[str, Any] | None, str]:
        """Human approver rejects request."""
        with self._lock:
            record = self._pending_approvals.get(approval_id)
            if not record:
                return False, None, "APPROVAL_NOT_FOUND"

            if record["status"] != "PENDING":
                return False, None, f"REQUEST_ALREADY_{record['status']}"

            record["status"] = "REJECTED"
            record["approver_id"] = approver_id
            record["rejection_reason"] = reason
            record["decision_timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            return True, record, "REJECTED_SUCCESSFULLY"
