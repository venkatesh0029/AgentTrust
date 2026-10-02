from enum import Enum


class AdminRole(str, Enum):
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    POLICY_ADMIN = "POLICY_ADMIN"
    FINANCE_APPROVER = "FINANCE_APPROVER"
    AUDITOR = "AUDITOR"

class RBACManager:
    """
    Role-Based Access Control (RBAC) Manager for Administrator Operations.
    """

    ROLE_PERMISSIONS = {
        AdminRole.SYSTEM_ADMIN: [
            "register_agent", "revoke_agent", "suspend_agent", "reactivate_agent",
            "rotate_agent_key", "delete_agent", "view_agents", "view_policies",
            "view_audit", "view_evidence", "verify_evidence", "view_blockchain",
            "switch_mode", "simulate_tamper"
        ],
        AdminRole.POLICY_ADMIN: [
            "create_policy", "update_policy", "rollback_policy", "view_policy",
            "view_policies", "view_audit"
        ],
        AdminRole.FINANCE_APPROVER: [
            "approve_transaction", "reject_transaction", "view_pending_approvals",
            "initiate_transfer", "view_audit"
        ],
        AdminRole.AUDITOR: [
            "view_audit", "view_evidence", "verify_evidence", "view_blockchain",
            "view_agents", "view_policies"
        ]
    }

    @classmethod
    def is_action_allowed(cls, role: AdminRole, required_permission: str) -> bool:
        """Verifies if the specified administrator role has the required permission."""
        permissions = cls.ROLE_PERMISSIONS.get(role, [])
        return required_permission in permissions
