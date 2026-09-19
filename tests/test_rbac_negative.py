import pytest
from agent_registry.admin_rbac import RBACManager, AdminRole

def test_auditor_attempts_to_revoke_agent_denied():
    assert RBACManager.is_action_allowed(AdminRole.AUDITOR, "revoke_agent") is False

def test_finance_approver_attempts_to_modify_policy_denied():
    assert RBACManager.is_action_allowed(AdminRole.FINANCE_APPROVER, "create_policy") is False
    assert RBACManager.is_action_allowed(AdminRole.FINANCE_APPROVER, "rollback_policy") is False

def test_policy_administrator_attempts_to_approve_reimbursement_denied():
    assert RBACManager.is_action_allowed(AdminRole.POLICY_ADMIN, "approve_transaction") is False

def test_system_admin_has_lifecycle_permissions():
    assert RBACManager.is_action_allowed(AdminRole.SYSTEM_ADMIN, "register_agent") is True
    assert RBACManager.is_action_allowed(AdminRole.SYSTEM_ADMIN, "revoke_agent") is True
