import datetime
from typing import Dict, Any, Tuple, List
from policy_engine.policy_models import PolicyRecord, PolicyDecision, DecisionReason
from policy_engine.policy_loader import PolicyLoader

class PolicyEvaluator:
    """
    Evaluates action requests against registered policies.
    Enforces 'Deny by Default' and 'Most Restrictive Rule Wins' Conflict Resolution.
    """

    def __init__(self, loader: PolicyLoader):
        self.loader = loader

    def evaluate(
        self,
        policy_id: str,
        action: str,
        resource: str,
        amount: float,
        request_timestamp_iso: str,
        risk_score: float = 0.0,
        risk_level: str = "LOW"
    ) -> Tuple[PolicyDecision, DecisionReason, str, List[str]]:
        """
        Evaluates policy rules with Deny-by-Default, Risk Integration, and Most-Restrictive Enforcement.
        Returns: (PolicyDecision, DecisionReason, policy_version, matched_rules)
        """
        matched_rules = []
        policy = self.loader.get_policy(policy_id)

        # Deny by default if policy not found or inactive
        if not policy:
            matched_rules.append("deny_by_default_missing_policy")
            return PolicyDecision.BLOCKED, DecisionReason.POLICY_NOT_FOUND, "1.0", matched_rules

        if policy.status != "ACTIVE":
            matched_rules.append("deny_inactive_policy")
            return PolicyDecision.BLOCKED, DecisionReason.POLICY_NOT_FOUND, policy.version, matched_rules

        # Explicit Denial for DELETE_ACCOUNT action
        if action.upper() == "DELETE_ACCOUNT":
            matched_rules.append("explicit_delete_account_denial")
            return PolicyDecision.BLOCKED, DecisionReason.ACTION_NOT_PERMITTED, policy.version, matched_rules

        # 1. Action Authorization Check (Deny by default if action not listed)
        if action not in policy.allowed_actions and "*" not in policy.allowed_actions:
            matched_rules.append("action_not_in_allowed_list")
            return PolicyDecision.BLOCKED, DecisionReason.ACTION_NOT_PERMITTED, policy.version, matched_rules

        # 2. Resource Authorization Check
        if resource != policy.allowed_resource and policy.allowed_resource != "*":
            matched_rules.append("resource_not_in_allowed_list")
            return PolicyDecision.BLOCKED, DecisionReason.RESOURCE_NOT_PERMITTED, policy.version, matched_rules

        # 3. Working Hours Check
        if not self._check_working_hours(request_timestamp_iso, policy.working_hours.start, policy.working_hours.end):
            matched_rules.append("working_hours_violation")
            return PolicyDecision.BLOCKED, DecisionReason.TIME_WINDOW_VIOLATION, policy.version, matched_rules

        # 4. Maximum Amount Authority Limit Check (Most Restrictive)
        if amount > policy.maximum_amount:
            matched_rules.append("amount_exceeds_maximum_authority_limit")
            return PolicyDecision.BLOCKED, DecisionReason.AUTHORITY_LIMIT_EXCEEDED, policy.version, matched_rules

        # 5. Risk Score Threshold Escalation (Risk Score > 70 requires human approval)
        if risk_score > 70 or risk_level == "HIGH":
            matched_rules.append("high_risk_score_escalation_rule")
            return PolicyDecision.PENDING_HUMAN_APPROVAL, DecisionReason.HIGH_VALUE_TRANSACTION, policy.version, matched_rules

        # 6. Human Approval Threshold Check
        if amount > policy.human_approval_above:
            matched_rules.append("amount_above_human_approval_threshold")
            return PolicyDecision.PENDING_HUMAN_APPROVAL, DecisionReason.HIGH_VALUE_TRANSACTION, policy.version, matched_rules

        matched_rules.append("within_authorized_policy_limits")
        return PolicyDecision.ALLOWED, DecisionReason.WITHIN_AUTHORITY_LIMIT, policy.version, matched_rules

    def resolve_conflicting_policies(
        self, policy_ids: List[str], action: str, resource: str, amount: float, timestamp_iso: str
    ) -> Tuple[PolicyDecision, DecisionReason, str]:
        """
        Conflict Resolver: Evaluates multiple active policies.
        Applies 'Most Restrictive Rule Wins' principle.
        If ANY policy blocks -> BLOCKED.
        If ANY policy requires Human Approval -> PENDING_HUMAN_APPROVAL.
        """
        if not policy_ids:
            return PolicyDecision.BLOCKED, DecisionReason.POLICY_NOT_FOUND, "1.0"

        decisions = []
        versions = []

        for pid in policy_ids:
            dec, reason, ver, _ = self.evaluate(pid, action, resource, amount, timestamp_iso)
            decisions.append((dec, reason))
            versions.append(ver)

        # Most restrictive precedence: BLOCKED > PENDING_HUMAN_APPROVAL > ALLOWED
        for dec, reason in decisions:
            if dec == PolicyDecision.BLOCKED:
                return PolicyDecision.BLOCKED, reason, versions[0]

        for dec, reason in decisions:
            if dec == PolicyDecision.PENDING_HUMAN_APPROVAL:
                return PolicyDecision.PENDING_HUMAN_APPROVAL, reason, versions[0]

        return PolicyDecision.ALLOWED, DecisionReason.WITHIN_AUTHORITY_LIMIT, versions[0]

    @staticmethod
    def _check_working_hours(request_timestamp_iso: str, start_str: str, end_str: str) -> bool:
        """Verifies if request timestamp falls within configured working hours (e.g. 09:00 - 18:00)."""
        try:
            dt = datetime.datetime.fromisoformat(request_timestamp_iso)
            request_time = dt.time()

            start_parts = [int(x) for x in start_str.split(':')]
            end_parts = [int(x) for x in end_str.split(':')]

            start_time = datetime.time(start_parts[0], start_parts[1])
            end_time = datetime.time(end_parts[0], end_parts[1])

            return start_time <= request_time <= end_time
        except Exception:
            return True
