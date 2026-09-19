import datetime
from typing import Dict, Optional, List, Any
from policy_engine.policy_models import PolicyRecord, PolicyHistoryEntry

class PolicyLoader:
    """
    Manages policy storage, retrieval, version history, and rollbacks.
    """

    def __init__(self):
        self._policies: Dict[str, PolicyRecord] = {}

    def save_policy(self, policy: PolicyRecord, author: str = "POLICY_ADMIN", reason: str = "Policy Update") -> None:
        """Saves or updates policy record, preserving version history."""
        existing = self._policies.get(policy.policy_id)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if existing and existing.version != policy.version:
            # Archive existing state into history before replacing
            history_entry = PolicyHistoryEntry(
                version=existing.version,
                maximum_amount=existing.maximum_amount,
                human_approval_above=existing.human_approval_above,
                allowed_actions=list(existing.allowed_actions),
                allowed_resource=existing.allowed_resource,
                changed_at=now,
                change_author=existing.change_author,
                change_reason=existing.change_reason
            )
            policy.version_history = existing.version_history + [history_entry]
        elif existing:
            policy.version_history = existing.version_history

        policy.effective_from = now
        policy.change_author = author
        policy.change_reason = reason
        self._policies[policy.policy_id] = policy.model_copy(deep=True)

    def rollback_policy(self, policy_id: str, target_version: str, author: str = "POLICY_ADMIN") -> Optional[PolicyRecord]:
        """
        Rolls back policy to a historical version.
        Returns rolled-back PolicyRecord if successful, None otherwise.
        """
        current = self.get_policy(policy_id)
        if not current:
            return None

        # Search in version history
        target_entry = None
        for entry in current.version_history:
            if entry.version == target_version:
                target_entry = entry
                break

        if not target_entry:
            return None

        # Create new version rolling back values
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        history_entry = PolicyHistoryEntry(
            version=current.version,
            maximum_amount=current.maximum_amount,
            human_approval_above=current.human_approval_above,
            allowed_actions=list(current.allowed_actions),
            allowed_resource=current.allowed_resource,
            changed_at=now,
            change_author=current.change_author,
            change_reason=current.change_reason
        )

        try:
            new_version_num = f"{float(current.version) + 0.1:.1f}"
        except Exception:
            new_version_num = "2.1"

        updated = current.model_copy(deep=True)
        updated.maximum_amount = target_entry.maximum_amount
        updated.human_approval_above = target_entry.human_approval_above
        updated.allowed_actions = list(target_entry.allowed_actions)
        updated.allowed_resource = target_entry.allowed_resource
        updated.version = new_version_num
        updated.change_author = author
        updated.change_reason = f"Rollback to version {target_version}"
        updated.version_history = current.version_history + [history_entry]

        self._policies[policy_id] = updated
        return updated

    def get_policy(self, policy_id: str) -> Optional[PolicyRecord]:
        pol = self._policies.get(policy_id)
        return pol.model_copy(deep=True) if pol else None

    def list_policies(self) -> List[PolicyRecord]:
        return [p.model_copy(deep=True) for p in self._policies.values()]
