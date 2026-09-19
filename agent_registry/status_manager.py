from enum import Enum

class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"

class StatusManager:
    """
    Validates and transitions AI agent operational statuses.
    """

    VALID_TRANSITIONS = {
        AgentStatus.ACTIVE: [AgentStatus.SUSPENDED, AgentStatus.REVOKED, AgentStatus.EXPIRED],
        AgentStatus.SUSPENDED: [AgentStatus.ACTIVE, AgentStatus.REVOKED, AgentStatus.EXPIRED],
        AgentStatus.REVOKED: [],  # Terminal state
        AgentStatus.EXPIRED: [AgentStatus.ACTIVE]  # Can reactivate upon cert renewal
    }

    @classmethod
    def can_transition(cls, current_status: AgentStatus, new_status: AgentStatus) -> bool:
        """Checks if status transition is allowed."""
        return new_status in cls.VALID_TRANSITIONS.get(current_status, [])
