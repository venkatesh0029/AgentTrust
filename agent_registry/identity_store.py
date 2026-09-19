import datetime
from typing import Dict, Optional, List, Any
from agent_registry.status_manager import AgentStatus, StatusManager

class IdentityStore:
    """
    In-memory and persistent store for registered AI agent profiles.
    """

    def __init__(self):
        self._agents: Dict[str, Dict[str, Any]] = {}

    def save_agent(self, agent_record: Dict[str, Any]) -> None:
        """Saves or updates an agent record."""
        agent_id = agent_record["agent_id"]
        self._agents[agent_id] = agent_record

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves agent record by ID."""
        return self._agents.get(agent_id)

    def list_agents(self) -> List[Dict[str, Any]]:
        """Returns all registered agent records."""
        return list(self._agents.values())

    def update_status(self, agent_id: str, new_status: AgentStatus, reason: str = "") -> bool:
        """Updates status of an agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            return False

        agent["status"] = new_status.value
        agent["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        agent["status_reason"] = reason
        self.save_agent(agent)
        return True

    def delete_agent(self, agent_id: str) -> bool:
        """Deletes/deactivates an agent record."""
        if agent_id in self._agents:
            del self._agents[agent_id]
            return True
        return False
