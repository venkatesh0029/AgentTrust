"""
Identity Store for AgentTrust Framework.
Provides in-memory caching backed by PersistentStorageEngine for atomic SQLite persistence across restarts.
"""

import datetime
from typing import Dict, Optional, List, Any
from agent_registry.status_manager import AgentStatus, StatusManager

class IdentityStore:
    """
    Persistent store for registered AI agent profiles with SQLite backing.
    """

    def __init__(self, db_path: str = "agenttrust_persistent.db"):
        self.db_path = db_path
        self._agents: Dict[str, Dict[str, Any]] = {}
        
        try:
            from fabric.persistent_db import PersistentStorageEngine
            self.storage = PersistentStorageEngine(db_path)
            stored_agents = self.storage.list_agents()
            for a in stored_agents:
                self._agents[a["agent_id"]] = a
        except Exception:
            self.storage = None

    def save_agent(self, agent_record: Dict[str, Any]) -> None:
        """Saves or updates an agent record in-memory and SQLite."""
        agent_id = agent_record["agent_id"]
        self._agents[agent_id] = agent_record
        if self.storage:
            try:
                self.storage.save_agent(agent_record)
            except Exception:
                pass

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves agent record by ID."""
        if agent_id not in self._agents and self.storage:
            db_rec = self.storage.get_agent(agent_id)
            if db_rec:
                self._agents[agent_id] = db_rec
        return self._agents.get(agent_id)

    def list_agents(self) -> List[Dict[str, Any]]:
        """Returns all registered agent records."""
        return list(self._agents.values())

    def update_status(self, agent_id: str, new_status: AgentStatus, reason: str = "") -> bool:
        """Updates status of an agent following formal transition constraints."""
        agent = self.get_agent(agent_id)
        if not agent:
            return False

        try:
            curr_status = AgentStatus(agent.get("status", "ACTIVE"))
        except Exception:
            curr_status = AgentStatus.ACTIVE

        if not StatusManager.can_transition(curr_status, new_status):
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
