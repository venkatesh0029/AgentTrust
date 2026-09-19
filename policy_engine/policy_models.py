import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field

class PolicyDecision(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
    ALLOWED_AFTER_APPROVAL = "ALLOWED_AFTER_APPROVAL"

class DecisionReason(str, Enum):
    WITHIN_AUTHORITY_LIMIT = "WITHIN_AUTHORITY_LIMIT"
    AUTHORITY_LIMIT_EXCEEDED = "AUTHORITY_LIMIT_EXCEEDED"
    HIGH_VALUE_TRANSACTION = "HIGH_VALUE_TRANSACTION"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    CERTIFICATE_REVOKED = "CERTIFICATE_REVOKED"
    AGENT_SUSPENDED = "AGENT_SUSPENDED"
    AGENT_EXPIRED = "AGENT_EXPIRED"
    ACTION_NOT_PERMITTED = "ACTION_NOT_PERMITTED"
    RESOURCE_NOT_PERMITTED = "RESOURCE_NOT_PERMITTED"
    TIME_WINDOW_VIOLATION = "TIME_WINDOW_VIOLATION"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    EXPIRED_REQUEST = "EXPIRED_REQUEST"
    POLICY_NOT_FOUND = "POLICY_NOT_FOUND"
    EVIDENCE_INTEGRITY_FAILED = "EVIDENCE_INTEGRITY_FAILED"
    DIRECT_ACCESS_DENIED = "DIRECT_ACCESS_DENIED"
    POLICY_CONFLICT_DENIAL = "POLICY_CONFLICT_DENIAL"

class WorkingHours(BaseModel):
    start: str = "09:00"  # HH:MM 24h format
    end: str = "18:00"    # HH:MM 24h format

class PolicyHistoryEntry(BaseModel):
    version: str
    maximum_amount: float
    human_approval_above: float
    allowed_actions: List[str]
    allowed_resource: str
    changed_at: str
    change_author: str = "POLICY_ADMIN"
    change_reason: str = "Policy Creation / Update"

class PolicyRecord(BaseModel):
    policy_id: str
    agent_id: str
    allowed_actions: List[str]
    allowed_resource: str
    maximum_amount: float
    human_approval_above: float
    working_hours: WorkingHours = Field(default_factory=WorkingHours)
    version: str = "1.0"
    status: str = "ACTIVE"
    effective_from: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    effective_until: Optional[str] = None
    change_author: str = "POLICY_ADMIN"
    change_reason: str = "Initial Policy Setup"
    version_history: List[PolicyHistoryEntry] = Field(default_factory=list)
