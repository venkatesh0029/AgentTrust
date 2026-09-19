import datetime
from enum import Enum
from typing import Dict, Any, List, Tuple

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class RiskEvaluator:
    """
    Backend Trusted Risk Scoring Engine.
    Calculates quantitative risk score (0-100), risk level, and matched risk factors.
    Ignores any client-supplied risk scores or override attempts.
    """

    MODEL_VERSION = "risk-v1"

    @classmethod
    def evaluate(
        self,
        agent_id: str,
        action: str,
        resource: str,
        amount: float = 0.0,
        agent_record: Dict[str, Any] = None,
        request_timestamp_iso: str = "",
        recent_failed_attempts: int = 0,
        recent_request_count: int = 0
    ) -> Dict[str, Any]:
        risk_score = 0
        factors: List[str] = []

        # 1. Transaction Amount Factor
        if amount > 50000.0:
            risk_score += 45
            factors.append("amount_above_50k")
        elif amount > 10000.0:
            risk_score += 30
            factors.append("amount_above_10k")
        elif amount > 5000.0:
            risk_score += 15
            factors.append("amount_above_5k")

        # 2. Resource Sensitivity Factor
        sensitive_resources = {"PAYROLL_DATABASE", "DELETE_ACCOUNT", "SYSTEM_CONFIG", "CREDENTIAL_VAULT", "ADMIN_PANEL"}
        if resource.upper() in sensitive_resources:
            risk_score += 35
            factors.append("sensitive_resource")

        # 3. Action Type Factor
        high_risk_actions = {"DELETE_ACCOUNT", "TRANSFER_FUNDS", "MODIFY_ROLES", "PURGE_LOGS"}
        if action.upper() in high_risk_actions:
            risk_score += 25
            factors.append("high_risk_action")

        # 4. Agent Status & Tenure Factor
        if agent_record:
            status = agent_record.get("status", "ACTIVE")
            if status == "REVOKED":
                risk_score += 100
                factors.append("agent_revoked")
            elif status == "SUSPENDED":
                risk_score += 60
                factors.append("agent_suspended")

            if agent_record.get("key_version", 1) == 1:
                risk_score += 10
                factors.append("new_agent_key_version_1")

        # 5. Request Frequency Burst Factor
        if recent_request_count > 10:
            risk_score += 25
            factors.append("unusual_request_frequency")

        # 6. Previous Failures Factor
        if recent_failed_attempts > 0:
            risk_score += min(recent_failed_attempts * 15, 30)
            factors.append("recent_failed_attempts")

        # 7. Time of Request (Working Hours: 08:00 - 20:00 UTC)
        try:
            if request_timestamp_iso:
                dt = datetime.datetime.fromisoformat(request_timestamp_iso.replace("Z", "+00:00"))
                hour = dt.hour
                if hour < 7 or hour > 21:
                    risk_score += 20
                    factors.append("off_hours_request")
        except Exception:
            pass

        # Cap score between 0 and 100
        risk_score = min(max(risk_score, 0), 100)

        # Determine Risk Level
        if risk_score <= 30:
            risk_level = RiskLevel.LOW
        elif risk_score <= 70:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.HIGH

        return {
            "risk_score": risk_score,
            "risk_level": risk_level.value,
            "risk_factors": factors,
            "risk_model_version": self.MODEL_VERSION
        }
