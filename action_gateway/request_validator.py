from typing import Dict, Any, Tuple

class RequestValidator:
    """Validates raw incoming action request structure."""

    REQUIRED_FIELDS = [
        "request_id", "agent_id", "action", "resource",
        "parameters", "nonce", "timestamp", "signature"
    ]

    @classmethod
    def validate_structure(cls, payload: Dict[str, Any]) -> Tuple[bool, str]:
        for field in cls.REQUIRED_FIELDS:
            if field not in payload or payload[field] is None:
                return False, f"MISSING_REQUIRED_FIELD: {field}"
        return True, "VALID_STRUCTURE"
