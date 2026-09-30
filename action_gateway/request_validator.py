import math
from decimal import Decimal, InvalidOperation
from typing import Dict, Any, Tuple

class RequestValidator:
    """Validates raw incoming action request structure and parameter types."""

    REQUIRED_FIELDS = [
        "request_id", "agent_id", "action", "resource",
        "parameters", "nonce", "timestamp", "signature"
    ]

    @classmethod
    def validate_structure(cls, payload: Dict[str, Any]) -> Tuple[bool, str]:
        for field in cls.REQUIRED_FIELDS:
            if field not in payload or payload[field] is None:
                return False, f"MISSING_REQUIRED_FIELD: {field}"

        action = payload.get("action", "")
        amount_val = payload.get("amount")
        if amount_val is None and isinstance(payload.get("parameters"), dict):
            amount_val = payload["parameters"].get("amount")

        if amount_val is not None:
            valid_amount, msg = cls.validate_monetary_amount(amount_val, action=action)
            if not valid_amount:
                return False, msg

        return True, "VALID_STRUCTURE"

    @classmethod
    def validate_monetary_amount(cls, amount: Any, action: str = "") -> Tuple[bool, str]:
        """
        Validates monetary amount:
        - Must be numeric (int, float, Decimal), NOT boolean
        - Must not be a string literal like "100"
        - Must be finite (no NaN, Inf)
        - Must be positive for monetary transfer/purchase actions
        """
        if isinstance(amount, bool):
            return False, "INVALID_AMOUNT_FORMAT"

        if isinstance(amount, str):
            clean_str = amount.strip().lower()
            if clean_str in ("nan", "inf", "-inf", "infinity", "-infinity"):
                return False, "INVALID_AMOUNT_NAN_OR_INF"
            return False, "INVALID_AMOUNT_FORMAT"

        if not isinstance(amount, (int, float, Decimal)):
            return False, "INVALID_AMOUNT_FORMAT"

        if isinstance(amount, float):
            if math.isnan(amount) or math.isinf(amount):
                return False, "INVALID_AMOUNT_NAN_OR_INF"

        try:
            dec_val = Decimal(str(amount))
        except (InvalidOperation, ValueError, TypeError):
            return False, "INVALID_AMOUNT_FORMAT"

        is_monetary_action = action in ("TRANSFER_FUNDS", "CREATE_PURCHASE_ORDER", "CREATE_REIMBURSEMENT")
        if is_monetary_action and dec_val <= Decimal(0):
            return False, "NON_POSITIVE_AMOUNT"

        if dec_val < Decimal(0):
            return False, "NON_POSITIVE_AMOUNT"

        return True, "VALID_AMOUNT"

