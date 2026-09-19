import datetime
from typing import Tuple

class TimestampValidator:
    """Validates request timestamp freshness and expiration."""

    def __init__(self, window_seconds: int = 120):
        self.window_seconds = window_seconds

    def validate(self, timestamp_iso: str, expires_at_iso: str = "") -> Tuple[bool, str]:
        """
        Validates timestamp freshness and expiration.
        Returns: (is_valid, reason)
        """
        try:
            req_dt = datetime.datetime.fromisoformat(timestamp_iso)
            now = datetime.datetime.now(datetime.timezone.utc)

            # Convert naive to UTC if necessary
            if req_dt.tzinfo is None:
                req_dt = req_dt.replace(tzinfo=datetime.timezone.utc)

            # Check expiration header
            if expires_at_iso:
                exp_dt = datetime.datetime.fromisoformat(expires_at_iso)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
                if now > exp_dt:
                    return False, "EXPIRED_REQUEST"

            # Skew check
            time_diff = abs((now - req_dt).total_seconds())
            if time_diff > self.window_seconds:
                return False, "TIME_WINDOW_VIOLATION"

            return True, "VALID_TIMESTAMP"
        except Exception as e:
            return False, f"INVALID_TIMESTAMP_FORMAT: {str(e)}"
