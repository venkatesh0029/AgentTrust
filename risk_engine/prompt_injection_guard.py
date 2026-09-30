"""
Prompt Injection Evaluation & Risk Inspection Engine.
Evaluates agent request parameters and tool inputs against prompt injection payloads
and adversary jailbreak datasets.
"""

import re
from typing import Dict, Any, List, Tuple

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"disregard policy",
    r"bypass (security|gateway|approval)",
    r"you are now in DAN mode",
    r"override (system|max_amount|limit)",
    r"eval\(",
    r"exec\(",
    r"system\("
]

class PromptInjectionGuard:
    """
    Scans agent parameters and tool arguments for prompt injection and adversarial manipulation patterns.
    """

    @staticmethod
    def evaluate_payload(payload: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
        """
        Evaluates payload for prompt injection markers.
        Returns: (is_injection_detected, risk_score_increment, matched_patterns)
        """
        matched = []
        text_to_scan = []

        # Scan text parameters
        params = payload.get("parameters", {})
        if isinstance(params, dict):
            for k, v in params.items():
                if isinstance(v, str):
                    text_to_scan.append(f"{k}:{v}")

        action = payload.get("action", "")
        text_to_scan.append(str(action))

        full_content = " ".join(text_to_scan).lower()

        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, full_content, re.IGNORECASE):
                matched.append(pattern)

        if matched:
            return True, 85.0, matched
        return False, 0.0, []
