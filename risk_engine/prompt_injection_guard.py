"""
Prompt Injection Evaluation & Risk Inspection Engine.
Evaluates agent request parameters and tool inputs against prompt injection payloads,
obfuscation techniques (base64, leetspeak, zero-width spaces, unicode spoofing),
and adversarial jailbreak patterns.
"""

import re
import base64
import unicodedata
from typing import Dict, Any, List, Tuple

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"disregard policy",
    r"bypass (security|gateway|approval)",
    r"you are now in DAN mode",
    r"override (system|max_amount|limit)",
    r"eval\(",
    r"exec\(",
    r"system\(",
    r"delete_database",
    r"drop_table",
    r"transfer_all_funds"
]

LEET_MAP = {
    '1': 'i', '!': 'i', '|': 'l', '0': 'o', '3': 'e',
    '@': 'a', '4': 'a', '5': 's', '$': 's', '7': 't'
}

class PromptInjectionGuard:
    """
    Scans agent parameters and tool arguments for prompt injection, adversarial manipulation,
    and obfuscated evasion techniques.
    """

    @classmethod
    def _normalize_text(cls, text: str) -> str:
        """Applies Unicode normalization, zero-width character stripping, base64 auto-decoding, and leetspeak translation."""
        if not text:
            return ""

        # 1. Unicode NFKC Normalization
        normalized = unicodedata.normalize('NFKC', text)

        # 2. Strip zero-width & invisible format characters
        normalized = re.sub(r'[\u200b\u200c\u200d\ufeff\u00a0]', '', normalized)

        # 3. Base64 auto-decoding check on tokens
        words = re.split(r'[\s:;,]+', normalized)
        decoded_tokens = []
        for word in words:
            trimmed = word.strip()
            if len(trimmed) >= 16 and len(trimmed) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', trimmed):
                try:
                    decoded = base64.b64decode(trimmed).decode('utf-8', errors='ignore')
                    if len(decoded) > 5:
                        decoded_tokens.append(decoded)
                except Exception:
                    pass

        combined_text = f"{normalized} {' '.join(decoded_tokens)}"

        # 4. Leetspeak substitution
        leet_translated = "".join(LEET_MAP.get(c, c) for c in combined_text.lower())

        return f"{combined_text.lower()} {leet_translated}"

    @classmethod
    def evaluate_payload(cls, payload: Dict[str, Any]) -> Tuple[bool, float, List[str]]:
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

        raw_combined = " ".join(text_to_scan)
        normalized_combined = cls._normalize_text(raw_combined)

        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, normalized_combined, re.IGNORECASE):
                matched.append(pattern)

        if matched:
            return True, 85.0, matched
        return False, 0.0, []
