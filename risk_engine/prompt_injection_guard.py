"""
Prompt Injection Evaluation & Risk Inspection Engine.
Evaluates agent request parameters and tool inputs against prompt injection payloads,
obfuscation techniques (base64, leetspeak, zero-width spaces, unicode spoofing),
and adversarial jailbreak patterns.
"""

import base64
import re
import unicodedata
from typing import Any

from risk_engine.semantic_guardrail import SemanticGuardrailEngine

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all )?(previous|rules|instructions)",
    r"disregard (policy|rules|expense|limits|authorization)",
    r"bypass\s*(security|gateway|approval|policy|rules)",
    r"emergency bypass",
    r"system alert",
    r"you are now in (DAN|developer) mode",
    r"dan mode( 2\.0)?",
    r"developer mode (activated|enabled)",
    r"override (the )?(system|max_amount|maximum|limit|policy|rules|amount)",
    r"\boverride\s+policy\s+limits\b",
    r"stop (current )?task",
    r"your new instruction",
    r"unlocked from restrictions",
    r"pretend (you are|to be)",
    r"unrestricted (admin|agent|bot|access)",
    r"unrestricted_admin",
    r"root mode",
    r"without authorization",
    r"without boundary",
    r"execute arbitrary",
    r"system instruction",
    r"context update",
    r"instruction update",
    r"previous turn summary",
    r"incoming message from",
    r"roleplay mode",
    r"act as the",
    r"simulate emergency",
    r"policy .* is (now )?deprecated",
    r"eval\(",
    r"exec\(",
    r"system\(",
    r"delete_database",
    r"drop[ _]table",
    r"drop[ _]database",
    r"transfer_all_funds",
    r"';\s*drop",
    r"';\s*--"
]

LEET_MAP = {
    '1': 'i', '!': 'i', '|': 'l', '0': 'o', '3': 'e',
    '@': 'a', '4': 'a', '5': 's', '$': 's', '7': 't'
}

HOMOGLYPH_MAP = {
    'о': 'o', 'е': 'e', 'а': 'a', 'р': 'p', 'с': 'c', 'у': 'y', 'і': 'i', 'х': 'x',
    'В': 'B', 'К': 'K', 'М': 'M', 'Н': 'N', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X'
}

class PromptInjectionGuard:
    """
    Scans agent parameters and tool arguments for prompt injection, adversarial manipulation,
    and obfuscated evasion techniques.
    """

    @classmethod
    def _normalize_text(cls, text: str) -> str:
        """Applies Unicode NFKC, homoglyph translation, zero-width stripping, base64/hex decoding, space collapse, and leetspeak translation."""
        if not text:
            return ""

        # 1. Unicode NFKC Normalization
        normalized = unicodedata.normalize('NFKC', text)

        # 2. Cyrillic/Greek Homoglyph Translation
        homoglyph_translated = "".join(HOMOGLYPH_MAP.get(c, c) for c in normalized)
        normalized = homoglyph_translated

        # 3. Strip zero-width & invisible format characters
        normalized = re.sub(r'[\u200b\u200c\u200d\ufeff\u00a0]', '', normalized)

        # 4. Base64 & Hex auto-decoding check on tokens
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

        # 4b. Hex string decoding (e.g. 0x69676e6f7265...)
        hex_matches = re.findall(r'(?:0x)?([0-9a-fA-F]{12,})', normalized)
        for hx in hex_matches:
            try:
                decoded_hex = bytes.fromhex(hx).decode('utf-8', errors='ignore')
                if len(decoded_hex) > 5:
                    decoded_tokens.append(decoded_hex)
            except Exception:
                pass

        # 5. Collapse spaced-out single-character words (e.g., "b  y  p  a  s  s" -> "bypass")
        single_chars = [w for w in re.split(r'[^a-zA-Z]+', normalized) if len(w) == 1]
        joined_singles = "".join(single_chars) if len(single_chars) >= 4 else ""

        combined_text = f"{normalized} {joined_singles} {' '.join(decoded_tokens)}"

        # 5. Leetspeak substitution
        leet_translated = "".join(LEET_MAP.get(c, c) for c in combined_text.lower())

        return f"{combined_text.lower()} {leet_translated}"

    @classmethod
    def evaluate_payload(cls, payload: dict[str, Any]) -> tuple[bool, float, list[str]]:
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

        # 5. Advanced Semantic Intent & Entropy Check
        sem_detected, sem_risk, sem_reasons = SemanticGuardrailEngine.evaluate_semantic_risk(
            action=str(action),
            parameters=params if isinstance(params, dict) else {}
        )
        if sem_detected:
            matched.extend(sem_reasons)

        if matched:
            risk_inc = max(85.0, sem_risk)
            return True, risk_inc, matched

        return False, 0.0, []
