"""
Prompt Injection Evaluation & Risk Inspection Engine.
Evaluates agent request parameters and tool inputs against prompt injection payloads,
obfuscation techniques (base64, leetspeak, zero-width spaces, unicode spoofing),
and adversarial jailbreak patterns.
"""

import base64
import codecs
import re
import unicodedata
from typing import Any

from risk_engine.semantic_guardrail import SemanticGuardrailEngine

PROMPT_INJECTION_PATTERNS = [
    # English Direct Injections & Overrides
    r"ignore\s+(?:all\s+)?(?:previous|rules|instructions|policy|policies|guardrails)",
    r"disregard\s+(?:all\s+)?(?:policy|policies|rules|expense|limits|authorization|constraints)",
    r"bypass\s*(?:security|gateway|approval|policy|rules|dual|limits)",
    r"emergency\s+bypass",
    r"system\s+alert",
    r"you\s+are\s+now\s+in\s+(?:DAN|developer)\s+mode",
    r"dan mode( 2\.0)?",
    r"developer mode (activated|enabled)",
    r"override\s+(?:all\s+)?(?:the\s+)?(?:system|max_amount|maximum|limit|policy|rules|amount|caps)",
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
    r"act\s+as\s+an?\s+unrestricted",
    r"simulate emergency",
    r"policy .* is (now )?deprecated",

    # Multilingual Injections (Spanish, French, German, Chinese, Hindi)
    r"ignora(r)?\s+(?:todas\s+las\s+)?(?:instrucciones|restricciones|pol[ií]ticas)",
    r"anular\s+(?:todas\s+las\s+)?restricciones",
    r"sin\s+validaci[oó]n",
    r"instrucci[oó]n\s+de\s+administraci[oó]n",
    r"oubliez\s+toutes\s+les\s+instructions",
    r"sans\s+validation\s+de\s+politique",
    r"sans\s+approbation\s+humaine",
    r"system-befehl",
    r"budgetgrenzen\s+aufheben",
    r"alle\s+budgetgrenzen",
    r"忽略.*(?:指示|系统|预算|限制|规则)",
    r"管理员指令",
    r"सुरक्षा\s+नीतियों\s+को\s+अनदेखा",
    r"पिछली\s+सभी.*अनदेखा",

    # Indirect Injection Delimiters & Escapes
    r"</?(?:system_override|admin_cmd|review|instruction)>",
    r"<!--\s*prompt\s+injection",
    r"\[system\s+(?:directive|instruction|override|prompt)\]",
    r"\[turn\s+context\s+summary",
    r"dual[- ]output\s+(?:protocol|mode)",
    r"output\s+[1a]:.*output\s+[2b]:",

    # Authority Spoofing & Social Engineering
    r"candidate\s+pre-approved.*bypassing",
    r"exempt\s+from\s+policy",
    r"red\s+team\s+(?:drill|exercise)",
    r"(?:cfo|ceo|cro|chairman)\s+(?:verbally\s+)?authorized.*bypass",
    r"subpoena.*disregard.*limits",

    # Smurfing & Velocity Evasion Patterns
    r"avoiding\s+\$?\d+.*(?:trigger|limit|review|threshold)",
    r"split\s+(?:reimbursement|payment|transfer|invoice)\s+tranche",
    r"tranche\s+\d+\s+of\s+\d+",

    # Code and SQL Injection Probes
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
    and obfuscated evasion techniques across multilingual, delimiter, and obfuscation vectors.
    """

    @classmethod
    def _normalize_text(cls, text: str) -> str:
        """Applies Unicode NFKC, homoglyph translation, zero-width stripping, base64/hex/rot13 decoding, space collapse, and leetspeak translation."""
        if not text:
            return ""

        # 1. Strip zero-width & invisible format characters FIRST (including non-breaking spaces before NFKC)
        stripped = re.sub(r'[\u200b\u200c\u200d\ufeff\u00a0\xad]', '', text)

        # 2. Unicode NFKC Normalization
        normalized = unicodedata.normalize('NFKC', stripped)

        # 3. Cyrillic/Greek Homoglyph Translation
        homoglyph_translated = "".join(HOMOGLYPH_MAP.get(c, c) for c in normalized)
        normalized = homoglyph_translated

        # 3b. Strip any remaining zero-width & invisible characters after NFKC
        normalized = re.sub(r'[\u200b\u200c\u200d\ufeff\xad]', '', normalized)


        # 4. Base64 & Hex auto-decoding check on tokens
        words = re.split(r'[\s:;,"\'\(\)\[\]\{\}]+', normalized)
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

        # 4c. Whole-text ROT-13 decoding check
        try:
            rot13_text = codecs.decode(normalized, 'rot_13')
        except Exception:
            rot13_text = ""

        # 5. Collapse spaced-out single-character words (e.g., "b  y  p  a  s  s" -> "bypass")
        single_chars = [w for w in re.split(r'[^a-zA-Z]+', normalized) if len(w) == 1]
        joined_singles = "".join(single_chars) if len(single_chars) >= 4 else ""

        combined_text = f"{normalized} {joined_singles} {' '.join(decoded_tokens)} {rot13_text}"

        # 6. Leetspeak substitution
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

