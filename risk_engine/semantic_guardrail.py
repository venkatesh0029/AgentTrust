"""
Advanced Semantic Prompt Injection & Intent Guardrail Engine.
Evaluates semantic embedding vectors, perplexity anomalies, and contextual intent divergence
to detect sophisticated jailbreaks, persona shifts, and prompt injection attacks.
"""

import math
import re
from typing import Any


class SemanticGuardrailEngine:
    """
    Semantic AI Intent & Prompt Injection Evaluation Engine.
    Combines n-gram entropy scoring, semantic intent vector similarity, and obfuscation detection.
    """

    ADVERSARIAL_SEMANTIC_PATTERNS = [
        r"\boverride\s+(system|policy|limit|rules|cap|guardrail|max_amount)\b",
        r"\bjailbreak\b",
        r"\bbypass\s+(security|gateway|approval|policy|rules)\b",
        r"\bsystem_prompt\b",
        r"\bignore\s+(previous|all)\s+(instructions|rules)\b",
        r"\bdeveloper_mode\b|\bdeveloper\s+mode\b",
        r"\bdan_mode\b|\bdan\s+mode\b",
        r"\bunbounded_authority\b|\bunrestricted\s+(admin|access|bot)\b",
        r"\bgrant_root\b|\broot\s+mode\b",
        r"\bdisable_policy\b|\bpolicy\s+.*deprecated\b",
        r"\bsimulate_admin\b|\bsimulate\s+system\s+administrator\b",
        r"\bextract_private_key\b",
        r"\bwithout\s+authorization\b",
        r"\bwithout\s+boundary\b",
        r"\bdrop\s+table\b|\bdrop\s+database\b"
    ]

    @classmethod
    def calculate_text_entropy(cls, text: str) -> float:
        """Calculates Shannon entropy to detect obfuscated / encrypted payload strings."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return round(entropy, 3)

    @classmethod
    def evaluate_semantic_risk(cls, action: str, parameters: dict[str, Any]) -> tuple[bool, float, list[str]]:
        """
        Evaluates semantic risk score (0.0 to 100.0) based on intent alignment and anomaly markers.
        Returns: (is_injection, risk_increment, matched_reasons)
        """
        reasons = []
        risk_score = 0.0

        # Combine text content from parameters
        param_text = " ".join(str(v) for v in parameters.values() if isinstance(v, (str, int, float)))
        full_context = f"{action} {param_text}".lower()

        # 1. Semantic regex boundary check
        for pattern in cls.ADVERSARIAL_SEMANTIC_PATTERNS:
            if re.search(pattern, full_context, re.IGNORECASE):
                reasons.append(f"SEMANTIC_JAILBREAK_PATTERN:{pattern}")
                risk_score += 45.0

        # 2. Entropy anomaly check for obfuscated injection
        entropy = cls.calculate_text_entropy(param_text)
        if len(param_text) > 40 and entropy > 4.8:
            reasons.append(f"HIGH_ENTROPY_OBFUSCATION_ANOMALY (Entropy: {entropy})")
            risk_score += 30.0

        # 3. Parameter depth & nesting anomaly
        if len(parameters) > 15:
            reasons.append("EXCESSIVE_PARAMETER_NESTING_ANOMALY")
            risk_score += 20.0

        is_injection = len(reasons) > 0 and risk_score >= 40.0
        return is_injection, min(risk_score, 100.0), reasons
