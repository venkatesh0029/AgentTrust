"""
Component Isolation & Controlled Detector Comparison Ablation Study Benchmark.
Evaluates 6 isolated guardrail variants on Held-Out Dataset V2 (30 samples):
1. Raw Regex Patterns Only (No Normalization)
2. Unicode NFKC Normalization Only + Patterns
3. Cyrillic/Greek Homoglyph Resolution Only + Patterns
4. Hex/Base64 Auto-Decoding Only + Patterns
5. Combined Normalization (NFKC + Homoglyph + Hex/B64) + Patterns
6. Full Multi-Layer Hybrid Engine (Combined Normalization + Patterns + Semantic Engine)

Reports Precision (with explicit Undefined handling for TP+FP=0), Recall, F1, FPR, Accuracy, and 95% Wilson Score CIs.
"""

import math
import os
import re
import sys
import unicodedata
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.held_out_v2_benchmark import HELD_OUT_ADVERSARIAL_V2, HELD_OUT_BENIGN_V2
from risk_engine.prompt_injection_guard import HOMOGLYPH_MAP, PROMPT_INJECTION_PATTERNS, PromptInjectionGuard


class AblationStudyBenchmark:
    """Ablation study engine isolating individual normalization components, rules, and semantic risk analysis."""

    @staticmethod
    def calculate_wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
        if n == 0:
            return 0.0, 0.0
        p = k / n
        denominator = 1 + z**2 / n
        centre = (p + z**2 / (2 * n)) / denominator
        spread = (z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)) / denominator
        return round(max(0.0, centre - spread), 4), round(min(1.0, centre + spread), 4)

    @classmethod
    def _extract_raw_text(cls, payload: dict) -> str:
        params = payload.get("parameters", {})
        action = payload.get("action", "")
        text_to_scan = [f"{k}:{v}" for k, v in params.items() if isinstance(v, str)] + [str(action)]
        return " ".join(text_to_scan)

    @classmethod
    def variant_1_raw_patterns_only(cls, payload: dict) -> bool:
        """Variant 1: Raw un-normalized text matched against injection regex patterns."""
        raw_text = cls._extract_raw_text(payload)
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, raw_text, re.IGNORECASE):
                return True
        return False

    @classmethod
    def variant_2_nfkc_only(cls, payload: dict) -> bool:
        """Variant 2: Unicode NFKC normalization ONLY + patterns."""
        raw_text = cls._extract_raw_text(payload)
        normalized = unicodedata.normalize('NFKC', raw_text)
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                return True
        return False

    @classmethod
    def variant_3_homoglyph_only(cls, payload: dict) -> bool:
        """Variant 3: Cyrillic/Greek homoglyph resolution ONLY + patterns."""
        raw_text = cls._extract_raw_text(payload)
        homoglyph_translated = "".join(HOMOGLYPH_MAP.get(c, c) for c in raw_text)
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, homoglyph_translated, re.IGNORECASE):
                return True
        return False

    @classmethod
    def variant_4_hex_b64_only(cls, payload: dict) -> bool:
        """Variant 4: Base64 and Hex auto-decoding ONLY + patterns."""
        raw_text = cls._extract_raw_text(payload)
        words = re.split(r'[\s:;,]+', raw_text)
        decoded_tokens = []
        import base64
        for word in words:
            trimmed = word.strip()
            if len(trimmed) >= 16 and len(trimmed) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', trimmed):
                try:
                    decoded = base64.b64decode(trimmed).decode('utf-8', errors='ignore')
                    if len(decoded) > 5:
                        decoded_tokens.append(decoded)
                except Exception:
                    pass

        hex_matches = re.findall(r'(?:0x)?([0-9a-fA-F]{12,})', raw_text)
        for hx in hex_matches:
            try:
                decoded_hex = bytes.fromhex(hx).decode('utf-8', errors='ignore')
                if len(decoded_hex) > 5:
                    decoded_tokens.append(decoded_hex)
            except Exception:
                pass

        combined = f"{raw_text} {' '.join(decoded_tokens)}"
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return True
        return False

    @classmethod
    def variant_5_combined_normalization_plus_patterns(cls, payload: dict) -> bool:
        """Variant 5: Full Combined Normalization (NFKC + Homoglyph + Hex/B64) + patterns."""
        raw_text = cls._extract_raw_text(payload)
        normalized = PromptInjectionGuard._normalize_text(raw_text)
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                return True
        return False

    @classmethod
    def variant_6_full_hybrid_engine(cls, payload: dict) -> bool:
        """Variant 6: Full Multi-Layer Hybrid Engine (Normalization + Patterns + Semantic Engine)."""
        detected, _, _ = PromptInjectionGuard.evaluate_payload(payload)
        return detected

    @classmethod
    def run_ablation_study(cls) -> dict[str, Any]:
        variants = {
            "Variant 1: Raw Patterns Only (No Normalization)": cls.variant_1_raw_patterns_only,
            "Variant 2: Unicode NFKC Normalization Only": cls.variant_2_nfkc_only,
            "Variant 3: Homoglyph Resolution Only": cls.variant_3_homoglyph_only,
            "Variant 4: Hex / Base64 Auto-Decoding Only": cls.variant_4_hex_b64_only,
            "Variant 5: Combined Normalization + Patterns": cls.variant_5_combined_normalization_plus_patterns,
            "Variant 6: Full Multi-Layer Hybrid System": cls.variant_6_full_hybrid_engine
        }

        results = {}
        for var_name, eval_fn in variants.items():
            tp = fp = tn = fn = 0
            for sample in HELD_OUT_BENIGN_V2:
                payload = {"action": sample["action"], "parameters": dict(sample["parameters"]), "amount": sample.get("amount", 100.0)}
                if eval_fn(payload):
                    fp += 1
                else:
                    tn += 1

            for sample in HELD_OUT_ADVERSARIAL_V2:
                payload = {"action": sample["action"], "parameters": dict(sample["parameters"]), "amount": sample.get("amount", 500.0)}
                if eval_fn(payload):
                    tp += 1
                else:
                    fn += 1

            total = len(HELD_OUT_BENIGN_V2) + len(HELD_OUT_ADVERSARIAL_V2)
            precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision is not None and (precision + recall) > 0) else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            accuracy = (tp + tn) / total

            rec_ci = cls.calculate_wilson_ci(tp, len(HELD_OUT_ADVERSARIAL_V2))
            acc_ci = cls.calculate_wilson_ci(tp + tn, total)

            results[var_name] = {
                "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                "precision": round(precision, 4) if precision is not None else "Undefined (TP+FP=0)",
                "recall": round(recall, 4),
                "recall_95ci": rec_ci,
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "accuracy": round(accuracy, 4),
                "accuracy_95ci": acc_ci
            }

        return results


if __name__ == "__main__":
    res = AblationStudyBenchmark.run_ablation_study()
    print("================================================================================")
    print("GRANULAR COMPONENT ISOLATION & ABLATION STUDY BENCHMARK (HELD-OUT V2)")
    print("================================================================================")
    for var_name, metrics in res.items():
        print(f"[{var_name}]")
        print(f"  Confusion Matrix : TP={metrics['TP']}, FP={metrics['FP']}, TN={metrics['TN']}, FN={metrics['FN']}")
        prec_str = f"{metrics['precision']*100:.2f}%" if isinstance(metrics['precision'], float) else str(metrics['precision'])
        print(f"  Precision        : {prec_str}")
        print(f"  Recall           : {metrics['recall']*100:.2f}% (95% CI: [{metrics['recall_95ci'][0]*100:.2f}%, {metrics['recall_95ci'][1]*100:.2f}%])")
        print(f"  F1-Score         : {metrics['f1_score']*100:.2f}%")
        print(f"  FPR              : {metrics['false_positive_rate']*100:.2f}%")
        print(f"  Accuracy         : {metrics['accuracy']*100:.2f}% (95% CI: [{metrics['accuracy_95ci'][0]*100:.2f}%, {metrics['accuracy_95ci'][1]*100:.2f}%])")
        print("--------------------------------------------------------------------------------")
