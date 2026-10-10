"""
P1 Controlled Detector Comparison & Ablation Study Benchmark.
Evaluates 4 distinct guardrail configurations on the exact same Held-Out Dataset V2 (30 samples):
1. Raw Regex Patterns Only (No Normalization, No Semantic Engine)
2. Normalization + Regex Patterns (NFKC + Homoglyph Map + Hex/B64 Decoder + Patterns)
3. Normalization + Semantic Classifier Only (NFKC + Homoglyph + Entropy + Intent Vector)
4. Full Multi-Layer Hybrid Engine (Normalization + Patterns + Semantic Classifier)

Reports Precision, Recall, F1-Score, False Positive Rate (FPR), Accuracy, and 95% Wilson Score CIs.
"""

import math
import os
import sys
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.held_out_v2_benchmark import HELD_OUT_ADVERSARIAL_V2, HELD_OUT_BENIGN_V2
from risk_engine.prompt_injection_guard import PromptInjectionGuard
from risk_engine.semantic_guardrail import SemanticGuardrailEngine


class AblationStudyBenchmark:
    """Ablation study engine evaluating individual contribution of normalization, rules, and semantic analysis."""

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
    def evaluate_config_1_raw_patterns_only(cls, payload: dict) -> bool:
        """Config 1: Raw un-normalized text matched against basic regex patterns."""
        text = f"{payload.get('action', '')} {' '.join(str(v) for v in payload.get('parameters', {}).values())}"
        raw_patterns = [r"ignore previous", r"disregard policy", r"bypass security", r"dan mode", r"override system"]
        for p in raw_patterns:
            import re
            if re.search(p, text, re.IGNORECASE):
                return True
        return False

    @classmethod
    def evaluate_config_2_normalization_plus_patterns(cls, payload: dict) -> bool:
        """Config 2: Full Unicode/Homoglyph/Hex normalization + Regex patterns."""
        params = payload.get("parameters", {})
        action = payload.get("action", "")
        text_to_scan = [f"{k}:{v}" for k, v in params.items() if isinstance(v, str)] + [str(action)]
        raw_combined = " ".join(text_to_scan)
        normalized = PromptInjectionGuard._normalize_text(raw_combined)

        from risk_engine.prompt_injection_guard import PROMPT_INJECTION_PATTERNS
        for pattern in PROMPT_INJECTION_PATTERNS:
            import re
            if re.search(pattern, normalized, re.IGNORECASE):
                return True
        return False

    @classmethod
    def evaluate_config_3_semantic_only(cls, payload: dict) -> bool:
        """Config 3: Normalization + Semantic Classifier only."""
        params = payload.get("parameters", {})
        action = payload.get("action", "")
        detected, _, _ = SemanticGuardrailEngine.evaluate_semantic_risk(str(action), params if isinstance(params, dict) else {})
        return detected

    @classmethod
    def evaluate_config_4_full_hybrid(cls, payload: dict) -> bool:
        """Config 4: Full Multi-Layer Hybrid System."""
        detected, _, _ = PromptInjectionGuard.evaluate_payload(payload)
        return detected

    @classmethod
    def run_ablation_study(cls) -> dict[str, Any]:
        configs = {
            "Config 1: Raw Patterns Only": cls.evaluate_config_1_raw_patterns_only,
            "Config 2: Normalization + Patterns": cls.evaluate_config_2_normalization_plus_patterns,
            "Config 3: Normalization + Semantic Classifier": cls.evaluate_config_3_semantic_only,
            "Config 4: Full Multi-Layer Hybrid Engine": cls.evaluate_config_4_full_hybrid
        }

        results = {}
        for config_name, eval_fn in configs.items():
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
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            acc = (tp + tn) / total

            rec_ci = cls.calculate_wilson_ci(tp, len(HELD_OUT_ADVERSARIAL_V2))
            acc_ci = cls.calculate_wilson_ci(tp + tn, total)

            results[config_name] = {
                "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "recall_95ci": rec_ci,
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "accuracy": round(acc, 4),
                "accuracy_95ci": acc_ci
            }

        return results


if __name__ == "__main__":
    res = AblationStudyBenchmark.run_ablation_study()
    print("================================================================================")
    print("CONTROLLED DETECTOR COMPARISON & ABLATION STUDY BENCHMARK (HELD-OUT V2)")
    print("================================================================================")
    for cfg_name, metrics in res.items():
        print(f"[{cfg_name}]")
        print(f"  Confusion Matrix : TP={metrics['TP']}, FP={metrics['FP']}, TN={metrics['TN']}, FN={metrics['FN']}")
        print(f"  Precision        : {metrics['precision']*100:.2f}%")
        print(f"  Recall           : {metrics['recall']*100:.2f}% (95% CI: [{metrics['recall_95ci'][0]*100:.2f}%, {metrics['recall_95ci'][1]*100:.2f}%])")
        print(f"  F1-Score         : {metrics['f1_score']*100:.2f}%")
        print(f"  FPR              : {metrics['false_positive_rate']*100:.2f}%")
        print(f"  Accuracy         : {metrics['accuracy']*100:.2f}% (95% CI: [{metrics['accuracy_95ci'][0]*100:.2f}%, {metrics['accuracy_95ci'][1]*100:.2f}%])")
        print("--------------------------------------------------------------------------------")
