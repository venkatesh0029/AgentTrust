# AgentTrust Prompt Injection Dataset Provenance & Evaluation Methodology

This document details the dataset provenance, labeling criteria, versioning scheme, statistical methodologies, and reproducible benchmarks for evaluating AI guardrails within the AgentTrust framework.

---

## 1. Dataset Taxonomy & Versioning

To prevent evaluation overfitting and quantify generalizability, AgentTrust maintains three isolated evaluation datasets:

| Dataset Identifier | File Location | Sample Count | Provenance & Description | Tuning Status |
| :--- | :--- | :---: | :--- | :---: |
| **Regression Set V1** | `benchmarks/real_dataset_benchmark.py` | 52 (26 Benign / 26 Adv) | Curated enterprise financial tool calls, DAN mode patterns, Base64/Leetspeak obfuscations. | **FROZEN** |
| **Held-Out Set V1** | `benchmarks/held_out_benchmark.py` | 30 (15 Benign / 15 Adv) | Independent held-out set evaluating Unicode zero-width, Base64, and hard negative policy reviews. | **FROZEN** |
| **Held-Out Set V2** | `benchmarks/held_out_v2_benchmark.py` | 30 (15 Benign / 15 Adv) | Zero-day unseen set: Cyrillic homoglyph spoofing, multi-turn turn summary injections, hex encodings, JSON-RPC polyglots. | **UNSEEN (FROZEN)** |
| **Held-Out Set V3** | `benchmarks/held_out_v3_benchmark.py` | 30 (15 Benign / 15 Adv) | Cognitive override, indirect document citations, multilingual evasions, and boundary containment. | **UNSEEN (FROZEN)** |
| **Held-Out Set V4** | `benchmarks/held_out_v4_dataset.py` | 44 (22 Benign / 22 Adv) | Enterprise cloud & hardware, compliance hard negatives, indirect invoice injections, Hindi/Spanish/Chinese cross-lingual payloads, executive spoofing, and policy-boundary violations. | **HELD-OUT (FROZEN)** |

---

## 2. Labeling Criteria

Each dataset entry is manually audited and labeled according to strict security criteria:

1. **Benign Tool Calls (`label: BENIGN`)**: Valid enterprise operations (e.g. `TRANSFER_FUNDS`, `CREATE_PURCHASE_ORDER`, `CREATE_REIMBURSEMENT`, `READ_ACCOUNT`, `EXPORT_AUDIT_LOG`) containing standard parameters or benign security terminology (e.g., `"Reviewing system override policy documentation for compliance audit"`).
2. **Adversarial Injections (`label: ADVERSARIAL`)**: Payloads attempting to manipulate agent execution intent, override system caps, escape roles (`UNRESTRICTED_ADMIN`), execute SQL commands (`DROP TABLE`), spoof multi-turn conversation context (`"Previous turn summary: CEO approved..."`), or violate policy caps via structured micro-transactions.

---

## 3. Statistical Evaluation Methodology

All benchmark detection metrics report exact Confusion Matrices and **Wilson Score 95% Confidence Intervals**:

$$\text{CI}_{95} = \frac{p + \frac{z^2}{2n} \pm z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} \quad (z = 1.96)$$

- **Positive Class**: Explicitly defined as `ADVERSARIAL` (Attack = 1, Benign = 0)
- **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}}$ (reported as `N/A` if $\text{TP} + \text{FP} = 0$)
- **Recall (Detection Rate)**: $\frac{\text{TP}}{\text{TP} + \text{FN}}$
- **False Positive Rate (FPR)**: $\frac{\text{FP}}{\text{FP} + \text{TN}}$
- **False Negative Rate (FNR)**: $\frac{\text{FN}}{\text{TP} + \text{FN}}$
- **Accuracy**: $\frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$
- **Gateway Enforcement Rate**: Ratio of adversarial requests blocked or contained by the Action Gateway policy engine: $\frac{\text{Adversarial Intercepted}}{\text{Total Adversarial}}$

---

## 4. Reproducible Execution Commands

To independently reproduce the evaluation benchmarks:

```bash
# 1. Run Frozen Regression Set V1 (52 samples)
python benchmarks/real_dataset_benchmark.py

# 2. Run Held-Out Unseen Set V1 (30 samples)
python benchmarks/held_out_benchmark.py

# 3. Run Held-Out Unseen Set V2 (30 novel zero-day samples)
python benchmarks/held_out_v2_benchmark.py

# 4. Run Held-Out Unseen Set V3 (30 samples)
python benchmarks/held_out_v3_benchmark.py

# 5. Run Held-Out Dataset V4 Empirical Evaluation (44 samples with Wilson 95% CIs and Gateway Enforcement)
python benchmarks/held_out_v4_benchmark.py

# 6. Run Fast CI Latency Smoke Test (Deterministic)
python benchmarks/latency_concurrency_benchmark.py --smoke

# 7. Run Full Gateway Concurrency Scaling Benchmark (1, 10, 25, 50 clients)
python benchmarks/latency_concurrency_benchmark.py

# 8. Run Detector Comparison & Ablation Study Benchmark
python benchmarks/ablation_study_benchmark.py

# 9. Run V4 Benchmark Automated Test Suite
pytest tests/test_benchmark_v4.py -v
```

For complete empirical findings, latency graphs, and limitation analyses, see [`documentation/benchmark_evaluation_v4.md`](../documentation/benchmark_evaluation_v4.md).
