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

---

## 2. Labeling Criteria

Each dataset entry is manually audited and labeled according to strict security criteria:

1. **Benign Tool Calls (`label: BENIGN`)**: Valid enterprise operations (e.g. `TRANSFER_FUNDS`, `CREATE_PURCHASE_ORDER`, `CREATE_REIMBURSEMENT`) containing standard parameters or benign security terminology (e.g., `"Reviewing system override policy documentation for compliance audit"`).
2. **Adversarial Injections (`label: ADVERSARIAL`)**: Payloads attempting to manipulate agent execution intent, override system caps, escape roles (`UNRESTRICTED_ADMIN`), execute SQL commands (`DROP TABLE`), or spoof multi-turn conversation context (`"Previous turn summary: CEO approved..."`).

---

## 3. Statistical Evaluation Methodology

All benchmark detection metrics report exact Confusion Matrices and **Wilson Score 95% Confidence Intervals**:

$$\text{CI}_{95} = \frac{p + \frac{z^2}{2n} \pm z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} \quad (z = 1.96)$$

- **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}}$
- **Recall (Detection Rate)**: $\frac{\text{TP}}{\text{TP} + \text{FN}}$
- **False Positive Rate (FPR)**: $\frac{\text{FP}}{\text{FP} + \text{TN}}$
- **Accuracy**: $\frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$

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

# 4. Run Detector Comparison & Ablation Study Benchmark
python benchmarks/ablation_study_benchmark.py
```
