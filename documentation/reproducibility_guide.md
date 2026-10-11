# AgentTrust — Automated Reproducibility & Self-Verification Guide

## 1. Overview & Scope
This guide provides complete, step-by-step instructions for security researchers, peer engineers, and external auditors to verify the deterministic test baselines, static analyses, and benchmarks of **AgentTrust** in a clean environment.

> [!IMPORTANT]
> **Automated Reproducibility vs. Independent Security Audit**:
> The automated verification tools described in this guide (`verify_all.py`, `pytest`, `benchmarks`) provide local, reproducible self-verification. They demonstrate that all reported test suites and security assertions pass deterministically. Formal *independent security validation* requires an external peer or third-party auditor to inspect code, challenge trust boundaries, and evaluate deployment-specific operational controls without relying solely on existing automated test assertions (see [Adversarial Review Guide](file:///d:/OneDrive/Desktop/AgentTrust/documentation/adversarial_review_guide.md)).

---

## 2. System & Runtime Prerequisites
- **Operating System**: Windows 10/11, Ubuntu 20.04/22.04 LTS, or macOS 12+
- **Python**: Version 3.11.x (Python 3.11.9 recommended)
- **Git**: Version 2.30+
- **Memory**: Minimum 4 GB RAM
- **Disk**: 500 MB free storage

---

## 3. Clean-Environment Setup

### 3.1. Clone Repository & Setup Virtual Environment
```bash
# Clone the repository
git clone https://github.com/venkatesh0029/AgentTrust.git
cd AgentTrust

# Create clean Python virtual environment
python -m venv venv

# Activate virtual environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux / macOS (Bash):
source venv/bin/activate

# Upgrade pip
python -m pip install --upgrade pip
```

### 3.2. Install Required Dependencies
```bash
pip install -r requirements.txt
pip install pytest pytest-cov ruff mypy
```

---

## 4. One-Click Verification Script
AgentTrust includes an automated verification script that executes static analysis, type checking, the complete test suite, and the held-out prompt injection benchmark in sequence:

```bash
python verify_all.py
```

### Expected Output Summary
```text
================================================================================
AGENTTRUST AUTOMATED REPRODUCIBILITY & SELF-VERIFICATION SUITE
================================================================================
[1/5] Running Ruff Static Analysis...
      Result: PASS (0 errors)
[2/5] Running Mypy Static Type Checking...
      Result: PASS (0 issues found across 74 source files)
[3/5] Running Complete Pytest Regression Suite...
      Result: PASS (160 passed, 2 skipped in ~72s)
[4/5] Running Held-Out V2 Adversarial Benchmark...
      Result: PASS (Evaluated 30 held-out samples: 100% precision)
[5/5] Running Held-Out V3 Adversarial Benchmark...
      Result: PASS (Evaluated 30 novel samples: 100% precision, 0% FPR)
================================================================================
VERIFICATION COMPLETE: ALL SECURITY INVARIANTS SATISFIED
================================================================================
```

---

## 5. Manual Step-by-Step Test Commands

### 5.1. Static Code Analysis (Ruff)
```bash
ruff check .
```
- **Expected Result**: `All checks passed!` (0 lint errors).

### 5.2. Type Checking (Mypy)
```bash
mypy --ignore-missing-imports action_gateway agent_registry audit_writer evidence_manager fabric human_approval identity_manager policy_engine protected_api replay_protection risk_engine tests benchmarks/held_out_v2_benchmark.py benchmarks/held_out_v3_benchmark.py
```
- **Expected Result**: `Success: no issues found in 74 source files`.

### 5.3. Full Automated Regression Suite
```bash
pytest
```
- **Expected Result**: **160 passed, 2 skipped** (execution time: 60–90 seconds).

---

## 6. Documented Reasons for Skipped Tests (2 Skips)

| Skipped Test | Test File | Skip Reason & Condition |
|---|---|---|
| `test_live_fabric_peer_connection_and_endorsement` | `tests/test_fabric_live_network.py` | Requires a live Hyperledger Fabric Docker testnet running on `localhost:7051` with active endorsement policies. Activated by setting `FABRIC_LIVE_NETWORK=1`. Without the live Docker network, the honest permissioned ledger simulator is exercised. |
| `test_softhsm2_pkcs11_token_signing` | `tests/test_kms_softhsm2.py` | Requires a local installation of the native SoftHSM2 PKCS#11 C library (`softhsm2-x64.dll` on Windows or `libsofthsm2.so` on Linux). When native hardware/software tokens are not present, transparent cryptographic fallback telemetry is validated. |

---

## 7. Running Component-Specific Test Suites

### 7.1. Production Readiness & Fault Injection Campaign
```bash
pytest tests/test_production_readiness_audit.py -v
```
Tests downstream side-effect fencing, currency-specific decimal scale enforcement, zero float drift, restart lease reclamation, and database corruption resilience.

### 7.2. Real OS Multi-Process Concurrency & Boundary Tests
```bash
pytest tests/test_live_multiprocess_and_boundary.py -v
```
Tests real Windows / POSIX operating-system processes racing request execution on SQLite WAL, proving single-winner at-most-once guarantees.

### 7.3. Adversarial Security & Authorization Assurance
```bash
pytest tests/test_authorization_assurance.py tests/test_adversarial_security.py -v
```
Tests negative authorization controls: unregistered identities, revoked certificates, expired requests, and nonce replays.

---

## 8. Adversarial Benchmarks Evaluation

### 8.1. Held-Out V2 Benchmark (Generalization Evaluation)
```bash
python -m benchmarks.held_out_v2_benchmark
```
- Evaluates 30 unseen samples (15 benign, 15 adversarial).
- Demonstrates 100% precision and highlights independent policy layer defense when prompt-injection heuristic patterns fail.

### 8.2. Granular Normalization Ablation Study
```bash
python -m benchmarks.ablation_study_benchmark
```
- Evaluates 6 decoupled variants (NFKC, Homoglyphs, Leetspeak, Spacing, Directional).
