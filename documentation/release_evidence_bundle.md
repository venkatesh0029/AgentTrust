# AgentTrust — Release Evidence Bundle (v0.7.0-production-readiness)

## 1. Release Metadata
- **Release Tag**: `v0.7.0-production-readiness`
- **Release Commit**: `d202a55`
- **Repository**: `https://github.com/venkatesh0029/AgentTrust`
- **Release Timestamp**: `2026-10-11T12:33:00Z`
- **Verification Harness**: `verify_all.py`

---

## 2. Verified Baseline Scorecard

| Category | Target / Requirement | Verified Baseline | Verification Command | Status |
|:---|:---|:---|:---|:---|
| **Static Code Hygiene** | Clean Ruff analysis (0 warnings) | 0 errors | `ruff check .` | **PASS** |
| **Strict Type Checking** | Clean Mypy checking across codebase | 0 errors (73 files) | `mypy --ignore-missing-imports ...` | **PASS** |
| **Automated Regression Suite** | 100% passing of runnable tests | **160 passed, 2 skipped** | `pytest -q` | **PASS** |
| **Held-Out V2 Benchmark** | Generalization evaluation (30 samples) | 100% precision, 0% FPR | `python -m benchmarks.held_out_v2_benchmark` | **EVALUATED** |
| **Held-Out V3 Benchmark** | Zero-day adversarial evaluation (30 samples) | 100% precision, 0% FPR (20% recall) | `python -m benchmarks.held_out_v3_benchmark` | **EVALUATED** |

---

## 3. Environment & Runtime Configuration

```ini
[Runtime]
OS_Platform       = Windows 11 Enterprise (Build 10.0.26100) / POSIX Linux compatible
Python_Version    = 3.11.9
Pytest_Version    = 7.4.3
Ruff_Version      = 0.9.9
Mypy_Version      = 1.15.0
SQLite_Mode       = WAL (Write-Ahead Logging) + busy_timeout=15000ms
```

### Core Dependency Manifest
```text
cryptography==42.0.5
pyjwt==2.8.0
pydantic==2.6.4
fastapi==0.110.0
uvicorn==0.28.0
requests==2.31.0
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
ruff==0.9.9
mypy==1.15.0
```

---

## 4. Architectural Guarantees & Bound Assumptions

### Invariant 1: At-Most-Once Downstream Side-Effect Execution
- Under single-host SQLite WAL coordination, multi-process concurrency races resolve with exactly one winning worker.
- Monotonic fencing tokens prevent stale workers from executing downstream side effects against `ProtectedFinanceAPI`.
- Fencing tokens are durably persisted per protected resource across service restarts.

### Invariant 2: Financial Precision & Zero Float Drift
- Currency-specific minor unit scaling enforced fail-closed (`USD`/`EUR`: 2, `JPY`: 0, `BHD`: 3).
- Input amounts with excess fractional precision are rejected before policy evaluation.
- Unregistered currencies (e.g. `currency="XYZ"`) are rejected with `UNSUPPORTED_CURRENCY`.
- Monetary values are maintained as exact integer minor units and canonical decimal strings.

### Invariant 3: Independent Policy Enforcement
- As demonstrated across Held-Out V1, V2, and V3 benchmarks, prompt-injection heuristic detectors exhibit an empirical generalization gap on novel attack vectors.
- The independent cryptographic authorization layer, parameter checking, and spending limit enforcement guarantee that all sensitive actions remain blocked with zero side effects even when injection detection fails.

---

## 5. Known Limitations & Out-of-Scope Assumptions

1. **Distributed Consensus Boundary**: Single-host SQLite WAL coordination provides at-most-once guarantees on a single host. True multi-host deployments require distributed consensus (Raft/etcd) with shared lease managers.
2. **External Infrastructure Verification**: Live Hyperledger Fabric multi-peer endorsement and hardware-backed SoftHSM2 token signing are simulated locally in the default test environment and require external testnet/HSM daemon provisioning for full live-network confirmation.
3. **Independent Security Validation**: Automated verification harnesses (`verify_all.py`) establish deterministic local reproducibility. Independent security validation requires external human review and third-party environment execution as specified in `documentation/adversarial_review_guide.md`.
