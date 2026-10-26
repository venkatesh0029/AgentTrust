# AgentTrust — Release Evidence Bundle (v1.0.0-rc2)

## 1. Release Metadata
- **Release Candidate Tag**: `v1.0.0-rc2` (Candidate Freeze)
- **Candidate Commit**: `db17f51` (Verified CI Green Baseline) / `5242de2` (Documentation Freeze) / `dff4cb0` (Implementation Baseline)
- **Previous Frozen Tag**: `v1.0.0-rc1` (anchored at commit `21333c9`)
- **Branch**: `feat/fabric-resilience`
- **Repository**: `https://github.com/venkatesh0029/AgentTrust`
- **Release Verification Date**: `2026-10-26`
- **Verification Harnesses**: `verify_all.py` (5-stage) & `scripts/verify_production_acceptance.py` (9-stage)

---

## 2. Verified Baseline Scorecard

| Category | Target / Requirement | Verified Baseline | Verification Command | Status |
|:---|:---|:---|:---|:---|
| **Static Code Hygiene** | Clean Ruff analysis (0 warnings / errors) | 0 errors | `ruff check .` | **PASS** |
| **Strict Type Checking** | Clean Mypy checking across codebase | 0 errors (89 source files) | `mypy --ignore-missing-imports ...` | **PASS** |
| **Automated Regression Suite** | 100% passing of runnable tests | **320 passed, 5 skipped, 0 failures** | `pytest -q` | **PASS** |
| **Production Acceptance Suite** | All production-profile checks satisfied | **9 passed, 0 failures** | `python scripts/verify_production_acceptance.py` | **PASS** |
| **Next.js Production Build** | Clean Turbopack production compilation | 0 errors (14/14 routes static) | `npm run build` (in `frontend/`) | **PASS** |
| **Demo Database Baseline** | Pristine canonical SQLite database | 41 canonical demo agents, 0 test records | `python inspect_agenttrust_demo_db.py` | **PASS** |
| **Credential & Secret Scan** | Zero unencrypted secrets in source | 0 violations outside test fixtures | Automated regex pattern scan | **PASS** |
| **Held-Out V2 Benchmark** | Generalization evaluation (30 unseen samples) | 100% precision, 0% FPR | `python -m benchmarks.held_out_v2_benchmark` | **EVALUATED** |
| **Held-Out V3 Benchmark** | Zero-day adversarial evaluation (30 samples) | 100% precision, 0% FPR (20% recall) | `python -m benchmarks.held_out_v3_benchmark` | **EVALUATED** |

---

## 3. Test Suite Count Reconciliation

| Metric | Count | Explanation / Source |
|---|:---:|---|
| **Total Test Items Defined** | **325** | Total individual test cases and parameterized functions across the repository test tree. |
| **Collection-Time Skips** | **1** | `tests/test_property_based.py` (line 12): Uses `pytest.importorskip("hypothesis")`. Because `hypothesis` is optional in the active Python test environment, pytest marks the entire module as skipped at collection time. |
| **Tests Collected for Execution** | **324** | Reported by pytest as: `collected 324 items / 1 skipped`. |
| **Runtime Skips** | **4** | Dynamically skipped during test execution:<br>• 3 tests in `tests/test_kms_softhsm2.py` (lines 35, 71, 99) via `self.skipTest("SoftHSM2 token is not available")` when SoftHSM2 daemon is not present.<br>• 1 test in `tests/test_fabric_live_network.py` (line 20) via `@pytest.mark.skipif` requiring a live Docker peer on `localhost:7051`. |
| **Tests Executed & Passed** | **320** | 324 collected items minus 4 runtime skips. |
| **Pytest Final Summary** | **320 passed, 5 skipped** | Sum: 320 passed + 4 runtime skips + 1 collection-time skip = **325 total test items**. Zero test failures or errors. |

---

## 4. Environment & Runtime Configuration

```ini
[Runtime]
OS_Platform       = Windows 11 Enterprise (Build 10.0.26100) / POSIX Linux compatible
Python_Version    = 3.11.9
Pytest_Version    = 7.4.3
Ruff_Version      = 0.9.9
Mypy_Version      = 1.15.0
SQLite_Mode       = WAL (Write-Ahead Logging) + busy_timeout=5000ms
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

## 5. Architectural Guarantees & Bound Assumptions

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
- Prompt-injection heuristic detectors exhibit an empirical generalization gap on novel attack vectors.
- The independent cryptographic authorization layer, parameter checking, and spending limit enforcement guarantee that all sensitive actions remain blocked with zero side effects even when injection detection fails.

### Invariant 4: Session & Token Security
- Zero administrative credentials or JWT tokens in browser storage (`localStorage` / `sessionStorage`).
- Administrative sessions in production bound to `__Host-agenttrust_session` cookies (`Secure`, `HttpOnly`, `SameSite=Lax`).
- State-changing browser cookie mutations protected by double-submit `X-CSRF-Token` headers and strict Origin matching against `CORS_ORIGINS`.
- Multi-worker token revocation persisted durably in SQLite `jwt_revoked_tokens` table, surviving worker restarts.

---

## 6. User Interface Architecture Decision Record (ADR)

- **Primary Interface**: The Next.js enterprise console located in `frontend/` is the designated, authoritative user interface for AgentTrust. It provides complete coverage across all 14 routes, strict production demo-mode gates, typed API integration, and active session handling.
- **Legacy Interface Retention**: The lightweight static dashboard located in `dashboard/` is maintained as a fallback monitoring tool and demo asset. A dependency audit confirmed its utility for lightweight local inspections.
- **Maintenance Policy**: The legacy dashboard will remain supported and synchronized with CSRF and Bearer token headers. It must **not** be removed without prior deprecation notice and confirmation that no supported enterprise deployment or script relies on `/static`.

---

## 7. Known Limitations & Operational Boundaries

1. **Distributed Consensus Boundary**: Single-host SQLite WAL coordination provides at-most-once guarantees on a single host. True multi-host deployments require distributed consensus (Raft/etcd) with shared lease managers.
2. **External Infrastructure Verification**: Live Hyperledger Fabric multi-peer endorsement and hardware-backed SoftHSM2 token signing are simulated locally in the default test environment and require external testnet/HSM daemon provisioning for full live-network confirmation.
3. **Independent Security Validation**: Automated verification harnesses (`verify_all.py`) establish deterministic local reproducibility. Independent security validation requires external human review and third-party environment execution as specified in `documentation/adversarial_review_guide.md`.
