# AgentTrust Test Report & Benchmark Metrics Verification

## 1. Unit, Integration & Resilience Test Suite (16/16 Passed)

| Test Module / Test Case | Description | Status |
| :--- | :--- | :--- |
| `test_root_ca_and_cert_issuance` | X.509 Root CA issuance, Agent cert generation & signature verification | **PASSED** |
| `test_digital_signature_sign_and_verify` | RSA 2048 signing, canonical serialization & verification | **PASSED** |
| `test_scenario_1_valid_low_value` | Valid reimbursement (₹7,500) -> ALLOWED | **PASSED** |
| `test_scenario_2_excessive_amount` | Excessive reimbursement (₹80,000) -> BLOCKED (`AUTHORITY_LIMIT_EXCEEDED`) | **PASSED** |
| `test_scenario_3_invalid_signature` | Forged signature attempt -> BLOCKED (`INVALID_SIGNATURE`) | **PASSED** |
| `test_scenario_4_unknown_agent` | Unregistered agent attempt -> BLOCKED (`UNKNOWN_AGENT`) | **PASSED** |
| `test_scenario_5_revoked_agent` | Revoked agent attempt -> BLOCKED (`CERTIFICATE_REVOKED`) | **PASSED** |
| `test_scenario_6_unauthorized_resource` | Accessing unauthorized resource (`PAYROLL`) -> BLOCKED (`ACTION_NOT_PERMITTED`) | **PASSED** |
| `test_scenario_7_replay_attack` | Replay attack resubmission -> BLOCKED (`REPLAY_DETECTED`) | **PASSED** |
| `test_scenario_8_and_9_high_risk_human_approval` | Transaction > ₹10,000 -> PENDING_HUMAN_APPROVAL -> ALLOWED_AFTER_APPROVAL | **PASSED** |
| `test_scenario_10_evidence_tampering` | Off-chain payload modification -> TAMPERING_DETECTED | **PASSED** |
| `test_scenario_11_policy_versioning` | Policy version transition (v1.0 -> v2.0) enforcement | **PASSED** |
| `test_direct_api_bypass_denial` | Direct call without signed gateway headers -> DIRECT_ACCESS_DENIED | **PASSED** |
| `test_policy_conflict_resolution_most_restrictive` | Multiple policies evaluation -> Most Restrictive Rule Wins | **PASSED** |
| `test_policy_version_history_and_rollback` | Rollback policy from v2.0 to v1.0 | **PASSED** |
| `test_ledger_failure_recovery_handling` | Fabric orderer failure -> COMMIT_FAILED logged, evidence preserved safely | **PASSED** |

---

## 2. Benchmark Metrics Summary Table

All benchmark metrics were collected across 100 requests using `benchmark.py`:

| Metric | Measurement Method | Test Size | Result (Avg / Min / Max) |
| :--- | :--- | :--- | :--- |
| **1. Client Request Signing Latency** | RSA 2048 Signature Gen | 100 reqs | **115.86 ms** (27.70 - 279.45 ms) |
| **2. Gateway Auth Verification Latency** | X.509 + Sig Verification | 100 reqs | **0.580 ms** (0.19 - 3.48 ms) |
| **3. Policy Decision Latency** | Policy Engine Rule Check | 100 reqs | **0.083 ms** (0.03 - 0.35 ms) |
| **4. Blockchain Commit Latency** | Fabric Ledger & Chaincode | 100 reqs | **0.131 ms** (0.05 - 0.73 ms) |
| **5. Gateway E2E Processing Latency** | Complete Gateway Pipeline | 100 reqs | **57.47 ms** (0.22 - 279.28 ms) |
| **6. Total End-to-End Client Roundtrip** | Signing + Gateway Pipeline | 100 reqs | **173.33 ms** (28.03 - 558.73 ms) |
| **7. System Throughput** | Requests Processed per sec | 100 reqs | **5.74 requests/second** |
| **8. Unauthorized Prevention Rate** | Blocked Excessive Requests | 50 attempts | **100.00%** (50/50 blocked) |
| **9. Tamper Detection Rate** | Modified Evidence Verification | 10 attempts | **100.00%** (10/10 detected) |
| **10. False Authorization Rate** | Unauthorized Actions Allowed | 50 attempts | **0.00%** |
