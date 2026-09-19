# AgentTrust Threat Model & Threat-to-Control Evaluation Matrix

AgentTrust defines a systematic threat model addressing autonomous AI agent security threats in enterprise environments.

## Threat-to-Control Mapping Matrix

| Threat ID | Threat / Attack Vector | Defense / Security Control | Verified Test Evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Forged Signature**: Attacker alters request payload or creates fake signature. | RSA 2048 RSA-PSS Canonical Signature Verification | `test_scenario_3_invalid_signature` & `test_adv_2_modified_request_parameters` | **PASSED** |
| **TH-02** | **Unknown / Rogue Agent**: Unregistered agent attempts access. | Agent Registry lookup & X.509 cert validation | `test_scenario_4_unknown_agent` | **PASSED** |
| **TH-03** | **Revoked Agent Reuse**: Compromised agent continues requesting after revocation. | Lifecycle status check & CRL / cert validation | `test_scenario_5_revoked_agent` & `test_invariant_2` | **PASSED** |
| **TH-04** | **Excessive Authority**: Agent attempts reimbursement above assigned limit. | Maximum amount policy evaluation in Policy Engine | `test_scenario_2_excessive_amount` | **PASSED** |
| **TH-05** | **Unauthorized Resource**: Agent accesses unauthorized service (e.g. Payroll). | Resource-level policy authorization check | `test_scenario_6_unauthorized_resource` | **PASSED** |
| **TH-06** | **Replay Attack**: Attacker captures valid request and resubmits. | Unique Request ID, Nonce tracking & Timestamp freshness | `test_scenario_7_replay_attack` & `test_invariant_5` | **PASSED** |
| **TH-07** | **Direct API Bypass**: Agent attempts to call Finance API directly without Gateway. | Direct-access denial via Gateway Service Signed Headers | `test_direct_api_bypass_denial` & `test_adv_6` | **PASSED** |
| **TH-08** | **Evidence Tampering**: Attacker modifies off-chain audit evidence records. | Deterministic SHA-256 Hashing & Fabric Ledger comparison | `test_scenario_10_evidence_tampering` & `test_canonicalization` | **PASSED** |
| **TH-09** | **Administrator Misuse**: Non-admin user attempts policy modification or agent revocation. | Role-Based Access Control (RBAC) permission matrix | `test_rbac_negative.py` & `test_adv_7` | **PASSED** |
| **TH-10** | **Policy Configuration Error**: Misconfigured or conflicting policy rules. | Policy Version History, Rollback & Most Restrictive Conflict Resolver | `test_scenario_11`, `test_policy_conflict_resolution` & `test_policy_version_history_and_rollback` | **PASSED** |
| **TH-11** | **Ledger Outage / Orderer Failure**: Blockchain peer network goes down during commit. | Durable Failure Retry Queue & DLQ (preserves evidence safely) | `test_ledger_failure_recovery_handling` & `test_complete_8step_failure_recovery_sequence` | **PASSED** |
