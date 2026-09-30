# AgentTrust: A Fabric-Compatible Permissioned Ledger Simulator for Verifiable Identity, Bounded Authorization, and Accountability of Autonomous AI Agents

[![Build Status](https://img.shields.io/badge/Build-Passing-10b981?style=for-the-badge&logo=github)](.)
[![Tests](https://img.shields.io/badge/Tests-78%2F78%20Passed%20(100%25)-8b5cf6?style=for-the-badge&logo=pytest)](tests)
[![Attack Matrix](https://img.shields.io/badge/Threat%20Matrix-20%2F20%20Scenarios%20Mitigated-06b6d4?style=for-the-badge&logo=shield)](attack_lab)
[![Blockchain](https://img.shields.io/badge/Blockchain-Fabric--Compatible%20Ledger%20Simulator-a855f7?style=for-the-badge)](fabric)
[![Architecture](https://img.shields.io/badge/Gateway-13--Stage%20Security%20Pipeline-10b981?style=for-the-badge)](action_gateway)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)

> **Core Research Objective**: AgentTrust provides cryptographic identity, bounded policy authorization, replay protection, controlled gateway execution, human-in-the-loop approvals, off-chain SHA-256 evidence integrity hashing, and verifiable ledger auditability for autonomous AI agents using a Fabric-compatible permissioned ledger simulator.

---

## 🚀 Key Highlights & Research Contributions

- **Cryptographic Agent Identity Lifecycle**: X.509 certificate issuance, RSA-2048 / ECDSA keypair generation, key versioning counters, status management (`ACTIVE`, `SUSPENDED`, `REVOKED`), Certificate Revocation List (CRL) checking, and key rotation.
- **13-Stage Action Gateway**: A security pipeline enforcing canonical JSON schema validation, digital request signature verification, JWT role authentication, replay protection, server-side risk scoring, versioned policy limits, human approval tickets, and atomic ledger commits.
- **Fabric-Compatible Permissioned Ledger Simulator**:
  - **Permissioned Ledger Engine (`fabric/ledger_service.py`)**: Python-native simulator engine implementing World State key-value store, SHA-256 block hash chaining, on-chain policy enforcement, and smart contract chaincode execution (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `EvaluateTransactionPolicy`).
  - **Fabric Gateway Client (`fabric/fabric_client.py`)**: Gateway client connecting to the ledger service and maintaining on-chain evidence audit trails.
- **Off-Chain Evidence Provenance & SHA-256 Tamper Detection**: Privacy-preserving off-chain storage linked to on-chain SHA-256 state tree digests, enabling instant detection of database tampering (`TAMPERING_DETECTED`).
- **20 Threat Scenarios Security Attack Lab**: Empirical evaluation suite covering signature forgery, payload tampering, replay attacks, timestamp window expiration, idempotency, certificate revocation, unauthorized actions, policy limit bypass, client risk manipulation, approval token substitution, direct API bypass, evidence tampering, and concurrency atomicity.
- **Multi-Page Security Dashboard**: Dedicated page views (`Executive Overview`, `Agent Governance`, `Human Approvals`, `Attack Lab`, `13-Stage Gateway Inspector`, `Ledger Explorer`, `Audit Trail`, `Evidence Tamper Lab`, `Research Benchmarks`).

---

## 🏗️ System Architecture & 13-Stage Gateway Pipeline

```
                               ┌──────────────────────────────────┐
                               │  Autonomous AI Agent (Client)    │
                               │  - X.509 Identity & Cert        │
                               │  - Digital Request Signer        │
                               └────────────────┬─────────────────┘
                                                │
                                    Signed Action Request JSON
                                                │
                                                v
  ┌──────────────────────────────────────────────────────────────────────────────────────────┐
  │                         AgentTrust 13-Stage Action Gateway                                │
  │                                                                                          │
  │   [Stage 1] Canonical JSON Schema  ──►  [Stage 2] X.509 Certificate Verification         │
  │                                                                                          │
  │   [Stage 3] Digital Signature Check──►  [Stage 4] Agent Status & Key-Version Check        │
  │                                                                                          │
  │   [Stage 5] Replay & Idempotency   ──►  [Stage 6] Trusted Server-Side Risk Evaluator      │
  │                                                                                          │
  │   [Stage 7] Versioned Policy Engine──►  [Stage 8] Decision Branch & Human Approval Ticket │
  │                                                                                          │
  │   [Stage 9] Protected API Execution──►  [Stage 10] Off-Chain SHA-256 Evidence Generator    │
  │                                                                                          │
  │   [Stage 11] Local Hash-Chain Log ──►  [Stage 12] Fabric Ledger Simulator Commit          │
  │                                                                                          │
  │   [Stage 13] Final Gateway Response Telemetry Payload                                    │
  └─────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
  ┌─────────────────────────────┐                               ┌─────────────────────────────┐
  │   Protected Finance API     │                               │  Fabric Ledger Simulator    │
  │   (Signed Gateway Headers)  │                               │  (On-Chain Policy Engine)   │
  └─────────────────────────────┘                               └─────────────────────────────┘
```

---

## 🛡️ Enforced Security Invariants

AgentTrust enforces six security invariants across all operational paths:

1. **Invariant 1 (Authorization Boundary)**: A protected API endpoint must never execute an unauthorized request.
2. **Invariant 2 (Identity Lifecycle Enforcement)**: A revoked (`REVOKED`) or suspended (`SUSPENDED`) agent must never execute an action.
3. **Invariant 3 (Complete Auditability)**: Every executed action must generate a deterministic audit record and off-chain evidence payload.
4. **Invariant 4 (Verifiable Cryptographic Proof)**: Every audit record on-chain must reference a SHA-256 digest mathematically matching off-chain evidence.
5. **Invariant 5 (Strict Replay & Idempotency Protection)**: A replayed request (duplicate request ID, nonce, or expired timestamp window) must be rejected.
6. **Invariant 6 (Administrative RBAC & Policy Immutability)**: Only authorized administrators with verified JWT claims or RBAC roles (`SYSTEM_ADMIN`, `POLICY_ADMIN`) can alter policies, rotate keys, or change agent statuses.

---

## ⚡ Operational Modes (A–D Benchmark Evaluation)

AgentTrust supports 4 configurable operational modes to measure the exact latency vs. security trade-off:

| Operational Mode | Action Gateway | Signature Check | Server Risk Engine | Local Hash Chain | Fabric Commit | Security Level |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Mode A: Direct API** | ❌ Bypassed | ❌ None | ❌ None | ❌ None | ❌ None | 🔴 **Critical Risk** |
| **Mode B: Auth + RBAC** | ⚠️ Partial | ✅ Verified | ❌ None | ❌ None | ❌ None | 🟡 **Basic Security** |
| **Mode C: AgentTrust w/o Fabric** | ✅ Full 13-Stage | ✅ Verified | ✅ Active | ✅ Atomic | ❌ Suppressed | 🔵 **High Security** |
| **Mode D: Full AgentTrust w/ Fabric** | ✅ Full 13-Stage | ✅ Verified | ✅ Active | ✅ Atomic | ✅ **Committed** | 🟢 **Full Ledger Security** |

---

## 🧪 Automated Test Suite (78/78 PASSED)

AgentTrust includes a comprehensive automated test suite with **100% pass rate (78/78 PASSED)**:

| Test Module Path | Test Focus | Total Tests | Status |
| :--- | :--- | :---: | :---: |
| [`attack_lab/test_attack_lab.py`](attack_lab/test_attack_lab.py) | 20 Attack Threat Matrix Scenarios | 20 | ✅ 20/20 PASSED |
| [`tests/test_audit_findings_regression.py`](tests/test_audit_findings_regression.py) | Security Hardening Regression Suite | 12 | ✅ 12/12 PASSED |
| [`tests/test_security_invariants.py`](tests/test_security_invariants.py) | Security Invariants 1–6 | 12 | ✅ 12/12 PASSED |
| [`tests/test_all_scenarios.py`](tests/test_all_scenarios.py) | End-to-End Gateway Scenarios | 10 | ✅ 10/10 PASSED |
| [`tests/test_adversarial_security.py`](tests/test_adversarial_security.py) | Adversarial Payloads & Edge Cases | 8 | ✅ 8/8 PASSED |
| [`tests/test_rbac_negative.py`](tests/test_rbac_negative.py) | RBAC Role Access Violations | 4 | ✅ 4/4 PASSED |
| [`tests/test_resilience.py`](tests/test_resilience.py) | Policy Conflicts & Rollbacks | 4 | ✅ 4/4 PASSED |
| [`tests/test_property_based.py`](tests/test_property_based.py) | Hypothesis Property-Based Invariants | 3 | ✅ 3/3 PASSED |
| [`tests/test_canonicalization.py`](tests/test_canonicalization.py) | RFC 8785 JSON Canonicalization | 2 | ✅ 2/2 PASSED |
| [`tests/test_failure_recovery_flow.py`](tests/test_failure_recovery_flow.py) | Ledger Outage & Dead-Letter Queue (DLQ) | 1 | ✅ 1/1 PASSED |
| [`tests/test_identity.py`](tests/test_identity.py) | X.509 Certs & Key Versioning | 1 | ✅ 1/1 PASSED |
| [`tests/test_signature.py`](tests/test_signature.py) | RSA PSS Cryptographic Signatures | 1 | ✅ 1/1 PASSED |
| **Total Project Test Suite** | **Comprehensive System Validation** | **78** | **✅ 78/78 PASSED (100%)** |

---

## 🎯 20 Threat Scenarios Attack Matrix Summary

| # | Threat Scenario Name | Attack Category | Attack Action / Vector | Expected Outcome | Gateway Decision |
| :-: | :--- | :--- | :--- | :--- | :---: |
| **1** | Forged Signature Rejection | Identity | Invalid RSA signature payload | **BLOCKED** | `INVALID_SIGNATURE` |
| **2** | Modified Payload Tampering | Identity | Parameter amount modified post-signing | **BLOCKED** | `INVALID_SIGNATURE` |
| **3** | Replay Attack Prevention | Replay | Duplicate request ID / nonce resubmission | **BLOCKED** | `REPLAY_DETECTED` |
| **4** | Expired Request Window | Replay | Timestamp outside 300s freshness window | **BLOCKED** | `EXPIRED_REQUEST` |
| **5** | Duplicate Request Idempotency | Idempotency | Duplicate PO with idempotency key | **ALLOWED** | `WITHIN_AUTHORITY_LIMIT` |
| **6** | Revoked Agent Block | Lifecycle | Action attempt from revoked certificate | **BLOCKED** | `CERTIFICATE_REVOKED` |
| **7** | Suspended Agent Block | Lifecycle | Action attempt from suspended cert | **BLOCKED** | `AGENT_SUSPENDED` |
| **8** | Unauthorized Action Block | Authorization | Unlisted action (`DELETE_ACCOUNT`) | **BLOCKED** | `ACTION_NOT_PERMITTED` |
| **9** | Policy Limit Bypass Attempt | Authorization | Request amount (₹500k) > Policy max | **BLOCKED** | `AUTHORITY_LIMIT_EXCEEDED` |
| **10** | Client Risk Override Rejection | Risk Engine | Client submits `risk_score=0.0` on high value | **PENDING_APPROVAL** | `HIGH_RISK_TRANSACTION` |
| **11** | Client Approval Flag Rejection | Approval | Client submits `approved=true` without token | **PENDING_APPROVAL** | `UNAUTHORIZED_APPROVAL_FLAG` |
| **12** | Single-Use Token Replay | Approval | Reusing single-use human approval token | **BLOCKED** | `TOKEN_ALREADY_USED` |
| **13** | Approval Token Substitution | Approval | Using approval token from another ticket | **BLOCKED** | `INVALID_APPROVAL_TOKEN` |
| **14** | Post-Approval Parameter Tampering | Approval | Modifying parameters after ticket creation | **BLOCKED** | `POST_APPROVAL_TAMPERING` |
| **15** | Direct API Access Denial | Execution | Direct call bypassing Gateway secret | **BLOCKED** | `DIRECT_ACCESS_DENIED` |
| **16** | Off-Chain Evidence Tampering | Auditability | Altering off-chain DB evidence record | **TAMPERING_DETECTED** | `OFF_CHAIN_EVIDENCE_TAMPERED` |
| **17** | Audit Hash Chain Tampering | Auditability | Modifying historical local hash chain record | **TAMPERING_DETECTED** | `LOCAL_HASH_CHAIN_TAMPERED` |
| **18** | Unauthorized Fabric Write | Ledger | Write call from unauthorized MSP caller | **BLOCKED** | `MSP_AUTHORIZATION_FAILED` |
| **19** | Key Rotation Enforcement | Key Mgmt | Using v1 key after key rotated to v2 | **BLOCKED** | `OUTDATED_KEY_VERSION` |
| **20** | Concurrent Audit Chain Atomicity | Concurrency | 10 concurrent requests testing chain locks | **VERIFIED_INTACT** | `CONCURRENCY_SAFE_LOCK` |

---

## ⚠️ System Limitations & Architectural Assumptions

1. **Permissioned Ledger Simulator**: The current default ledger execution engine is an in-memory/SQLite-backed Python simulator mimicking Fabric chaincode semantics. Production deployment requires connecting to a real multi-node Hyperledger Fabric network via `fabric-samples`.
2. **Single-Node Deployment**: The Gateway and REST APIs run in a single process by default. High-throughput production deployments require a distributed load-balancer and Redis-backed replay tracker.
3. **Cryptographic Key Storage**: Private keys generated in client mode must be stored in secure Hardware Security Modules (HSM) or secret managers rather than local disk files.

---

## ⚡ Quick Start Guide

### 1. Prerequisites & Installation

Clone the repository and install dependencies:
```bash
git clone https://github.com/venkatesh0029/AgentTrust.git
cd AgentTrust
pip install -r requirements.txt
```

### 2. Run Complete 78-Test Suite

Execute the entire test suite using `pytest`:
```bash
pytest -v
```

### 3. Run Experimental Performance Benchmarks

Run latency, throughput, and operational mode performance evaluation:
```bash
python benchmark.py
```

### 4. Run Interactive CLI Live Demonstration

Run the step-by-step terminal narration demonstrating core security scenarios:
```bash
python live_demo.py
```

### 5. Start Server & Open Dashboard

Launch the FastAPI application server:
```bash
python server.py
```
Open your browser at **`http://127.0.0.1:8000`** to interact with the multi-page security dashboard.

---

## 📚 Complete Documentation Index

- [`documentation/complete_project_overview.md`](documentation/complete_project_overview.md) — Technical Architecture Manual.
- [`documentation/getting_started.md`](documentation/getting_started.md) — Operational Guide.
- [`documentation/final_project_report.md`](documentation/final_project_report.md) — Academic Project Report & Security Analysis.
- [`documentation/presentation_visuals.md`](documentation/presentation_visuals.md) — System Diagrams & Presentation Visuals.
- [`documentation/deployment_readiness.md`](documentation/deployment_readiness.md) — Production Deployment Roadmap.
- [`fabric/production_deployment_guide.md`](fabric/production_deployment_guide.md) — Hyperledger Fabric Deployment Guide.
- [`documentation/architecture.md`](documentation/architecture.md) — Architecture Specification.
- [`documentation/security_model.md`](documentation/security_model.md) — Enforced Invariants Specification.
- [`documentation/threat_model.md`](documentation/threat_model.md) — Threat Model & STRIDE Table.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
