# AgentTrust: A Permissioned Blockchain Framework for Verifiable Identity, Bounded Authorization, and Accountability of Autonomous AI Agents

[![Build Status](https://img.shields.io/badge/Build-Passing-10b981?style=for-the-badge&logo=github)](file:///d:/OneDrive/Desktop/AgentTrust)
[![Tests](https://img.shields.io/badge/Tests-63%2F63%20Passed%20(100%25)-8b5cf6?style=for-the-badge&logo=pytest)](file:///d:/OneDrive/Desktop/AgentTrust/tests)
[![Attack Matrix](https://img.shields.io/badge/Threat%20Matrix-20%2F20%20Scenarios%20Mitigated-06b6d4?style=for-the-badge&logo=shield)](file:///d:/OneDrive/Desktop/AgentTrust/attack_lab)
[![Blockchain](https://img.shields.io/badge/Blockchain-Hyperledger%20Fabric%20v2.0-a855f7?style=for-the-badge&logo=hyperledger)](file:///d:/OneDrive/Desktop/AgentTrust/fabric)
[![Architecture](https://img.shields.io/badge/Gateway-13--Stage%20Zero--Trust-10b981?style=for-the-badge)](file:///d:/OneDrive/Desktop/AgentTrust/action_gateway)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](file:///d:/OneDrive/Desktop/AgentTrust/LICENSE)

> **Core Research Objective**: AgentTrust provides cryptographic identity, bounded policy authorization, replay protection, controlled gateway execution, human-in-the-loop approvals, off-chain SHA-256 evidence integrity hashing, and independently verifiable Hyperledger Fabric ledger auditability for autonomous AI agents.

---

## 🚀 Key Highlights & Research Contributions

- **Cryptographic Agent Identity Lifecycle**: X.509 certificate issuance, RSA-2048 keypair generation with AES-256 encryption at rest, key versioning counters, status management (`ACTIVE`, `SUSPENDED`, `REVOKED`), and seamless key rotation.
- **13-Stage Non-Bypassable Action Gateway**: A zero-trust pipeline enforcing canonical JSON schema validation, RSA SHA-256 request signature verification, replay protection, server-side risk scoring, versioned policy limits, human approval tickets, and atomic ledger commits.
- **Dual-Ledger Hyperledger Fabric Architecture**:
  - **Permissioned Ledger Engine (Local Baseline)**: Python-native engine implementing LevelDB/CouchDB World State abstraction, SHA-256 block hash chaining, MSP certificate validation, and smart contract chaincode execution (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `VerifyEvidenceReference`).
  - **Hyperledger Fabric SDK Bridge (Production Blueprint)**: gRPC gateway client connecting to external multi-peer Hyperledger Fabric consortiums (`Org1MSP`, `Org2MSP`, Raft Orderer).
- **Off-Chain Evidence Provenance & SHA-256 Tamper Detection**: Privacy-preserving off-chain storage linked to on-chain SHA-256 state tree digests, enabling instant detection of database tampering (`TAMPERING_DETECTED`).
- **20 Threat Scenarios Security Attack Lab**: Empirical evaluation suite covering signature forgery, payload tampering, replay attacks, timestamp window expiration, idempotency, certificate revocation, unauthorized actions, policy bypass, client risk manipulation, approval token substitution, direct API bypass, evidence tampering, and concurrency atomicity.
- **State-of-the-Art Multi-Page Security Dashboard**: 9 dedicated, standalone page views (`Executive Overview`, `Agent Governance`, `Human Approvals`, `Attack Lab`, `13-Stage Gateway Inspector`, `Hyperledger Explorer`, `Audit Trail`, `Evidence Tamper Lab`, `Research Benchmarks`).

---

## 🏗️ System Architecture & 13-Stage Gateway Pipeline

```
                               ┌──────────────────────────────────┐
                               │  Autonomous AI Agent (Client)    │
                               │  - X.509 Identity & Cert        │
                               │  - RSA SHA-256 Request Signer    │
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
  │   [Stage 3] RSA Digital Signature  ──►  [Stage 4] Agent Status & Key-Version Check        │
  │                                                                                          │
  │   [Stage 5] Replay & Idempotency   ──►  [Stage 6] Trusted Server-Side Risk Evaluator      │
  │                                                                                          │
  │   [Stage 7] Versioned Policy Engine──►  [Stage 8] Decision Branch & Human Approval Ticket │
  │                                                                                          │
  │   [Stage 9] Protected API Execution──►  [Stage 10] Off-Chain SHA-256 Evidence Generator    │
  │                                                                                          │
  │   [Stage 11] Local Hash-Chain Log ──►  [Stage 12] Hyperledger Fabric Blockchain Commit  │
  │                                                                                          │
  │   [Stage 13] Final Gateway Response Telemetry Payload                                    │
  └─────────────────────────────────────────────┬────────────────────────────────────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
  ┌─────────────────────────────┐                               ┌─────────────────────────────┐
  │   Protected Finance API     │                               │  Hyperledger Fabric Ledger  │
  │   (Signed Gateway Headers)  │                               │  (Org1MSP + Org2MSP Nodes)  │
  └─────────────────────────────┘                               └─────────────────────────────┘
```

---

## 🛡️ Formal Security Invariants

AgentTrust guarantees 6 formal security invariants across all operational paths:

1. **Invariant 1 (Authorization Boundary)**: A protected API endpoint must never execute an unauthorized request.
2. **Invariant 2 (Identity Lifecycle Enforcement)**: A revoked (`REVOKED`) or suspended (`SUSPENDED`) agent must never execute an action.
3. **Invariant 3 (Complete Auditability)**: Every executed action must generate a deterministic audit record and off-chain evidence payload.
4. **Invariant 4 (Verifiable Cryptographic Proof)**: Every audit record on-chain must reference a SHA-256 digest mathematically matching off-chain evidence.
5. **Invariant 5 (Strict Replay & Idempotency Protection)**: A replayed request (duplicate request ID, nonce, or expired timestamp window) must be rejected.
6. **Invariant 6 (Administrative RBAC & Policy Immutability)**: Only authorized administrators with verified RBAC roles (`SYSTEM_ADMIN`, `POLICY_ADMIN`) can alter policies, rotate keys, or change agent statuses.

---

## ⚡ Operational Modes (A–D Benchmark Evaluation)

AgentTrust supports 4 configurable operational modes to measure the exact latency vs. security trade-off:

| Operational Mode | Action Gateway | RSA Signature Check | Server Risk Engine | Local Hash Chain | Hyperledger Fabric Commit | Security Level |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Mode A: Direct API** | ❌ Bypassed | ❌ None | ❌ None | ❌ None | ❌ None | 🔴 **Critical Risk** |
| **Mode B: Auth + RBAC** | ⚠️ Partial | ✅ Verified | ❌ None | ❌ None | ❌ None | 🟡 **Basic Security** |
| **Mode C: AgentTrust w/o Fabric** | ✅ Full 13-Stage | ✅ Verified | ✅ Active | ✅ Atomic | ❌ Suppressed | 🔵 **High Security** |
| **Mode D: Full AgentTrust w/ Fabric** | ✅ Full 13-Stage | ✅ Verified | ✅ Active | ✅ Atomic | ✅ **Committed** | 🟢 **10/10 Enterprise Zero-Trust** |

---

## 🧪 63/63 Automated Test Suite Breakdown

AgentTrust includes a comprehensive automated test suite with **100% pass rate (63/63 PASSED)**:

| Test Module Path | Test Focus | Total Tests | Status |
| :--- | :--- | :---: | :---: |
| [`attack_lab/test_attack_lab.py`](file:///d:/OneDrive/Desktop/AgentTrust/attack_lab/test_attack_lab.py) | 20 Attack Threat Matrix Scenarios | 20 | ✅ 20/20 PASSED |
| [`tests/test_security_invariants.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_security_invariants.py) | Formal Security Invariants 1–6 | 12 | ✅ 12/12 PASSED |
| [`tests/test_adversarial_security.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_adversarial_security.py) | Adversarial Payloads & Edge Cases | 8 | ✅ 8/8 PASSED |
| [`tests/test_all_scenarios.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_all_scenarios.py) | End-to-End Gateway Scenarios | 10 | ✅ 10/10 PASSED |
| [`tests/test_canonicalization.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_canonicalization.py) | RFC 8785 JSON Canonicalization | 2 | ✅ 2/2 PASSED |
| [`tests/test_failure_recovery_flow.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_failure_recovery_flow.py) | Ledger Outage & Dead-Letter Queue (DLQ) | 1 | ✅ 1/1 PASSED |
| [`tests/test_identity.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_identity.py) | X.509 Certs & Key Versioning | 1 | ✅ 1/1 PASSED |
| [`tests/test_rbac_negative.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_rbac_negative.py) | RBAC Role Access Violations | 4 | ✅ 4/4 PASSED |
| [`tests/test_resilience.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_resilience.py) | Policy Conflicts & Rollbacks | 4 | ✅ 4/4 PASSED |
| [`tests/test_signature.py`](file:///d:/OneDrive/Desktop/AgentTrust/tests/test_signature.py) | RSA PSS Cryptographic Signatures | 1 | ✅ 1/1 PASSED |
| **Total Project Test Suite** | **Comprehensive System Validation** | **63** | **✅ 63/63 PASSED (100%)** |

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

## 🖥️ Multi-Page Dashboard & Visual Navigation

The dashboard is structured into **9 dedicated standalone page views** accessible via the sidebar navigation menu:

1. **Executive Overview**: High-level telemetry, KPI metric cards, Fabric network status, 13-stage visual pipeline stepper, quick attack launcher, and recent activity stream table.
2. **Agent Governance & Policies**: Complete agent registry table with X.509 cert fingerprints, key versions, status update controls (`Rotate Key`, `Revoke`), and fine-grained authorization policy rules.
3. **Human Approval Queue**: Dedicated supervisor queue holding high-value or high-risk requests (> ₹10,000) for CFO approval or rejection.
4. **Security Attack Lab**: Interactive 20-threat scenario runner with output console log.
5. **13-Stage Pipeline Inspector**: Stage-by-stage pipeline breakdown with micro-stage latencies and pass/fail telemetry.
6. **Hyperledger Explorer**: Blockchain block height, Raft consensus cluster status, Merkle roots, and transaction commit details.
7. **Audit Trail & Ledger**: Filterable, immutable log of all signed agent actions and evidence hashes.
8. **Evidence & Tamper Lab**: Interactive off-chain database tamper simulator demonstrating real-time hash comparison verification.
9. **Research Benchmarks & Modes**: Live operational mode switcher (Modes A–D), micro-stage latency percentiles (P50, P95, P99), and concurrency scaling graph (1–100 agents).

---

## ⚡ Quick Start Guide

### 1. Prerequisites & Installation

Clone the repository and install dependencies:
```bash
git clone https://github.com/agenttrust/agenttrust.git
cd AgentTrust
pip install -r requirements.txt
```

### 2. Run Complete 63-Test Suite

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

- [`documentation/getting_started.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/getting_started.md) — **Getting Started & Operational Guide** (Architecture, 13-Stage Pipeline, CLI Commands & Usage).
- [`documentation/final_project_report.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/final_project_report.md) — **Academic Project Report** (Abstract, Literature Review, Formal Security Proofs, Benchmark Tables & Results).
- [`documentation/presentation_visuals.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/presentation_visuals.md) — **Presentation Visuals & Diagrams** (ASCII Schematics, Diagrams, Slide Content).
- [`documentation/deployment_readiness.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/deployment_readiness.md) — **Enterprise Production Roadmap** (OAuth2/mTLS, HSM Key Storage, Multi-Org Fabric Deployment).
- [`fabric/production_deployment_guide.md`](file:///d:/OneDrive/Desktop/AgentTrust/fabric/production_deployment_guide.md) — **Production Hyperledger Fabric Deployment Guide**.
- [`documentation/architecture.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/architecture.md) — System Design & Pipeline Architecture.
- [`documentation/security_model.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/security_model.md) — Formal Security Guarantees & 6 Invariants Specification.
- [`documentation/threat_model.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/threat_model.md) — Threat Vectors & Adversarial Capabilities.
- [`documentation/api_specification.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/api_specification.md) — Gateway & REST API Specifications.
- [`documentation/test_report.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/test_report.md) — Automated Test Suite Results & Breakdown.
- [`documentation/baseline_comparison.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/baseline_comparison.md) — Comparative Analysis vs Traditional IAM & Centralized Logging.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](file:///d:/OneDrive/Desktop/AgentTrust/LICENSE) file for details.
