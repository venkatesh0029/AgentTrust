# AgentTrust: A Permissioned Blockchain Framework for Verifiable Identity, Bounded Authorization, and Accountability of Autonomous AI Agents

**Final Academic Project Report & System Architecture Specification**

---

## Executive Abstract

As autonomous Artificial Intelligence (AI) agents assume operational decision-making in finance, healthcare, supply chains, and enterprise IT infrastructure, existing Identity and Access Management (IAM) systems fail to offer cryptographic non-repudiation, execution boundary enforcement, or immutable post-hoc auditability. Traditional REST APIs rely on long-lived bearer tokens or static API keys, enabling rogue or compromised AI agents to perform unauthorized high-value transactions, replay historical actions, or manipulate local system logs.

**AgentTrust** addresses these fundamental vulnerabilities by introducing a zero-trust permissioned blockchain framework tailored for autonomous AI agents. AgentTrust tightly integrates:
1. **Cryptographic Agent Identity**: Managed via X.509 Certificates and 2048-bit RSA Digital Signatures encrypted at rest with AES-256-GCM.
2. **Bounded Attribute Policy Authorization**: Enforcing multi-attribute constraints (`maximum_amount`, `allowed_resource`, `working_hours`) with mandatory *Deny by Default* and *Most Restrictive Rule Wins* conflict resolution.
3. **Mandatory Action Gateway**: Serving as an unbypassable execution barrier with replay protection (Nonces + SHA-256 Request Tracking) and service-to-service cryptographic tokens (`X-Gateway-Signature`).
4. **Human-in-the-Loop Threshold Approvals**: Routing high-value or high-risk requests (> ₹10,000) to human supervisor queues before downstream execution.
5. **Off-Chain Evidence Provenance Schema v2.0**: Storing full request payloads off-chain while committing deterministic SHA-256 evidence hashes onto a permissioned ledger.
6. **Dual-Mode Hyperledger Fabric Permissioned Ledger**: Implementing LevelDB/CouchDB World State, SHA-256 block hash chaining, MSP certificate validation, and smart contract chaincode execution (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `VerifyEvidenceReference`), alongside an external Hyperledger Fabric gRPC Gateway SDK Bridge.

Empirical evaluation demonstrates **100.00% unauthorized request prevention** across 50 adversarial attack attempts, **100.00% off-chain tamper detection**, and zero false authorizations across a 36/36 automated test suite. Performance benchmarks yield a client roundtrip latency of **173.33 ms** (with Gateway authentication verification taking **0.580 ms** and policy engine evaluation taking **0.083 ms**), establishing AgentTrust as a performant security architecture for enterprise AI deployments.

---

## 1. Introduction & Background

### 1.1 The Shift to Autonomous AI Agents
Modern enterprise workflows are undergoing a paradigm shift from passive predictive models to active autonomous agents empowered by Large Language Models (LLMs) and automated agentic frameworks (e.g., AutoGen, LangChain, CrewAI). These agents independently execute API calls, process financial transactions, query SQL databases, and interact with external cloud services.

### 1.2 The Security Void in Agentic Infrastructure
Despite their capabilities, autonomous agents present distinct security challenges:
- **Nondeterministic Execution**: LLMs may hallucinate tool arguments, issue unauthorized financial requests, or exceed delegated business limits.
- **Credential Abuse**: Sharing static user credentials or OAuth refresh tokens with autonomous agents exposes corporate backends to credential theft or prompt injection attacks.
- **Log Tampering**: Standard application logs stored on standard servers can be deleted or modified by compromised agents or malicious insiders.

AgentTrust bridges this gap by establishing an immutable, verifiable, and cryptographic boundary around every agent action.

---

## 2. Literature Survey & Related Work

| Domain / Prior Work | Mechanism | Limitations Addressed by AgentTrust |
| :--- | :--- | :--- |
| **Traditional Enterprise IAM** (OAuth 2.0 / SAML) | Bearer token authorization | Lacks request payload signature binding, non-repudiation, or fine-grained parameter bounded policy checks. |
| **Traditional Audit Logs** (Syslog / CloudWatch) | Centralized text logging | Vulnerable to post-hoc tampering, truncation, or insider modification. |
| **Public Blockchains** (Ethereum / Solana) | Decentralized consensus | High transaction fees, slow finality (seconds to minutes), and violation of enterprise payload privacy. |
| **Hyperledger Fabric Architecture** | Permissioned ledger with MSP & channels | Provides enterprise privacy and high throughput; AgentTrust adds agent identity management and bounded gateway execution. |

---

## 3. Problem Statement & Threat Model

### 3.1 Problem Statement
Enterprise systems require a mechanism to guarantee that:
1. No AI agent can perform an action without a valid, unrevoked cryptographic identity.
2. No AI agent can exceed its explicitly assigned policy bounds.
3. No historical agent action can be replayed or forged.
4. All executed actions are immutably logged with evidence hashes on a permissioned ledger.

### 3.2 Threat Model & Adversarial Capabilities
AgentTrust assumes an adversary capable of:
- Intercepting network traffic and attempting **Replay Attacks** using prior valid signatures.
- Modifying request parameters in transit (**Payload Tampering Attack**).
- Attempting **Direct API Bypass** by invoking backend services directly without gateway headers.
- Exploiting compromised agents whose X.509 certificates have been **Revoked**.
- Altering off-chain evidence payloads stored in traditional databases (**Off-Chain Tamper Attack**).

---

## 4. Formal Security Model & Invariants

AgentTrust strictly enforces six formal security invariants across all execution pipelines:

- **Invariant 1 (Authorization Bound)**: A protected API must never execute an unauthorized request.
- **Invariant 2 (Identity Non-Repudiation)**: A revoked or suspended agent must never execute a new action.
- **Invariant 3 (Audit Completeness)**: Every executed action must have a corresponding audit event and evidence payload.
- **Invariant 4 (Evidence Integrity)**: Every audit event on the ledger must reference a verifiable SHA-256 evidence hash.
- **Invariant 5 (Replay Prevention)**: A replayed request (same request ID or nonce) must never execute twice within the validity window.
- **Invariant 6 (Administrative RBAC Integrity)**: Only authorized administrators with proper RBAC roles may modify policies or agent registration statuses.

---

## 5. System Architecture & Component Design

```
                  ┌───────────────────────┐
                  │ Admin / Policy Admin  │
                  └───────────┬───────────┘
                              │
                              v
                  ┌───────────────────────┐
                  │ Agent Registry & CA   │
                  └───────────┬───────────┘
                              │
                              v
                  ┌───────────────────────┐
                  │ Autonomous AI Agent   │
                  └───────────┬───────────┘
                              │
                      Signed Request
                              │
                              v
                  ┌───────────────────────┐
                  │ Request Validator     │
                  └───────────┬───────────┘
                              │
                              v
                  ┌───────────────────────┐
                  │ Identity Verification │
                  └───────────┬───────────┘
                              │
                              v
                  ┌───────────────────────┐
                  │ Replay Protection     │
                  └───────────┬───────────┘
                              │
                              v
                  ┌───────────────────────┐
                  │ Policy Engine         │
                  └───────────┬───────────┘
                              │
                  ┌───────────┴───────────┐
                  │                       │
                  v                       v
        ┌──────────────────┐   ┌───────────────────┐
        │ Human Approval   │   │ Audit Event Builder│
        └────────┬─────────┘   └─────────┬─────────┘
                 │                       │
                 v                       v
        ┌──────────────────┐   ┌───────────────────┐
        │ Action Gateway   │   │ Evidence Manager  │
        └────────┬─────────┘   └─────────┬─────────┘
                 │                       │
                 v                       v
        ┌──────────────────┐   ┌───────────────────┐
        │ Protected API    │   │ SHA-256 Hashing   │
        └──────────────────┘   └─────────┬─────────┘
                                         │
                                         v
                               ┌───────────────────┐
                               │ Hyperledger Fabric│
                               └─────────┬─────────┘
                                         │
                                         v
                               ┌───────────────────┐
                               │ Audit Dashboard   │
                               └───────────────────┘
```

### Key Modules:
1. **Cryptographic Identity Manager (`identity_manager/`)**: Handles X.509 CA certificate signing, RSA 2048 key creation, AES-256-GCM private key storage, and digital signature verification.
2. **Agent Registry & Status Manager (`agent_registry/`)**: Manages agent states (`ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`) with finite state machine validation.
3. **Bounded Policy Engine (`policy_engine/`)**: Evaluates multi-attribute JSON policies with version history tracking and administrative rollback capabilities (`rollback_policy()`).
4. **Replay Protection Engine (`replay_protection/`)**: Enforces nonces and request tracking within configurable freshness windows (300 seconds).
5. **Action Gateway & DLQ (`action_gateway/`)**: Intercepts all requests, enforces signatures, routes high-value requests to human approval, delegates execution to protected APIs via signed headers, and enqueues failed commits into a Dead-Letter Queue (DLQ).
6. **Off-Chain Evidence Manager (`evidence_manager/`)**: Stores full provenance data off-chain using Canonical Evidence Schema v2.0 and computes deterministic SHA-256 integrity hashes.
7. **Dual-Mode Fabric Ledger Engine (`fabric/`)**: Operates in local Fabric-compatible prototype mode or external Hyperledger Fabric gRPC Gateway SDK mode.

---

## 6. Data & Evidence Provenance Schema v2.0

Off-chain evidence payloads adhere strictly to the **Canonical Evidence Schema v2.0** format:

```json
{
  "evidence_id": "EVIDENCE-REQ-1001",
  "schema_version": "2.0",
  "timestamp": "2026-09-13T16:00:00Z",
  "agent": {
    "agent_id": "FINANCE-AGENT-001",
    "certificate_fingerprint": "SHA256:DADE7797500C58B6B..."
  },
  "request": {
    "request_id": "REQ-1001",
    "action": "CREATE_REIMBURSEMENT",
    "resource": "FINANCE_API",
    "parameters": {
      "amount": 7500.0,
      "employee_id": "EMP-99"
    },
    "nonce": "N-1001"
  },
  "policy_evaluation": {
    "policy_id": "FIN-POLICY-001",
    "policy_version": "1.0",
    "decision": "ALLOWED",
    "reason": "WITHIN_AUTHORITY_LIMIT"
  },
  "execution_result": {
    "status": "EXECUTED",
    "response_code": 200
  }
}
```

---

## 7. Dual-Mode Hyperledger Fabric Architecture

AgentTrust supports two deployment operating modes:

1. **Fabric-Compatible Permissioned Ledger Prototype (Local Mode)**:
   - Built-in Python engine implementing LevelDB/CouchDB World State key-value store.
   - SHA-256 block hash chaining with genesis block initialization.
   - Chaincode contract execution (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `VerifyEvidenceReference`).
2. **Hyperledger Fabric Production Network (SDK Bridge Mode)**:
   - Connecting via gRPC to external Hyperledger Fabric Docker containers (`peer0.org1`, `peer0.org2`, `orderer`, `fabric-ca`).
   - Smart contracts packaged and compiled in Go (`fabric/chaincode/agenttrust_cc.go`).

---

## 8. Test Suite & Adversarial Security Evaluation

The AgentTrust framework includes a 36/36 automated test suite validating edge cases and security invariants:

| Test Module | Coverage Area | Status |
| :--- | :--- | :--- |
| `test_adversarial_security.py` | Expired certs, payload parameter tampering, timestamp skew, direct API bypass denial, forged signatures | **PASSED** |
| `test_security_invariants.py` | Verification of Security Invariants 1 through 6 | **PASSED** |
| `test_rbac_negative.py` | Verification of role boundaries (`AUDITOR`, `POLICY_ADMIN`) | **PASSED** |
| `test_canonicalization.py` | Key ordering invariance and SHA-256 hash sensitivity | **PASSED** |
| `test_failure_recovery_flow.py` | 8-step orderer outage recovery sequence & DLQ flush | **PASSED** |
| `test_resilience.py` | Conflict resolution & policy version rollback | **PASSED** |
| `test_all_scenarios.py` | 11 automated attack laboratory scenarios | **PASSED** |

---

## 9. Validated Performance Benchmarks & Percentiles

Benchmark evaluation was conducted over 3 repetitions of 100 requests (with 5 warm-up iterations discarded).

### 9.1 Environment Metadata
- **Operating System**: Windows 11 (10.0.26200)
- **CPU Architecture**: Intel64 Family 6 Model 154 (16 Cores)
- **RAM Capacity**: 15.69 GB Total Memory
- **Python Environment**: Python 3.14.2 (cryptography v46.0.5, pytest v9.0.2)
- **Execution Model**: Sequential Single-Threaded Event Loop

### 9.2 Latency Percentiles Breakdown (in ms)

| Metric Component | Mean | StdDev | Min | P50 (Median) | P90 | P95 | P99 | Max |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Client RSA 2048 Signing** | **115.86** | 12.40 | 27.70 | 114.20 | 128.50 | 134.10 | 148.90 | 279.45 |
| **2. Gateway Auth Verification** | **0.580** | 0.12 | 0.19 | 0.55 | 0.72 | 0.81 | 1.15 | 3.48 |
| **3. Policy Engine Evaluation** | **0.083** | 0.02 | 0.03 | 0.08 | 0.10 | 0.12 | 0.18 | 0.35 |
| **4. Fabric Commit (Local Prototype)** | **0.131** | 0.04 | 0.05 | 0.12 | 0.16 | 0.19 | 0.28 | 0.73 |
| **5. Gateway E2E Execution** | **57.47** | 8.15 | 0.22 | 56.10 | 66.40 | 71.20 | 85.30 | 279.28 |
| **6. Total Client Roundtrip Latency** | **173.33** | 18.90 | 28.03 | 170.80 | 194.50 | 205.10 | 234.60 | 558.73 |

### 9.3 Security Effectiveness Summary
- **System Processing Throughput**: **5.74 requests/second**
- **Unauthorized Prevention Rate**: **100.00%** (50/50 excessive requests blocked)
- **Evidence Tamper Detection Rate**: **100.00%** (10/10 tampered evidence payloads flagged)
- **False Authorization Rate**: **0.00%**

---

## 10. Conclusion & Future Scope

### 10.1 Conclusion
AgentTrust provides a complete, production-ready permissioned blockchain framework for autonomous AI agent governance. By enforcing cryptographic identities, bounded authorization rules, mandatory gateway interception, human-in-the-loop sign-offs, and SHA-256 evidence hash verification on Hyperledger Fabric, AgentTrust eliminates unauthorized AI agent actions while establishing non-repudiable audit trails.

### 10.2 Future Enterprise Roadmap
1. **Multi-Agent Delegation Chains**: Hierarchical key lineage tracking delegation trees across parent-child agent workflows.
2. **Hardware-Backed Key Storage**: Integration with Hardware Security Modules (HSM), TPMs, or AWS KMS for private key isolation.
3. **Dynamic Risk-Based Authorization**: Incorporating real-time ML anomaly detection scores into policy threshold evaluations.
4. **Multi-Organization Fabric Peer Deployment**: Expanding peer endorsement nodes across distinct cloud infrastructure providers.
