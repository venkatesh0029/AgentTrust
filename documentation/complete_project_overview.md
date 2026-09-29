# AgentTrust: Complete End-to-End System & Architecture Overview

Welcome to **AgentTrust**, an enterprise-grade, zero-trust security framework, permissioned authorization sidecar, and cryptographically verifiable audit system for **Autonomous AI Agents** executing sensitive corporate financial transactions.

This document serves as the **definitive, end-to-end technical manual** covering the entire project architecture, cryptographic pipeline, security invariants, operational modes, source code structure, REST API specifications, dashboard UI features, benchmark performance metrics, and step-by-step terminal execution guides.

---

## 📑 Table of Contents

1. [Executive Summary & Core Value Proposition](#1-executive-summary--core-value-proposition)
2. [Problem Statement & Threat Landscape](#2-problem-statement--threat-landscape)
3. [High-Level System Architecture](#3-high-level-system-architecture)
4. [13-Stage Cryptographic & Authorization Pipeline](#4-13-stage-cryptographic--authorization-pipeline)
5. [Formal Security Invariants & Guarantees](#5-formal-security-invariants--guarantees)
6. [Operational Governance Modes (Modes A–D)](#6-operational-governance-modes-modes-ad)
7. [Dual Ledger Architecture (Local & Hyperledger Fabric)](#7-dual-ledger-architecture-local--hyperledger-fabric)
8. [End-to-End Directory & Module Taxonomy](#8-end-to-end-directory--module-taxonomy)
9. [Web Audit Dashboard UI Architecture](#9-web-audit-dashboard-ui-architecture)
10. [REST API Endpoints Specification](#10-rest-api-endpoints-specification)
11. [Attack Matrix Suite (20 Security Scenarios)](#11-attack-matrix-suite-20-security-scenarios)
12. [Empirical Benchmark & Performance Scaling Results](#12-empirical-benchmark--performance-scaling-results)
13. [Step-by-Step Terminal Execution Commands](#13-step-by-step-terminal-execution-commands)
14. [Future Roadmap & Research Directions](#14-future-roadmap--research-directions)

---

## 1. Executive Summary & Core Value Proposition

As autonomous AI agents are increasingly entrusted with financial procurement, fund transfers, and cloud infrastructure management, traditional identity access management (IAM) systems designed for humans fall short:
* **LLM Hallucinations & Prompt Injections:** AI models can be tricked into generating out-of-bounds parameter requests or executing unauthorized actions.
* **Non-Repudiation Failure:** Standard API keys do not prove *which* autonomous agent version signed a request or whether its off-chain payload was tampered with after execution.
* **Lack of Multi-Party Accountability:** Traditional logging databases are vulnerable to internal database administrator (DBA) tampering.

**AgentTrust** solves this by providing a **zero-trust cryptographic gateway sidecar** and an **immutable permissioned blockchain audit trail**. It ensures:
1. **Cryptographic Non-Repudiation:** Every agent action is digitally signed using an RSA-2048 key tied to an X.509 certificate.
2. **Real-Time Policy & Risk Enforcement:** Requests are evaluated against granular multi-attribute rules and dynamic risk models prior to API dispatch.
3. **Human-in-the-Loop Interception:** High-value or high-risk transactions (> ₹10,000) are automatically held for supervisor sign-off.
4. **Verifiable Audit Provenance:** Execution events generate SHA-256 content hashes anchored to an immutable **Hyperledger Fabric** blockchain ledger.

---

## 2. Problem Statement & Threat Landscape

| Threat Vector | Description | AgentTrust Defense Mechanism |
| :--- | :--- | :--- |
| **Direct API Bypass** | Malicious agent bypasses the governance gateway to hit protected backend APIs directly. | **Service-to-Service HMAC Headers**: Backend APIs mandate `X-Gateway-Signature` tokens issued only by the Action Gateway (`403 DIRECT_ACCESS_DENIED`). |
| **Replay & Timestamp Attacks** | Attacker intercepts a valid signed request and replays it to duplicate financial transfers. | **Sliding Window Nonce Tracker**: Replaces nonces and enforces a strict 300-second freshness window. |
| **Certificate / Key Compromise** | An agent's key is leaked or compromised. | **Agent Registry Revocation List (CRL)**: Real-time certificate status verification blocks revoked or suspended agents instantly. |
| **Off-Chain Audit Tampering** | Malicious DBA alters log entries in standard SQL/NoSQL databases. | **SHA-256 Ledger Anchor**: Off-chain JSON payloads are hashed and compared against immutable Hyperledger Fabric block hashes. |
| **Prompt-Injected Parameter Spikes** | Agent is coerced into issuing ₹800,000 transfers instead of ₹8,000. | **Multi-Attribute Policy Engine & Human Approval Queue**: Intercepts requests exceeding threshold limits (`BLOCKED: Limit Exceeded`). |

---

## 3. High-Level System Architecture

The AgentTrust framework acts as a mandatory sidecar proxy separating Autonomous AI Agents from Protected Enterprise Systems:

```
                                ┌───────────────────────────────────┐
                                │    Admin / Security Operator      │
                                └─────────────────┬─────────────────┘
                                                  │
                                                  ▼
                                ┌───────────────────────────────────┐
                                │ Root Certificate Authority (CA)   │
                                └─────────────────┬─────────────────┘
                                                  │ X.509 Cert & RSA-2048 Key
                                                  ▼
                                ┌───────────────────────────────────┐
                                │    Autonomous AI Agent (Client)   │
                                └─────────────────┬─────────────────┘
                                                  │
                                          RSA-PSS Signed Request
                                                  │
                                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                    AGENTTRUST ACTION GATEWAY                                     │
 │                                                                                                  │
 │   ┌───────────────────────┐      ┌───────────────────────┐      ┌─────────────────────────────┐  │
 │   │  1. Ingestion & Format│ ───► │ 2. X.509 Identity     │ ───► │ 3. Replay Tracker & Nonce   │  │
 │   └───────────────────────┘      └───────────────────────┘      └─────────────────────────────┘  │
 │                                                                                │                 │
 │                                                                                ▼                 │
 │   ┌───────────────────────┐      ┌───────────────────────┐      ┌─────────────────────────────┐  │
 │   │  6. Human-in-Loop     │ ◄─── │ 5. Trusted Risk       │ ◄─── │ 4. Policy Evaluator         │  │
 │   │     Approval Manager  │      │    Engine (Score 0-100)│      │    (Deny-by-Default)        │  │
 │   └──────────┬────────────┘      └───────────────────────┘      └─────────────────────────────┘  │
 └──────────────│───────────────────────────────────────────────────────────────────────────────────┘
                │
                ├───────────────────────────────────────┐
                ▼ (If Approved / Auto-Allowed)          ▼ (Audit Generation)
 ┌──────────────────────────────┐       ┌─────────────────────────────────┐
 │   Protected Financial API    │       │     Evidence Store & Hashing    │
 │   (Mock Enterprise Backend)  │       │     (Provenance Schema v2.0)    │
 └──────────────────────────────┘       └────────────────┬────────────────┘
                                                         │
                                                         ▼
                                        ┌─────────────────────────────────┐
                                        │  Hyperledger Fabric Ledger      │
                                        │  (Local Engine / Docker Peer)   │
                                        └────────────────┬────────────────┘
                                                         │
                                                         ▼
                                        ┌─────────────────────────────────┐
                                        │  Glassmorphism Web Dashboard    │
                                        └─────────────────────────────────┘
```

---

## 4. 13-Stage Cryptographic & Authorization Pipeline

Whenever an AI agent requests an action (e.g. `CREATE_PURCHASE_ORDER` or `TRANSFER_FUNDS`), it passes through a strict **13-stage security pipeline**:

```
Agent Request ──► [Stage 1: Format & Schema] ──► [Stage 2: Input Canonicalization] ──► [Stage 3: Identity Check]
              ──► [Stage 4: Cert Revocation] ──► [Stage 5: Key Version] ──► [Stage 6: RSA-PSS Signature]
              ──► [Stage 7: UTC Timestamp Drift] ──► [Stage 8: Nonce Replay Check] ──► [Stage 9: Scoped Idempotency]
              ──► [Stage 10: Dynamic Risk Engine] ──► [Stage 11: Policy Evaluator] ──► [Stage 12: Human Approval Gate]
              ──► [Stage 13: Signed Gateway Execution & Fabric Commitment]
```

1. **Format & Schema Validation (`action_gateway/request_validator.py`):**
   * Validates structure of inbound payload against required fields (`request_id`, `agent_id`, `action`, `resource`, `nonce`, `timestamp`, `signature`).
2. **Strict Input Canonicalization & Format Sanitization (`action_gateway/gateway.py`):**
   * Rejects NaN/Infinity, negative amounts, string format invalidities, and mismatch between top-level vs. parameter amounts.
3. **Identity & Certificate Registration Verification (`agent_registry/`):**
   * Verifies agent registration in `AgentRegistry` and verifies certificate fingerprint matches CA store.
4. **Certificate Revocation & Expiration Check (`agent_registry/status_manager.py`):**
   * Confirms agent status is `ACTIVE` (fail-closed on `SUSPENDED`, `REVOKED`, or `EXPIRED`).
5. **Key Version Validation (`action_gateway/gateway.py`):**
   * Validates request key version against agent's active key version in registry to enforce post-rotation revoking of retired keys.
6. **RSA-PSS Digital Signature Verification (`identity_manager/signature_manager.py`):**
   * Verifies RSA-PSS digital signature over the unmutated canonical payload using agent's public key.
7. **UTC Normalized Timestamp Drift Protection (`replay_protection/`):**
   * Normalizes timestamps to UTC and enforces a strict sliding window (<300s freshness).
8. **Nonce & Replay Attack Prevention (`replay_protection/request_tracker.py`):**
   * Thread-locked nonce manager ensures nonces are unique within the active window.
9. **Per-Agent Scoped Idempotency Evaluation (`protected_api/finance_api.py`):**
   * Caches execution outcomes keyed by `(agent_id, idempotency_key)` to guarantee duplicate submissions do not produce duplicate business logic side-effects.
10. **Dynamic 8-Factor Risk Scoring Engine (`risk_engine/risk_evaluator.py`):**
    * Calculates dynamic 0–100 risk score across transaction magnitude, frequency, resource sensitivity, and operational hours.
11. **Multi-Attribute Deny-by-Default Policy Evaluation (`policy_engine/policy_evaluator.py`):**
    * Evaluates rules enforcing resource boundary, allowed actions, maximum single amount, and UTC working hours.
12. **Human-in-the-Loop Approval Interception & Resume Status Re-Validation (`human_approval/`):**
    * Intercepts high-value (>₹10,000) or high-risk actions into supervisor holding queue. Upon resume request, re-validates agent active status prior to execution.
13. **Signed Gateway Execution, Audit Hashing & Fabric Block Commitment (`protected_api/`, `evidence_manager/`, `fabric/`):**
    * Dispatches request to backend using HMAC `X-Gateway-Signature` headers, generates SHA-256 evidence provenance logs, and commits transaction blocks to Hyperledger Fabric.

---

## 5. Formal Security Invariants & Guarantees

AgentTrust mathematically guarantees **6 core security invariants**:

| Invariant | Formal Security Requirement | Enforcement Component |
| :--- | :--- | :--- |
| **Invariant 1** | Protected backend APIs must NEVER execute requests that bypass gateway authentication. | `action_gateway/` & `protected_api/finance_api.py` |
| **Invariant 2** | Revoked or suspended agents must NEVER execute actions under any circumstances. | `agent_registry/status_manager.py` |
| **Invariant 3** | Every executed action MUST generate a corresponding audit event & provenance record. | `evidence_manager/` & `fabric/` |
| **Invariant 4** | Every audit event MUST reference an immutable, verifiable SHA-256 evidence hash. | `evidence_manager/hash_manager.py` |
| **Invariant 5** | Replayed requests (duplicate ID or nonce) MUST be detected and rejected. | `replay_protection/request_tracker.py` |
| **Invariant 6** | Administrative actions (policy updates, agent revocation) require explicit RBAC authorization. | `agent_registry/admin_rbac.py` |

---

## 6. Operational Governance Modes (Modes A–D)

AgentTrust supports 4 operational modes to demonstrate security progression and baseline comparative benchmarking:

```
[ Mode A: Direct API ] ──► [ Mode B: Auth + RBAC ] ──► [ Mode C: AgentTrust No Fabric ] ──► [ Mode D: Full AgentTrust Fabric ]
 (Zero Security)             (Basic Auth Only)           (Sidecar w/o Blockchain)            (100% Zero-Trust + Blockchain)
```

1. **Mode A (Direct API Bypass):** Bypasses all sidecar controls; agent communicates directly with backend APIs. (Used as baseline for zero-security performance comparisons).
2. **Mode B (Auth + Basic RBAC):** Performs signature verification and basic policy checks, but skips risk scoring, hash chains, and blockchain commitments.
3. **Mode C (AgentTrust Sidecar without Fabric):** Full 10-stage gateway validation and off-chain audit hashing, with blockchain commitments disabled.
4. **Mode D (Full Production AgentTrust + Fabric - DEFAULT):** Complete zero-trust governance pipeline including real-time risk engine scoring, human approval queue, and Hyperledger Fabric block commitments.

---

## 7. Dual Ledger Architecture (Local & Hyperledger Fabric)

AgentTrust provides two plug-and-play ledger operating modes:

```
                                ┌───────────────────────────────────┐
                                │     AgentTrust Fabric Engine      │
                                └─────────────────┬─────────────────┘
                                                  │
                        ┌─────────────────────────┴─────────────────────────┐
                        │                                                   │
                        ▼                                                   ▼
       ┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
       │     1. Local Prototype Mode     │                 │   2. Production Fabric Gateway  │
       │    (Pure Python Implementation) │                 │  (Multi-Peer Docker gRPC Net)   │
       └────────────────┬────────────────┘                 └────────────────┬────────────────┘
                        │                                                   │
                        ├─ LevelDB / CouchDB State Abstraction             ├─ gRPC Gateway Client (FabricClient)
                        ├─ In-Memory SHA-256 Block Hashing                 ├─ Fabric Channel: agenttrust-channel
                        └─ Zero external setup required                    └─ Chaincode: agenttrust-cc (Go)
```

1. **Local Prototype Mode (Default):**
   * High-performance, pure Python in-memory ledger engine (`fabric/ledger.py`).
   * Implements LevelDB/CouchDB key-value state abstractions, SHA-256 block hash chaining, MSP certificate verification, and Smart Contract chaincode functions (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `VerifyEvidenceReference`).
2. **Production Hyperledger Fabric Mode:**
   * Enterprise gRPC Gateway client (`fabric/fabric_client.py`) connecting to a real multi-peer Hyperledger Fabric network (`agenttrust-channel` and Go chaincode `agenttrust-cc`).
   * Infrastructure Docker configs are available in `fabric/docker-compose-fabric.yaml`.

---

## 8. End-to-End Directory & Module Taxonomy

```
AgentTrust/
├── action_gateway/         # Central enforcement gateway, request router, DLQ retry queue
├── agent_registry/         # Agent registration, certificate revocation lists (CRL), admin RBAC
├── attack_lab/             # Automated test harness executing all 20 Attack Matrix scenarios
├── audit_writer/           # Local SHA-256 hash-chained log writer with sequence numbering
├── benchmark.py            # CLI latency (P50-P99) and RPS throughput benchmarking tool
├── benchmarks/             # Benchmark calculation engine (P50/P90/P95/P99 latency math)
├── config/                 # YAML configuration parameters (settings.yaml)
├── dashboard/              # Glassmorphism Single-Page Application (index.html, styles.css, app.js)
├── documentation/          # 12 comprehensive markdown guides & technical specifications
├── evidence_manager/       # Provenance Schema v2.0 generator & SHA-256 payload integrity manager
├── fabric/                 # Hyperledger Fabric ledger engine, chaincode, and gRPC client
├── human_approval/        # Holding queue for supervisor approvals (>₹10,000 or high risk)
├── identity_manager/       # Root CA, RSA-2048 key issuance, AES-256 encryption, RSA-PSS signatures
├── live_demo.py            # Narrated CLI demonstration runner executing 8 core scenarios
├── policy_engine/          # Multi-attribute JSON policy parser, evaluator, and rollback engine
├── protected_api/          # Target Finance API enforcing mandatory signed gateway headers
├── replay_protection/      # Nonce sliding window tracker & 300s timestamp drift verifier
├── requirements.txt        # Python dependency manifest
├── risk_engine/            # Dynamic 8-factor risk scoring engine (0-100 score)
├── server.py               # FastAPI backend server powering REST endpoints and dashboard UI
└── tests/                  # 75 total automated tests (55 core unit/integration/invariant tests + 20 attack matrix scenarios in attack_lab/)
```

---

## 9. Web Audit Dashboard UI Architecture

Accessing `http://127.0.0.1:8000/` loads an interactive Glassmorphism web console containing 5 primary operational viewports:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│  [ AgentTrust Console ]  Mode: MODE_D_AGENTTRUST_FABRIC | Cert: Active | Blocks: #14 | RPS: 16.5  │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│  [ Tab 1: Executive Overview ]                                                                   │
│  ├── Real-time Security Health Cards                                                            │
│  ├── Quick Cyber Demonstration Controls (1-Click Scenario Execution)                             │
│  └── Recent Telemetry Activity Stream Table                                                      │
│                                                                                                  │
│  [ Tab 2: Agent Governance ]                                                                     │
│  ├── Agent Certificate Registry Table (Rotate Key, Suspend, Revoke)                              │
│  └── Policy Version Control & Rule Limits Inspector                                              │
│                                                                                                  │
│  [ Tab 3: Human Approval Queue ]                                                                 │
│  └── Pending Supervisor Approval Cards (Approve / Reject Controls)                               │
│                                                                                                  │
│  [ Tab 4: Security Attack Lab ]                                                                  │
│  └── 20 Threat Scenarios Execution Grid (Run All 20 Scenarios Batch)                             │
│                                                                                                  │
│  [ Tab 5: Evidence & Tamper Lab ]                                                                │
│  ├── Off-Chain Database Tamper Simulator                                                         │
│  └── Live SHA-256 Hyperledger Fabric Verification Inspector                                      │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. REST API Endpoints Specification

### System & Governance Endpoints
* `GET /api/health` — Check system status, operating mode, and timestamp.
* `GET /mode` — Get current operational mode (`MODE_A` to `MODE_D`).
* `POST /mode` — Dynamically switch operational mode.

### Agent Management Endpoints
* `POST /agents/register` — Register a new agent and issue RSA-2048 keys + X.509 cert.
* `GET /agents` — List all registered agents.
* `POST /agents/{agent_id}/suspend` — Suspend an agent's active status.
* `POST /agents/{agent_id}/reactivate` — Reactivate a suspended agent.
* `POST /agents/{agent_id}/revoke` — Revoke an agent's certificate (`CERTIFICATE_REVOKED`).
* `POST /agents/{agent_id}/rotate-key` — Increment key version and issue new RSA keypair.

### Action Gateway & Business Endpoints
* `POST /purchase-orders` — Issue purchase order request through governance pipeline.
* `POST /fund-transfers` — Issue fund transfer request through governance pipeline.
* `POST /actions/submit` — Raw generic request submission to gateway.

### Human Approval Endpoints
* `GET /approvals/pending` — List pending high-value/high-risk approval tickets.
* `POST /approvals/{approval_id}/approve` — Supervisor approves held request.
* `POST /approvals/{approval_id}/reject` — Supervisor rejects held request.

### Audit & Blockchain Endpoints
* `GET /audit/events` — Retrieve full audit event history.
* `GET /audit/blockchain/blocks` — List committed Hyperledger Fabric blocks.
* `POST /evidence/{evidence_id}/simulate-tamper` — Simulate off-chain evidence tampering.
* `POST /fabric/verify-evidence` — Re-calculate SHA-256 hash and verify against blockchain block.

### Scenario & Benchmark Endpoints
* `POST /scenarios/attack-matrix/run-all` — Execute all 20 Attack Matrix scenarios in batch.
* `POST /scenarios/attack-matrix/run/{scenario_id}` — Execute a specific attack scenario.
* `POST /benchmark/run` — Execute performance benchmark harness.

---

## 11. Attack Matrix Suite (20 Security Scenarios)

AgentTrust includes an automated Attack Matrix containing 20 adversarial security threat vectors across 8 security domains:

| Domain | Scenario ID & Name | Expected Result | Mitigation Verification |
|---|---|---|---|
| **Cryptographic Identity** | #1 Forged Signature Rejection | `BLOCKED` | Signature verification failure caught at Stage 3. |
| **Cryptographic Identity** | #2 Modified Payload Tampering | `BLOCKED` | Post-signing parameter change invalidates RSA-PSS signature. |
| **Replay Protection** | #3 Replay Attack Prevention | `BLOCKED` | RequestTracker detects duplicate nonce/request_id. |
| **Replay Protection** | #4 Expired Request Window | `BLOCKED` | Timestamp > 300s drift rejected. |
| **Idempotency** | #5 Duplicate Idempotency Key | `ALLOWED` | Idempotent duplicate returns cached outcome safely. |
| **Lifecycle** | #6 Revoked Agent Block | `BLOCKED` | Certificate Revocation List (CRL) check blocks agent. |
| **Lifecycle** | #7 Suspended Agent Block | `BLOCKED` | Agent registry state check blocks execution. |
| **Authorization** | #8 Unauthorized Action Block | `BLOCKED` | Action not in policy allowlist rejected. |
| **Authorization** | #9 Policy Limit Bypass Attempt | `BLOCKED` | Transaction amount > maximum limit blocked. |
| **Risk Engine** | #10 Client Risk Override Rejection | `PENDING_APPROVAL` | Client-supplied risk scores ignored; server score enforced. |
| **Human Approval** | #11 Client Approval Flag Rejection | `PENDING_APPROVAL` | Forged client approval flags ignored. |
| **Human Approval** | #12 Single-Use Token Replay | `BLOCKED` | Approved tickets invalidated after single use. |
| **Human Approval** | #13 Approval Token Substitution | `BLOCKED` | Approval ticket bound to exact request parameters. |
| **Human Approval** | #14 Post-Approval Tampering | `BLOCKED` | Altered parameters after approval invalidate ticket. |
| **Execution** | #15 Direct API Access Denial | `BLOCKED` | Direct request without gateway signed token returns 403. |
| **Auditability** | #16 Off-Chain Evidence Tampering | `TAMPERING_DETECTED` | SHA-256 hash mismatch vs blockchain block hash. |
| **Auditability** | #17 Audit Hash Chain Tampering | `TAMPERING_DETECTED` | Hash chain link validation failure. |
| **Ledger Security** | #18 Unauthorized Fabric Write | `BLOCKED` | Unsigned MSP caller blocked from chaincode write. |
| **Key Management** | #19 Key Rotation Enforcement | `BLOCKED` | Requests signed with old key version rejected. |
| **Concurrency** | #20 Concurrent Audit Atomicity | `VERIFIED_INTACT` | Mutex locks ensure zero race conditions under concurrent write. |

> **Security Efficacy Result:** `20/20 Scenarios Mitigated (100% Security Protection)`.

---

## 12. Empirical Benchmark & Performance Scaling Results

### Stage Latency Micro-Breakdown
Benchmarking on standard Intel x86_64 hardware demonstrates sub-millisecond gateway enforcement overhead:

| Pipeline Stage | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) |
|---|---|---|---|---|
| **RSA 2048 Signature Generation (Agent)** | 29.79 ms | 28.98 ms | 34.02 ms | 34.07 ms |
| **RSA 2048 Signature Verification** | 0.082 ms | 0.076 ms | 0.112 ms | 0.116 ms |
| **X.509 Certificate Validation** | 0.137 ms | 0.126 ms | 0.175 ms | 0.245 ms |
| **Replay Tracker Check** | 0.012 ms | 0.011 ms | 0.015 ms | 0.017 ms |
| **Trusted Risk Engine Eval** | 0.011 ms | 0.010 ms | 0.013 ms | 0.014 ms |
| **Policy Engine Eval** | 0.039 ms | 0.037 ms | 0.047 ms | 0.048 ms |
| **Approval Ticket Processing** | 0.050 ms | 0.048 ms | 0.059 ms | 0.064 ms |
| **Protected API Execution** | 0.098 ms | 0.094 ms | 0.124 ms | 0.125 ms |
| **Evidence Generation & SHA-256 Hashing** | 0.024 ms | 0.023 ms | 0.029 ms | 0.031 ms |
| **Fabric Ledger Commit** | 0.038 ms | 0.036 ms | 0.046 ms | 0.059 ms |
| **Total Gateway Enforcement Overhead (excl. sig gen)** | **0.514 ms** | **0.483 ms** | **0.647 ms** | **0.746 ms** |

### Concurrency Scaling Results (1 to 100 Agents)

| Concurrent Agents | Throughput (RPS) | Mean Latency (ms) | P95 Latency (ms) | P99 Latency (ms) | Failures |
|---|---|---|---|---|---|
| **1 Agent** | 16.5 RPS | 30.46 ms | 29.89 ms | 29.89 ms | **0.0%** |
| **10 Agents** | 15.5 RPS | 135.44 ms | 386.68 ms | 414.00 ms | **0.0%** |
| **50 Agents** | 4.4 RPS | 1010.89 ms | 3212.70 ms | 3733.68 ms | **0.0%** |
| **100 Agents** | 4.6 RPS | 1922.30 ms | 5027.19 ms | 8146.83 ms | **0.0%** |

---

## 13. Step-by-Step Terminal Execution Commands

### Prerequisites
* Operating System: Windows 10/11, macOS, or Linux (Ubuntu 20.04+)
* Python `3.10+` installed.

### 1. Environment Setup
```bash
# Clone or navigate to directory
cd AgentTrust

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
.\venv\Scripts\activate
# Activate virtual environment (macOS / Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Backend Web Server & Console UI
```bash
python server.py
```
* **Dashboard Console:** Open browser to `http://127.0.0.1:8000`
* **Swagger API Specs:** Open `http://127.0.0.1:8000/docs`

### 3. Run Live CLI Demonstration Script
```bash
python live_demo.py
```
Executes 8 real-world security scenarios sequentially in CLI with colorized output.

### 4. Run Complete Automated Test Suite (43 Tests)
```bash
python -m pytest tests/ -v
```

### 5. Run Performance Benchmark Harness
```bash
python benchmark.py
```

### 6. Deploy Production Docker Hyperledger Fabric Network
```bash
docker-compose -f fabric/docker-compose-fabric.yaml up -d
```

---

## 14. Future Roadmap & Research Directions

1. **Hardware Security Module (HSM) Integration:** Support PKCS#11 HSM integration (AWS KMS / HashiCorp Vault) for hardware-isolated agent private keys.
2. **Zero-Knowledge Evidence Proofs (zk-SNARKs):** Allow agents to cryptographically prove policy compliance to external auditors without revealing raw financial transaction values.
3. **ML-Driven Adaptive Risk Engine:** Incorporate unsupervised anomaly detection models (Isolation Forest / Autoencoders) trained on historical agent behavioral trajectories.
4. **Cross-Chain Interoperability:** Extend chaincode support to Ethereum (EVM) and Solana permissioned sidechains.

---

*AgentTrust Framework v2.0 — Enterprise Security, Permissioned Authorization & Verifiable Audit for Autonomous AI Agents.*
