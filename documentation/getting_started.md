# AgentTrust: How It Works & Getting Started Guide

Welcome to **AgentTrust**, an enterprise-grade security, permissioned authorization, and verifiable audit framework for autonomous AI agents.

This guide provides a comprehensive overview of **how AgentTrust works under the hood**, followed by **step-by-step terminal commands** to install, run, test, benchmark, and interact with the application.

---

## 📑 Table of Contents

1. [How AgentTrust Works](#-how-agenttrust-works)
   - [Core Architecture & Security Pipeline](#core-architecture--security-pipeline)
   - [Formal Security Invariants](#formal-security-invariants)
   - [Dual Ledger Architecture](#dual-ledger-architecture)
   - [System Module Overview](#system-module-overview)
2. [Prerequisites & Environment Setup](#-prerequisites--environment-setup)
3. [Terminal Commands to Run the Application](#-terminal-commands-to-run-the-application)
   - [1. Run the Web Audit Dashboard & Server](#1-run-the-web-audit-dashboard--server)
   - [2. Run the Interactive Live Demonstration Script](#2-run-the-interactive-live-demonstration-script)
   - [3. Run the Automated Test Suite (36/36 Passed)](#3-run-the-automated-test-suite-3636-passed)
   - [4. Run the Performance Benchmark Harness](#4-run-the-performance-benchmark-harness)
   - [5. Deploy Production Hyperledger Fabric (Docker)](#5-deploy-production-hyperledger-fabric-docker)
4. [Using the Web Audit Dashboard](#-using-the-web-audit-dashboard)
5. [Troubleshooting & Common Questions](#-troubleshooting--common-questions)

---

## 🧠 How AgentTrust Works

AgentTrust acts as a zero-trust cryptographic sidecar and authorization gateway between **Autonomous AI Agents** and **Protected Enterprise Resources** (such as Finance APIs, Databases, and Execution Infrastructure).

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

### Core Architecture & Security Pipeline

When an AI agent attempts to perform an action (e.g., executing a reimbursement transfer), the request moves through a 10-step security validation pipeline:

1. **Identity & Cryptographic Credential Issuance**:
   - Each AI agent is provisioned an X.509 digital certificate and an RSA 2048 keypair issued by the AgentTrust Root Certificate Authority (`identity_manager/`).
   - Private keys are encrypted at rest using AES-256 (passphrase + salt).

2. **Policy Provisioning**:
   - Administrators register granular JSON policies defining allowed actions, maximum transaction limits, working hours, and human approval thresholds (`policy_engine/`).

3. **RSA-PSS Digital Signing**:
   - The agent constructs its payload (Resource, Action, Amount, Request ID, Timestamp) and creates an RSA-PSS digital signature using its private key.

4. **Gateway Ingestion**:
   - The request is sent to the central `ActionGateway` (`action_gateway/`), which acts as the sole mandatory entry point for protected APIs.

5. **Certificate & Status Verification**:
   - The gateway verifies the agent's digital signature against its X.509 certificate public key and queries the `AgentRegistry` (`agent_registry/`) to ensure the agent status is `ACTIVE` (not `SUSPENDED`, `REVOKED`, or `EXPIRED`).

6. **Replay Protection**:
   - The `RequestTracker` (`replay_protection/`) checks that the Request ID/Nonce has never been seen before and verifies that the request timestamp falls within the allowed 300-second freshness window.

7. **Multi-Attribute Policy Evaluation**:
   - The `PolicyEvaluator` (`policy_engine/`) evaluates multi-attribute rules (Allowed Resource, Action Name, Transaction Amount, Working Hours window). Evaluation uses a **Deny by Default** strategy and **Most Restrictive Rule Wins** conflict resolution.

8. **Human-in-the-Loop Approval Interception**:
   - If the request exceeds the predefined human approval threshold (e.g., transaction amount > ₹10,000), the request status transitions to `PENDING_HUMAN_APPROVAL` and is held in the `HumanApprovalManager` (`human_approval/`) until a supervisor approves or rejects it.

9. **Protected API Execution**:
   - Upon successful authorization, the gateway forwards the request to the target `ProtectedFinanceAPI` (`protected_api/`) attaching service-to-service signed headers (`X-Gateway-Signature`, `X-Gateway-Service`, `X-Gateway-Timestamp`). Direct access attempts bypassing the gateway are automatically rejected (`DIRECT_ACCESS_DENIED`).

10. **Off-Chain Provenance & Blockchain Commitment**:
    - The `EvidenceStore` (`evidence_manager/`) stores the full audit payload off-chain according to **Provenance Schema v2.0** and computes a canonical SHA-256 content hash.
    - The hash reference, agent ID, and execution status are committed as an immutable block on the **Hyperledger Fabric** ledger (`fabric/`).

---

### Formal Security Invariants

AgentTrust enforces **6 strict security invariants**:

| Invariant | Security Rule | Enforcement Component |
| :--- | :--- | :--- |
| **Invariant 1** | Protected APIs must NEVER execute unauthorized requests. | `action_gateway/` & `protected_api/` |
| **Invariant 2** | Revoked/Suspended agents must NEVER execute actions. | `agent_registry/` certificate status check |
| **Invariant 3** | Every executed action MUST generate a corresponding audit event & evidence payload. | `evidence_manager/` & `fabric/` |
| **Invariant 4** | Every audit event MUST reference a verifiable SHA-256 evidence hash. | `evidence_manager/hash_manager.py` |
| **Invariant 5** | Replayed requests (duplicate ID/nonce) MUST be rejected. | `replay_protection/` sliding window tracker |
| **Invariant 6** | Policy and agent status changes require administrative RBAC authorization. | `agent_registry/admin_rbac.py` |

---

### Dual Ledger Architecture

AgentTrust supports two deployment operating modes:

1. **Local Prototype Mode (Default)**:
   - In-memory/local Fabric-compatible ledger engine located in `fabric/ledger.py`.
   - Features LevelDB/CouchDB state abstractions, SHA-256 block hash chaining, MSP certificate verification, and Smart Contract chaincode execution (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `VerifyEvidenceReference`).
   - Zero external setup required — runs out-of-the-box in pure Python.

2. **Production Hyperledger Fabric Gateway Mode**:
   - gRPC Gateway connection (`fabric/fabric_client.py`) connecting to a real multi-peer Hyperledger Fabric network (`agenttrust-channel` and `agenttrust-cc` chaincode written in Go).
   - Deployment configuration files are available in `fabric/docker-compose-fabric.yaml` and `fabric/production_deployment_guide.md`.

---

### System Module Overview

| Directory / Module | Role & Responsibility |
| :--- | :--- |
| [`identity_manager/`](file:///d:/OneDrive/Desktop/AgentTrust/identity_manager/) | X.509 Root CA, RSA key pair issuance, AES-256 key encryption, RSA-PSS signature verification. |
| [`agent_registry/`](file:///d:/OneDrive/Desktop/AgentTrust/agent_registry/) | Agent identity storage, certificate revocation lists (CRL), status management, RBAC enforcement. |
| [`policy_engine/`](file:///d:/OneDrive/Desktop/AgentTrust/policy_engine/) | Policy JSON parser, multi-attribute rule evaluator, versioning history, policy rollback engine. |
| [`replay_protection/`](file:///d:/OneDrive/Desktop/AgentTrust/replay_protection/) | Nonce tracker, timestamp drift checking (300s window), replay attack prevention. |
| [`action_gateway/`](file:///d:/OneDrive/Desktop/AgentTrust/action_gateway/) | Central enforcement gateway, request router, durable retry queue & Dead-Letter Queue (DLQ). |
| [`protected_api/`](file:///d:/OneDrive/Desktop/AgentTrust/protected_api/) | Mock enterprise financial API enforcing mandatory gateway service-to-service signed headers. |
| [`human_approval/`](file:///d:/OneDrive/Desktop/AgentTrust/human_approval/) | Holding queue & manager for high-value/high-risk transactions requiring supervisor review. |
| [`evidence_manager/`](file:///d:/OneDrive/Desktop/AgentTrust/evidence_manager/) | Canonical Provenance Schema v2.0 generator & SHA-256 payload integrity manager. |
| [`fabric/`](file:///d:/OneDrive/Desktop/AgentTrust/fabric/) | Permissioned ledger engine, chaincode contracts, and Hyperledger Fabric gRPC Gateway SDK client. |
| [`dashboard/`](file:///d:/OneDrive/Desktop/AgentTrust/dashboard/) | Glassmorphism UI single-page web app with Attack Lab, Tamper Simulator, and Block Explorer. |
| [`server.py`](file:///d:/OneDrive/Desktop/AgentTrust/server.py) | FastAPI backend server powering the dashboard UI and REST API endpoints. |
| [`live_demo.py`](file:///d:/OneDrive/Desktop/AgentTrust/live_demo.py) | CLI narration runner executing 8 core security and failure scenarios in sequence. |
| [`benchmark.py`](file:///d:/OneDrive/Desktop/AgentTrust/benchmark.py) | Latency percentile (P50/P90/P95/P99) and system throughput benchmarking harness. |
| [`tests/`](file:///d:/OneDrive/Desktop/AgentTrust/tests/) | 36 automated unit, integration, adversarial, invariant, and recovery tests. |

---

## 💻 Prerequisites & Environment Setup

### System Requirements
- **Operating System**: Windows 10/11, macOS, or Linux (Ubuntu 20.04+)
- **Python**: Version `3.10` or higher
- **Package Manager**: `pip`

### Step 1: Clone or Navigate to Project Directory

Open your terminal or command prompt and navigate to the project directory:

```bash
cd AgentTrust
```

### Step 2: Create & Activate Virtual Environment (Recommended)

**On Windows (PowerShell / Command Prompt)**:
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**On macOS / Linux**:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies

Install all core dependencies specified in `requirements.txt`:

```bash
pip install -r requirements.txt
```

*Installed libraries include `fastapi`, `uvicorn`, `cryptography`, `pydantic`, `pyyaml`, `requests`, `pytest`, and `matplotlib`.*

---

## 🚀 Terminal Commands to Run the Application

Here are the step-by-step terminal commands for running every component of the AgentTrust framework.

---

### 1. Run the Web Audit Dashboard & Server

To start the REST server and live interactive Glassmorphism audit interface:

```bash
python server.py
```

**Terminal Output**:
```text
INFO:     Started server process [PID]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

#### Accessing the User Interfaces:
- **Web Audit Dashboard UI**: Open your browser to **`http://127.0.0.1:8000`**
- **Interactive Swagger API Documentation**: Open **`http://127.0.0.1:8000/docs`**
- **OpenAPI JSON Schema**: Open **`http://127.0.0.1:8000/openapi.json`**

---

### 2. Run the Interactive Live Demonstration Script

To view an automated, step-by-step CLI demonstration of 8 real-world attack and approval scenarios with colorized output:

```bash
python live_demo.py
```

**What this script does**:
- Initializes CA certificates, registers `FINANCE-AGENT-001`, and sets policy bounds.
- **Scenario 1**: Valid Reimbursement (`₹7,500`) -> **ALLOWED (200 OK)**
- **Scenario 2**: Excessive Policy Request (`₹80,000`) -> **BLOCKED (Limit Exceeded)**
- **Scenario 3**: Forged Digital Signature -> **BLOCKED (Invalid Sig)**
- **Scenario 4**: Suspended/Revoked Agent -> **BLOCKED (Cert Revoked)**
- **Scenario 5**: Replay Attack (Duplicate Request ID) -> **BLOCKED (Replay Detected)**
- **Scenario 6**: High-Value Human Approval (`₹25,000`) -> **PENDING -> ALLOWED**
- **Scenario 7**: Evidence Tampering Attack -> **TAMPERING DETECTED**
- **Scenario 8**: Fabric Ledger Outage Recovery -> **RECOVERED (DLQ Flush)**

---

### 3. Run the Automated Test Suite (36/36 Passed)

To verify system integrity, run the complete 36-test suite using `pytest`:

```bash
python -m pytest tests/ -v
```

#### Running Specific Test Files:

- **Run Security Invariant Tests**:
  ```bash
  python -m pytest tests/test_security_invariants.py -v
  ```
- **Run Adversarial Security Vectors**:
  ```bash
  python -m pytest tests/test_adversarial_security.py -v
  ```
- **Run Negative RBAC & Permission Tests**:
  ```bash
  python -m pytest tests/test_rbac_negative.py -v
  ```
- **Run Failure Recovery & DLQ Flow**:
  ```bash
  python -m pytest tests/test_failure_recovery_flow.py -v
  ```

---

### 4. Run the Performance Benchmark Harness

To benchmark latency percentiles (P50, P90, P95, P99) and processing throughput across cryptographic signing, policy evaluation, and ledger block commitments:

```bash
python benchmark.py
```

**Key Performance Metrics Produced**:
- **RSA 2048 Signing Latency** (P50 ~100 ms)
- **Gateway Authentication & Verification Latency** (P50 ~0.43 ms)
- **Policy Engine Latency** (P50 ~0.06 ms)
- **Ledger Commit Latency** (P50 ~0.09 ms)
- **Total System Roundtrip Latency**
- **System Throughput (Req/sec)**

---

### 5. Deploy Production Hyperledger Fabric (Docker)

*(Optional for production multi-peer network deployment)*

To launch a production multi-organization Hyperledger Fabric network (Orderer, Peer0.Org1, Peer0.Org2, CouchDB, Fabric CLI):

```bash
docker-compose -f fabric/docker-compose-fabric.yaml up -d
```

To view running containers:
```bash
docker ps
```

To stop the network:
```bash
docker-compose -f fabric/docker-compose-fabric.yaml down
```

---

## 🎨 Using the Web Audit Dashboard

When you open `http://127.0.0.1:8000` in your web browser, you are presented with an interactive, real-time audit dashboard containing:

1. **System Status Header**:
   - Shows active Agent status (`ACTIVE`), Certificate Fingerprint, Policy Version, Total Audit Events, and Hyperledger Fabric Ledger Block Count.
2. **Interactive Attack Lab (11 Attack Scenarios)**:
   - Click buttons to simulate live attack scenarios (e.g., *Valid Reimbursement*, *Excessive Amount*, *Forged Signature*, *Revoked Certificate*, *Replay Attack*, *Direct API Bypass*).
   - Real-time response visualizers display HTTP Status, Gateway Decision, and Ledger Commit details.
3. **Human Approval Queue**:
   - View high-value requests (e.g., `₹25,000`) placed in `PENDING_HUMAN_APPROVAL`.
   - Click **Approve** or **Reject** with supervisor credentials to resume/terminate execution.
4. **Off-Chain Evidence Tamper Simulator**:
   - Alter off-chain payload amounts (e.g., changing `₹7,500` to `₹75,000`).
   - Run the SHA-256 integrity manager to observe immediate detection (`TAMPERING_DETECTED` hash mismatch).
5. **Immutable Block Explorer**:
   - Inspect committed blocks, block hashes, prev_block_hash pointers, block height, and verifiable evidence payload references.

---

## ❓ Troubleshooting & Common Questions

### Q1: Address already in use error when running `python server.py`
**Cause**: Port `8000` is currently occupied by another process.
**Solution**:
- Kill existing process running on port 8000, or run uvicorn on an alternate port:
  ```bash
  python -m uvicorn server:app --host 127.0.0.1 --port 8080 --reload
  ```

### Q2: ModuleNotFoundError when executing scripts
**Cause**: Dependencies are not installed in the active Python environment.
**Solution**:
- Ensure your virtual environment is activated (`venv/Scripts/activate` or `source venv/bin/activate`).
- Run `pip install -r requirements.txt`.

### Q3: `live_demo.py` output characters display incorrectly on Windows Command Prompt
**Cause**: Default Windows legacy console encoding (CP1252/cp437) doesn't render UTF-8 box characters.
**Solution**:
- Execute `chcp 65001` in command prompt before running, or use Windows Terminal / PowerShell. `live_demo.py` automatically reconfigures stdout encoding when run.

---

## 📚 Related Documentation

- [`README.md`](file:///d:/OneDrive/Desktop/AgentTrust/README.md) — Main Repository Technical Overview.
- [`documentation/final_project_report.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/final_project_report.md) — Complete Academic Project Report.
- [`documentation/architecture.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/architecture.md) — In-Depth System Architecture & Design.
- [`documentation/security_model.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/security_model.md) — Security Guarantees & 6 Invariants Specification.
- [`documentation/api_specification.md`](file:///d:/OneDrive/Desktop/AgentTrust/documentation/api_specification.md) — REST API Endpoints & Gateway Schema.
- [`fabric/production_deployment_guide.md`](file:///d:/OneDrive/Desktop/AgentTrust/fabric/production_deployment_guide.md) — Production Hyperledger Fabric Guide.
