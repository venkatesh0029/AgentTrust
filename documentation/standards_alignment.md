# AgentTrust Standards & Regulatory Alignment Matrix

This document maps AgentTrust security controls, invariants, and gateway architecture stages to established international cybersecurity and AI governance standards, specifically **OWASP Top 10 for Agentic AI Systems (2026)** and **NIST AI Risk Management Framework (AI RMF 1.0)**.

---

## 🛡️ 1. OWASP Top 10 for Agentic AI Threat Mapping

| OWASP Threat Category | Threat Description | AgentTrust Control Mechanism | Verification & Invariants |
| :--- | :--- | :--- | :--- |
| **ASI-01: Unauthorized Agent Execution** | Autonomous sub-agents executing actions without identity verification. | X.509 Certificate verification, RSA/ECDSA digital signatures, and JWT admin authentication. | **Invariant 1 & 2** (`test_attack_01_forged_signature`, `test_identity.py`) |
| **ASI-02: Policy Limit & Scope Escalation** | Agent executing actions exceeding monetary or scope bounds. | Versioned Policy Engine, On-chain Chaincode enforcement (`EvaluateTransactionPolicy`), and Scope Attenuation (`identity_manager/delegation.py`). | **Invariant 1** (`test_attack_09_policy_bypass_attempt`) |
| **ASI-03: Replay & State Spoofing** | Replaying past valid tool calls to duplicate financial transfers. | 300-second freshness window, single-use nonces, and SHA-256 idempotency tracking. | **Invariant 5** (`test_attack_03_replay_attack`, `test_attack_05_idempotency`) |
| **ASI-04: Self-Approval & Privilege Escalation** | AI agent approving its own pending high-value transaction tickets. | Strict approver-requester separation (`approver_id != agent_id`) and single-use approval tokens. | **Invariant 6** (`test_attack_11_client_approval_flag_rejection`) |
| **ASI-05: Non-Repudiation & Audit Evasion** | Untraceable actions or tampered audit logs post-execution. | Atomic Hash-Chain log, off-chain evidence SHA-256 hashing, and Fabric block Merkle inclusion proofs. | **Invariant 3 & 4** (`test_attack_16_tampered_off_chain_evidence`) |
| **ASI-06: Prompt Injection Tool Manipulation** | Adversarial prompts hijacking tool arguments to execute unauthorized API calls. | Server-side `PromptInjectionGuard` pattern scanner and strict Pydantic Decimal validation. | **Invariant 1** (`test_attack_08_unauthorized_action`, `risk_engine/prompt_injection_guard.py`) |
| **ASI-07: Compromised SDK Default Privilege** | Client SDK defaulting to administrative access or silent fallback. | Fail-closed network handling (`AgentTrustNetworkError`) and removal of default admin roles in SDK. | **Invariant 1 & 6** (`agenttrust_sdk/agent_guard.py`) |
| **ASI-08: In-Memory State Loss & Rollback** | System crash causing loss of revocation status or policy state. | SQLite-backed `PersistentStorageEngine` persisting agents, policies, nonces, and block ledgers across restarts. | **Invariant 2 & 6** (`fabric/persistent_db.py`) |
| **ASI-09: Direct API Execution Bypass** | Bypassing security gateway to execute underlying API endpoints directly. | HMAC gateway secret authorization headers required by protected API endpoints. | **Invariant 1** (`test_attack_15_direct_protected_api_access`) |
| **ASI-10: Cryptographic Key Leakage** | Server generating and returning agent private keys in cleartext responses. | Public key / CSR registration mode (`public_key_pem`) where client retains private keys locally. | **Invariant 2 & 6** (`agent_registry/registration.py`) |

---

## 🏛️ 2. NIST AI Risk Management Framework (AI RMF 1.0) Mapping

### GOVERN (1.1 - 2.3)
- **Governance Mechanisms**: Fine-grained versioned policies bound to registered agent identities with admin RBAC control (`policy_engine/`).
- **Identity & Access Management**: X.509 Root CA and Certificate Revocation List (CRL) tracking (`identity_manager/certificate_manager.py`).

### MAP (1.1 - 3.2)
- **Categorization of Risk**: 20-scenario threat matrix mapping security threats across identity, authorization, replay, risk, approval, auditability, and concurrency categories.

### MEASURE (1.1 - 2.8)
- **Empirical Evaluation**: 78 automated test cases covering adversarial inputs, Hypothesis property-based fuzzing, and benchmark latency profiling across Operational Modes A–D.

### MANAGE (1.1 - 4.2)
- **Risk Mitigation**: 13-stage Action Gateway enforcing real-time interception, human-in-the-loop approvals for high-value/high-risk transactions, and atomic ledger commitments.
