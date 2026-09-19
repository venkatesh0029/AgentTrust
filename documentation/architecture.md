# AgentTrust Architecture & Security Documentation

AgentTrust is a security and accountability framework designed to control and monitor autonomous AI agents interacting with enterprise resources, financial APIs, and business systems.

## Blockchain Architecture Distinction

> **Technical Credibility Notice**:
> AgentTrust includes a native **Fabric-compatible permissioned ledger engine** and **Chaincode smart contract abstraction** in Python (`RegisterAgent`, `RegisterPolicy`, `RecordActionEvent`, `VerifyEvidenceReference`) featuring state database (World State), append-only hash-linked blockchain ledger immutability, and MSP identity checking. Full deployment on a multi-peer Hyperledger Fabric network via Fabric SDK is supported as an external integration target.

## System Architecture Diagram

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

## Security Pipeline & Key Controls

1. **Agent Cryptographic Identity**: Issuance of X.509 Certificates and RSA 2048 keypairs with **AES-256 Encryption at Rest**. Private keys are never stored on the blockchain or unencrypted.
2. **Administrator RBAC Security**: Role-Based Access Control enforcing `SYSTEM_ADMIN`, `POLICY_ADMIN`, `FINANCE_APPROVER`, and `AUDITOR` permissions.
3. **Request Signing**: AI Agent constructs canonical JSON request and signs with RSA private key.
4. **Mandatory Action Gateway**:
   - Validates payload structure.
   - Verifies Agent Identity, X.509 certificate, and status (`ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`).
   - Verifies digital signature with Agent public key.
   - Enforces replay protection via unique Request ID, Nonce tracking, and timestamp freshness check.
   - Evaluates Policy Engine rules with **Deny by Default** and **Most Restrictive Rule Wins** conflict resolution.
   - Supports Policy Version History and Administrative Rollback (`rollback_policy()`).
   - Routes high-risk transactions (> ₹10,000) to Human Approval Queue.
   - Calls Protected Finance API using **Service-to-Service Signed Headers** (`X-Gateway-Signature`, `X-Gateway-Service`, `X-Gateway-Timestamp`) preventing API bypass (`DIRECT_ACCESS_DENIED`).
   - Generates off-chain evidence record adhering to **Canonical Evidence Schema v2.0**.
   - Calculates canonical SHA-256 hash and commits audit event to Fabric blockchain ledger.
   - Provides **Failure Recovery**: If blockchain recording fails, event is marked `COMMIT_FAILED` / retry queue without silently claiming false success.
