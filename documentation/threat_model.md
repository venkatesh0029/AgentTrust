# AgentTrust Threat Model & Security Architecture

## 1. Trust Boundaries & System Assets

### Assets
- **Agent Identity & Private Keys**: Cryptographic identities (X.509 certs, RSA/ECDSA private keys).
- **Authorization Policies**: Fine-grained maximum transfer amounts, allowed actions, resource rules.
- **Financial & API Operations**: Protected financial endpoints (`/purchase-orders`, `/fund-transfers`).
- **Audit Evidence & Block Ledger**: SHA-256 evidence records, atomic hash chains, block ledger transactions.

### Trust Boundaries
1. **Client / Agent Boundary**: Autonomous AI Agent process running on external client nodes.
2. **Gateway Enforcement Boundary**: 13-stage Action Gateway processing signed requests.
3. **Protected API Boundary**: Internal backend services accessible ONLY via valid Gateway HMAC tokens.
4. **Ledger Boundary**: Fabric-compatible permissioned ledger storing block transactions and on-chain state.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Potential Attack Vector | Mitigating AgentTrust Control | Verification Test Case |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | Attacker forging digital signature or impersonating an agent. | RSA-PSS / ECDSA signature verification against registered X.509 certificate. | `test_attack_01_forged_signature` |
| **Tampering with Data** | Altering transaction amount or recipient after signing. | Canonical JSON payload hashing and digital signature verification. | `test_attack_02_modified_signed_payload` |
| **Repudiation** | Agent denying having executed an unauthorized purchase. | Cryptographic signature bound to action parameters committed atomically to ledger. | `test_attack_16_tampered_off_chain_evidence` |
| **Information Disclosure** | Server returning agent private keys in cleartext responses. | CSR / public-key registration (`public_key_pem`) keeping private keys client-side. | `tests/test_audit_findings_regression.py` |
| **Denial of Service** | Replaying past valid requests or submitting high-frequency nonces. | 300-second freshness window, single-use nonces, and aggregate rate-limiting drop counters. | `test_attack_03_replay_attack` |
| **Elevation of Privilege** | Agent executing unauthorized action (`DELETE_ACCOUNT`) or self-approving. | Versioned Policy Engine, `approver_id != agent_id` check, and single-use approval tokens. | `test_attack_08_unauthorized_action`, `test_attack_11_approval_flag` |

---

## 3. What We Found and Fixed (Security Hardening Summary)

1. **Unauthenticated Admin Header**: Replaced raw `X-Admin-Role` header checking with PyJWT token verification (`identity_manager/jwt_auth.py`).
2. **Server-Side Private Key Generation Leak**: Added public key CSR submission (`public_key_pem`) so private keys never touch the server.
3. **Caller-less Server Signing Endpoints**: Restricted auto-signing `/purchase-orders` and `/fund-transfers` endpoints to require client-side signatures when `DEMO_MODE=False`.
4. **Unrestricted Operational Mode Switching**: Restricted `/mode` POST endpoint to require admin JWT claims and `ALLOW_RUNTIME_MODE_CHANGE=True`.
5. **Self-Approval Flaw**: Enforced `approver_id != agent_id` restriction in human approval workflow.
6. **Loose Monetary Type Parsing**: Added strict Decimal validation in `RequestValidator`, rejecting boolean, NaN, Inf, string literals, and negative values.
7. **Gateway-Only Policy Checking**: Moved policy limits and agent status checking into smart contract chaincode (`EvaluateTransactionPolicy`).
8. **SDK Default Admin Privilege**: Removed default admin role fallback and implemented fail-closed network handling (`AgentTrustNetworkError`).
