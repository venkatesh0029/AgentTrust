# AgentTrust Security Invariants Model

## Overview
The AgentTrust security architecture is mathematically and algorithmically governed by **12 Core Security Invariants (I1–I12)**. Every request processed by the system must satisfy all active invariants.

---

## The 12 Security Invariants

### I1: Identity Cryptographic Verification
*No unauthenticated agent action shall execute.*
Every request must be accompanied by a valid X.509 certificate and an RSA/Ed25519 digital signature over the JCS canonical payload. Unsigned or forged requests are rejected at Stage 2.

### I2: Non-Bypassable Gateway Pipeline
*No direct API invocation shall bypass the Action Gateway.*
The Protected Finance API requires a valid secret `gateway_token` and signed auth headers. Direct access attempts return `403 DIRECT_ACCESS_DENIED`.

### I3: Replay & Freshness Protection
*No request shall be replayed or processed outside the freshness window.*
Nonces are tracked per agent, and timestamps must fall within a 300-second (5 min) window. Duplicate nonces or stale timestamps return `REPLAY_DETECTED` or `TIME_WINDOW_VIOLATION`.

### I4: Server-Side Trusted Risk Evaluation
*Client-supplied risk parameters shall be strictly overridden by the backend Risk Engine.*
Risk evaluation executes on the server based on transaction amount, resource sensitivity, off-hours timing, and agent key version. Client overrides (e.g., `"risk_score": 0`) are ignored.

### I5: Bounded Policy Authorization Limits
*No transaction exceeding authority limits shall execute automatically.*
Transactions exceeding maximum limits are blocked (`AUTHORITY_LIMIT_EXCEEDED`). Transactions exceeding human approval thresholds are held (`PENDING_HUMAN_APPROVAL`).

### I6: Single-Use Human Approval Binding
*Human approval tickets and tokens shall be single-use, cryptographically bound, and non-replayable.*
Approval tokens are bound to `request_id`, `request_hash`, `agent_id`, and `policy_version`. Reusing an approval token or substituting tokens across requests is rejected.

### I7: Post-Approval Payload Integrity
*Any parameter modification post-approval shall invalidate execution.*
Modifying parameters (e.g. altering PO amount from ₹25k to ₹90k) after approval causes signature verification failure when the request is resumed.

### I8: Cryptographic Audit Hash Chain Integrity
*The local audit log shall form an immutable SHA-256 hash chain.*
Every record includes `previous_record_hash`. Any historical tampering or sequence gap breaks the hash chain and is detected by `verify_chain_integrity()`.

### I9: Off-Chain Evidence SHA-256 Integrity Verification
*Off-chain evidence storage shall be verifiable against on-chain ledger digests.*
Evidence records are SHA-256 hashed and stored on Hyperledger Fabric. Tampering with off-chain evidence causes `verify_evidence_hash` to return `TAMPERING_DETECTED`.

### I10: Idempotent Execution Safeguard
*Duplicate business requests with identical idempotency keys shall produce idempotent execution without duplicate side effects.*
Retrying a purchase order with the same `idempotency_key` returns cached transaction output without creating duplicate purchase orders.

### I11: Permissioned Ledger Authorization (MSP)
*Ledger writes shall require authorized MSP credentials.*
Fabric chaincode enforces caller MSP authorization (`Org1MSP` / `Org2MSP`). Unauthorized caller orgs (e.g. `UNAUTHORIZED_ROGUE_MSP`) are rejected with `PermissionError`.

### I12: Secure Key Rotation & Key Version Enforcement
*Rotating an agent's key invalidates signatures created with old keys.*
Upon key rotation, `key_version` increments (e.g. v1 -> v2). Requests signed with old keys or specifying outdated `key_version` are rejected with `INVALID_KEY_VERSION` or `INVALID_SIGNATURE`.

---

## Verification Test Suite
All 12 invariants are validated via automated tests in `tests/test_security_invariants.py`.
Result: **12/12 Invariants PASSED**.
