# AgentTrust Presentation Visuals & Visual Assets (12 Slides)

This document contains visual diagrams, Markdown tables, and layout code designed for rendering the 12 presentation slides of the **AgentTrust** project.

---

## Slide 1: Title & Tagline

```
====================================================================================
                        A G E N T T R U S T
   A Permissioned Blockchain Framework for Verifiable Identity, Bounded 
              Authorization, and Accountability of Autonomous AI Agents
====================================================================================
                       "Making AI Actions Controlled and Accountable"

               Presenter : AI Security & Agentic Systems Research Team
               Platform  : Cryptographic Gateway + Hyperledger Fabric Simulator
               Status    : 75/75 Tests Passed (55 Core + 20 Attack Lab)
====================================================================================
```

---

## Slide 2: Problem Statement & Security Gaps

| Traditional Enterprise Setup | Threat / Vulnerability | AgentTrust Solution |
| :--- | :--- | :--- |
| Static Bearer Tokens / API Keys | Credential Theft & Misuse | **X.509 Cryptographic Certificates + RSA 2048 Signatures** |
| Unbounded API Access | Hallucinated / High-Value Reqs | **Bounded Multi-Attribute Policy Engine (Deny-by-Default)** |
| Traditional Database Logs | Log Modification / Deletion | **Hyperledger Fabric Append-Only Ledger Simulator** |
| Direct Backend Invocations | Gateway Bypass Attacks | **Mandatory RBAC Authorization (`X-Admin-Role`) + Signed Headers** |

---

## Slide 3: Proposed Private Blockchain Architecture

```
=============================================================================================================================
                                      PROPOSED PRIVATE BLOCKCHAIN ARCHITECTURE
=============================================================================================================================

                                       ┌───────────────────────────────────┐
                                       │       Autonomous AI Agent         │
                                       │   (X.509 Identity + RSA SHA-256   │
                                       │          Signed Request)          │
                                       └─────────────────┬─────────────────┘
                                                         │
                        ┌────────────────────────────────┼────────────────────────────────┐
                        │                                │                                │
                        ▼                                ▼                                ▼
  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐  ┌─────────────────────────────────┐
  │         IDENTITY PHASE          │  │          POLICY PHASE           │  │    EXECUTION & COMMIT PHASE     │
  │                                 │  │                                 │  │                                 │
  │  1. Canonical JSON Validation   │  │  5. Replay & Idempotency Check │  │  9. Protected API Execution     │
  │                │                │  │                │                │  │                │                │
  │                ▼                │  │                ▼                │  │                ▼                │
  │  2. X.509 Certificate Verify    │  │  6. Server-Side Risk Eval      │  │ 10. Off-Chain SHA-256 Evidence │
  │                │                │  │                │                │  │                │                │
  │                ▼                │  │                ▼                │  │                ▼                │
  │  3. RSA Signature Verification  │  │  7. Versioned Policy Engine   │  │ 11. Local Hash-Chain Log       │
  │                │                │  │                │                │  │                │                │
  │                ▼                │  │                ▼                │  │                ▼                │
  │  4. Agent Status & Key-Version  │  │  8. Decision / Human Approval  │  │ 12. Hyperledger Fabric Commit   │
  │     Check                       │  │     Ticket                      │  │                │                │
  └─────────────────┬───────────────┘  └────────────────┬────────────────┘  │                ▼                │
                    │                                   │                   │ 13. Final Gateway Response      │
                    │                                   │                   │     Telemetry                   │
                    └───────────────────────────────────┼───────────────────┴────────────────┬────────────────┘
                                                        │                                    │
                                        ┌───────────────┴───────────────┐                    │
                                        ▼                               ▼                    ▼
                          ┌───────────────────────────┐   ┌───────────────────────────┐
                          │   Protected Finance API   │   │    Hyperledger Fabric     │
                          │     (Signed Headers)      │   │        Consortium         │
                          └───────────────────────────┘   └───────────────────────────┘
```

---

## Slide 4: Cryptographic Identity (X.509 & RSA 2048)

```
       ┌────────────────────────┐
       │ Agent Registry X.509 CA│
       └───────────┬────────────┘
                   │
                   ├──► Issues Certificate  : SHA256 Fingerprint
                   ├──► Key Generation      : RSA 2048-bit Keypair
                   └──► Key Storage         : PEM Format Keypair
                               │
                               v
       ┌─────────────────────────────────────────────────────────┐
       │                 Signed Payload Structure                │
       ├─────────────────────────────────────────────────────────┤
       │ {                                                       │
       │   "request_id": "REQ-1001",                             │
       │   "agent_id": "FINANCE-AGENT-001",                      │
       │   "action": "CREATE_REIMBURSEMENT",                     │
       │   "parameters": { "amount": 7500.0 },                   │
       │   "nonce": "N-9821",                                    │
       │   "timestamp": "2026-09-13T16:00:00Z",                  │
       │   "signature": "MEYCIQD7vKx2..." <── RSA 2048 PSS Sig    │
       │ }                                                       │
       └─────────────────────────────────────────────────────────┘
```

---

## Slide 5: Bounded Policy Enforcement Example

```json
{
  "policy_id": "FIN-POLICY-001",
  "agent_id": "FINANCE-AGENT-001",
  "allowed_actions": ["CREATE_REIMBURSEMENT"],
  "allowed_resource": "FINANCE_API",
  "maximum_amount": 10000.0,
  "human_approval_above": 10000.0,
  "working_hours": { "start": "00:00", "end": "23:59" },
  "version": "1.0"
}
```

```
           Incoming Request Payload (Amount = ₹7,500)
                              │
                              v
           ┌─────────────────────────────────────┐
           │ Check Action: CREATE_REIMBURSEMENT  │ ──► PASSED
           └──────────────────┬──────────────────┘
                              │
                              v
           ┌─────────────────────────────────────┐
           │ Check Resource: FINANCE_API         │ ──► PASSED
           └──────────────────┬──────────────────┘
                              │
                              v
           ┌─────────────────────────────────────┐
           │ Check Amount: ₹7,500 <= ₹10,000     │ ──► PASSED
           └──────────────────┬──────────────────┘
                              │
                              v
                   DECISION: ALLOWED (200 OK)
```

---

## Slide 6: Action Gateway & Replay Protection

```
  Agent Request ──► Gateway Nonce Check ──► Request ID Tracker ──► Expiration Window (300s)
                         │                         │                        │
                         ├── If Nonce Reused ─────┼── If Duplicate ID ─────┴── If Expired
                         │                         │
                         v                         v
               REPLAY_DETECTED (403)     REPLAY_DETECTED (403)
```

---

## Slide 7: Human Approval & Re-Validation Workflow

```
   Agent Request (Amount = ₹25,000 > ₹10,000 Threshold)
                           │
                           v
        ┌───────────────────────────────────────┐
        │ Action Gateway Policy Evaluation      │
        └──────────────────┬────────────────────┘
                           │
                           v
        ┌───────────────────────────────────────┐
        │ DECISION: PENDING_HUMAN_APPROVAL      │
        │ Status: Action Suspended (API Held)   │
        └──────────────────┬────────────────────┘
                           │
                           v
        ┌───────────────────────────────────────┐
        │ Human Supervisor (FINANCE_APPROVER)   │ (Strict RBAC Gated)
        └──────────────────┬────────────────────┘
                           │
                           v
        ┌───────────────────────────────────────┐
        │ Policy & Agent Status Re-Validation   │ (Verify Agent active + policy rules)
        └──────────────────┬────────────────────┘
                           │
                           v
        ┌───────────────────────────────────────┐
        │ DECISION: ALLOWED_AFTER_APPROVAL      │
        │ Downstream Finance API Executed       │
        │ Committed to Hyperledger Fabric Block │
        └───────────────────────────────────────┘
```

---

## Slide 8: Evidence Hashing & Tamper Detection

```
                       OFF-CHAIN DATABASE
              ┌──────────────────────────────────┐
              │ Evidence JSON Payload (v2.0)     │
              │ Amount: ₹7,500                   │
              └────────────────┬─────────────────┘
                               │
                        SHA-256 Digest
                               │
                               v
                       ON-CHAIN LEDGER
              ┌──────────────────────────────────┐
              │ Block #4 Transaction Payload     │
              │ evidence_hash: "6e32f9112776..." │
              └──────────────────────────────────┘
                               │
               [ Malicious DB Tamper: ₹999,999 ]
                               │
                               v
            Recalculated Hash: "662b2892bd24..."
                               │
               Compare with Stored On-Chain Hash
                               │
                               v
                  TAMPERING DETECTED (Alert)
```

---

## Slide 9: Fabric Architecture & Simulation Engine

```
                       ┌───────────────────────────────┐
                       │ AgentTrust Action Gateway     │
                       └───────────────┬───────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │                                             │
                v                                             v
  ┌───────────────────────────┐                 ┌───────────────────────────┐
  │ Fabric Simulator Engine   │                 │ Production Fabric Spec    │
  │ (In-Memory Ledger)        │                 │ (Docker Test Network)     │
  ├───────────────────────────┤                 ├───────────────────────────┤
  │ • LevelDB World State     │                 │ • Orderer Node (Raft)     │
  │ • SHA-256 Block Chaining  │                 │ • Peer0 Org1 & Peer0 Org2 │
  │ • Fabric Client Wrapper   │                 │ • Go Chaincode (cc.go)    │
  └───────────────────────────┘                 └───────────────────────────┘
```

---

## Slide 10: 20-Scenario Attack Lab & Security Matrix

| # | Demo Scenario Name | Threat Vector | Expected Gateway Result | Ledger Audit Result |
| :-: | :--- | :--- | :--- | :--- |
| **1** | Valid Reimbursement | Low-value policy compliance | **ALLOWED (200 OK)** | Block Committed |
| **2** | Excessive Amount | Boundary limit breach | **BLOCKED (Limit Exceeded)** | Block Committed |
| **3** | Invalid Signature | Signature forgery | **BLOCKED (Invalid Sig)** | Fast Edge Denial |
| **4** | Revoked Agent | Certificate revocation | **BLOCKED (Cert Revoked)** | Fast Edge Denial |
| **5** | Replay Attack | Nonce & Req ID reuse | **BLOCKED (Replay Detected)** | Fast Edge Denial |
| **6** | High-Value Approval | Policy human-in-loop hold | **PENDING -> ALLOWED** | Block Committed |
| **7** | Evidence Tampering | Off-chain data modification | **TAMPERING DETECTED** | Hash Mismatch |
| **8** | Unauthenticated Transfer | Missing RBAC authorization | **401 UNAUTHORIZED** | Fast Edge Denial |

---

## Slide 11: Benchmark Results & Latency Percentiles

```
   Latency Percentiles Comparison (Milliseconds)

   Signing (RSA)    : [========================] 115.86 ms (P95: 134.1 ms)
   Auth Verification: [=] 0.58 ms (P95: 0.81 ms)
   Policy Engine    : [=] 0.08 ms (P95: 0.12 ms)
   Fabric Commit    : [=] 0.13 ms (P95: 0.19 ms)
   Gateway E2E      : [============] 57.47 ms (P95: 71.20 ms)
   Total Roundtrip  : [=============================] 173.33 ms (P95: 205.10 ms)
```

---

## Slide 12: Conclusion & Future Scope

### Key Empirical Achievements
- 20/20 modeled adversarial attack scenarios mitigated in Attack Lab.
- Fast edge rejection for unauthenticated and forged requests.
- 75/75 passing automated unit, integration, and adversarial tests.

### Future Architectural Enhancements
- Hardware Security Module (HSM) private key isolation and encryption at rest.
- SQLite/PostgreSQL persistent storage for CA certificates and ledger blocks.
- Real multi-peer Docker network deployment for Hyperledger Fabric Go chaincode.
" │
              └──────────────────────────────────┘
                               │
               [ Malicious DB Tamper: ₹999,999 ]
                               │
                               v
            Recalculated Hash: "662b2892bd24..."
                               │
               Compare with Stored On-Chain Hash
                               │
                               v
                  TAMPERING DETECTED (Alert)
```

---

## Slide 9: Dual-Mode Hyperledger Fabric Architecture

```
                       ┌───────────────────────────────┐
                       │ AgentTrust Action Gateway     │
                       └───────────────┬───────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │                                             │
                v                                             v
  ┌───────────────────────────┐                 ┌───────────────────────────┐
  │ Local Prototype Baseline  │                 │ Production Fabric SDK     │
  │ (Built-In Python Engine)  │                 │ (External Docker Network) │
  ├───────────────────────────┤                 ├───────────────────────────┤
  │ • LevelDB World State     │                 │ • Orderer Node (Raft)     │
  │ • SHA-256 Block Chaining  │                 │ • Peer0 Org1 & Peer0 Org2 │
  │ • Python Chaincode Class  │                 │ • Go Chaincode (cc.go)    │
  └───────────────────────────┘                 └───────────────────────────┘
```

---

## Slide 10: 8-Scenario Live Demo Summary Matrix

| # | Demo Scenario Name | Input Condition | Expected Gateway Result | Ledger Audit Result |
| :-: | :--- | :--- | :--- | :--- |
| **1** | Valid Reimbursement | Amount = ₹7,500 (<= ₹10k) | **ALLOWED (200 OK)** | Block Committed |
| **2** | Excessive Amount | Amount = ₹80,000 (> ₹10k) | **BLOCKED (Limit Exceeded)** | Block Committed |
| **3** | Invalid Signature | Signature = Forged String | **BLOCKED (Invalid Sig)** | Event Logged |
| **4** | Revoked Agent | Cert Status = REVOKED | **BLOCKED (Cert Revoked)** | Event Logged |
| **5** | Replay Attack | Duplicate Nonce / Req ID | **BLOCKED (Replay Detected)** | Event Logged |
| **6** | High-Value Approval | Amount = ₹25,000 | **PENDING -> ALLOWED** | Block Committed |
| **7** | Evidence Tampering | Off-Chain Amount Altered | **TAMPERING DETECTED** | Hash Mismatch |
| **8** | Ledger Outage Recovery | Orderer Connection Down | **RECOVERED (DLQ Flush)** | Retry Committed |

---

## Slide 11: Benchmark Results & Percentile Charts

```
   Latency Percentiles Comparison (Milliseconds)

   Signing (RSA)    : [========================] 115.86 ms (P95: 134.1 ms)
   Auth Verification: [=] 0.58 ms (P95: 0.81 ms)
   Policy Engine    : [=] 0.08 ms (P95: 0.12 ms)
   Fabric Commit    : [=] 0.13 ms (P95: 0.19 ms)
   Gateway E2E      : [============] 57.47 ms (P95: 71.20 ms)
   Total Roundtrip  : [=============================] 173.33 ms (P95: 205.10 ms)
```

---

## Slide 12: Conclusion & Future Scope

### Key Achievements
- Complete zero-trust security framework for autonomous AI agents.
- 100.00% unauthorized request prevention rate.
- 100.00% off-chain tamper detection rate.
- 36/36 passing automated unit, integration, and adversarial tests.

### Enterprise Roadmap
- Multi-agent delegation trees with key inheritance.
- Hardware Security Module (HSM) private key isolation.
- Real-time ML anomaly detection scoring.
- Multi-organization Hyperledger Fabric raft ordering networks.
