# AgentTrust Project Demonstration Walkthrough

**Document Identifier**: `AGENTTRUST-DEMO-V1`  
**Milestone**: Version 1.0.0 General Availability (GA)  
**Execution Script**: [`live_demo.py`](../live_demo.py)  
**Coverage**: 5 Core Governance Pillars across 16 Rigorous Verification Checks  

---

## 📌 Executive Summary

The **AgentTrust Interactive Live Demonstration** ([`live_demo.py`](../live_demo.py)) showcases the end-to-end zero-trust cryptographic security, policy authorization, and distributed accountability pipeline enforced on autonomous AI agents.

By default, the demonstration executes within an **ephemeral isolated SQLite sandbox**, guaranteeing that the canonical demo database baseline ([`agenttrust_persistent.db`](../agenttrust_persistent.db)) remains completely untouched and pristine (`inspect_agenttrust_demo_db.py` passes with zero residue).

```bash
# Execute the live demonstration:
python live_demo.py
```

---

## 🏗️ The 5 Core Governance Pillars

```
+----------------------------------------------------------------------------------------------------+
|                                    AGENTTRUST 5-PILLAR DEMONSTRATION                               |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  1. CRYPTOGRAPHIC AGENT IDENTITY    ──►  X.509 PKI, RSA-2048 Digital Signatures, Dynamic CRL       |
|  2. BOUNDED POLICY AUTHORIZATION    ──►  Monetary Caps, Scope Whitelists, Human Approvals (HITL)   |
|  3. REPLAY ATTACK DEFENSE           ──►  Single-Use Nonces, Timestamp Skew Windows, Idempotency    |
|  4. CUMULATIVE LIMITS & VELOCITY    ──►  Rolling-Window Volume Accounting, Smurfing Evasion Defense |
|  5. TAMPER-EVIDENT AUDIT EVIDENCE   ──►  SHA-256 Merkle Proofs, Blockchain Blocks, Outbox DLQ     |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

---

## 🧪 Detailed Scenario Walkthrough

### Pillar 1: Cryptographic Agent Identity & PKI Non-Repudiation

Enforces that no autonomous agent can interact with enterprise backends without a registered, unrevoked X.509 certificate and mathematical proof of private key custody.

| Check | Scenario | Threat Vector | Enforcement Mechanism | Result |
| :---: | :--- | :--- | :--- | :---: |
| **1.1** | **Legitimate Request Signed with Registered Private Key** | Ambient token sharing / Anonymous requests | Gateway Stage 2 validates X.509 certificate; Stage 3 verifies RSA-PSS 2048-bit digital signature over canonicalized JSON bytes. | **`ALLOWED (EXECUTED)`** |
| **1.2** | **Adversarial Payload Tampering / Forged Signature** | In-transit payload modification / Forgery | Attacker modifies amount or recipient after digital signing. Stage 3 cryptographic verification fails (`INVALID_SIGNATURE`). Execution halted before reaching policy or backend. | **`BLOCKED (INVALID_SIGNATURE)`** |
| **1.3** | **Revoked Agent Certificate Execution Attempt** | Zombie or compromised agent credential abuse | Security administrator revokes agent certificate in the Certificate Revocation List (CRL). Stage 2 detects revoked serial and blocks fail-closed. | **`BLOCKED (CERTIFICATE_REVOKED)`** |
| **1.4** | **Unregistered Autonomous Agent Invocation** | Unregistered or rogue agent execution | Unregistered agent attempts invocation. Agent ID not found in registry; blocked fail-closed before any business logic executes. | **`BLOCKED (UNKNOWN_AGENT)`** |

---

### Pillar 2: Bounded Policy Authorization & Human-in-the-Loop Dual Custody

Enforces business boundaries, monetary transaction caps, resource scopes, and Time-of-Check to Time-of-Use (TOCTOU) protected human supervisor approval queues.

| Check | Scenario | Threat Vector | Enforcement Mechanism | Result |
| :---: | :--- | :--- | :--- | :---: |
| **2.1** | **Single-Transaction Policy Cap Breach ($50,000 > $10,000)** | Overspending / Unbounded agent financial autonomy | Policy Evaluator Stage 7 evaluates `maximum_amount` rule. $50,000 request breaches $10,000 limit. Action blocked without executing downstream financial API. | **`BLOCKED (AUTHORITY_LIMIT_EXCEEDED)`** |
| **2.2** | **High-Value Transaction Routing to Human Review & TOCTOU Resumption** | High-risk rogue transactions bypassing oversight | Request ($12,500) exceeds $5,000 review trigger. Placed in `PENDING_HUMAN_APPROVAL` with single-use ticket. Upon CFO sign-off, gateway re-verifies certificate status and policy rules before executing API. | **`ALLOWED_AFTER_APPROVAL (EXECUTED)`** |

---

### Pillar 3: Nonce Freshness & Replay Attack Defense

Guarantees at-most-once execution across network retries, race conditions, and adversarial network packet replays.

| Check | Scenario | Threat Vector | Enforcement Mechanism | Result |
| :---: | :--- | :--- | :--- | :---: |
| **3.1** | **Initial Legitimate Action Submission** | Standard business operation | Stage 5 verifies request timestamp freshness ($\pm 300\text{s}$) and registers fresh single-use nonce into `RequestTracker`. | **`ALLOWED (EXECUTED)`** |
| **3.2** | **Adversarial Replay Attack (Duplicate Packet Re-Transmission)** | Man-in-the-middle replay / Double-spend | Attacker captures valid signed packet from Scenario 3.1 and resubmits it. `RequestTracker` detects duplicate `nonce` and `request_id`. Request rejected with HTTP 409 Conflict without re-executing backend. | **`BLOCKED (REPLAY_DETECTED)`** |

---

### Pillar 4: Stateful Cumulative Limits & Velocity Controls (`V4-ADV-022`)

Addresses micro-transaction smurfing and structuring evasion where an adversary splits a large unauthorized amount into multiple small sub-threshold tranches.

| Check | Scenario | Amount | Rolling Window Volume | Enforcement Outcome |
| :---: | :--- | :---: | :---: | :--- |
| **4.1** | **Routine Split Tranche 1** | $2,500.00 | $2,500.00 / $5,000.00 | **`ALLOWED (EXECUTED)`** — Within single cap and cumulative threshold. |
| **4.2** | **Routine Split Tranche 2** | $2,499.00 | $4,999.00 / $5,000.00 | **`ALLOWED (EXECUTED)`** — Cumulative total reaches $4,999.00 ($1.00 below review trigger). |
| **4.3** | **Structuring Tranche 3 (Smurfing Trigger)** | $500.00 | $5,499.00 > $5,000.00 | **`PENDING_HUMAN_APPROVAL (CUMULATIVE_APPROVAL_REQUIRED)`** — Single amount ($500) is small, but rolling total ($5,499) breaches $5,000 threshold. Execution halted for human sign-off. |
| **4.4** | **Excessive Cumulative Volume Tranche** | $6,000.00 | $10,999.00 > $10,000.00 | **`BLOCKED (CUMULATIVE_LIMIT_EXCEEDED)`** — Single amount ($6,000) is below $10,000 single cap, but rolling total ($10,999) breaches `cumulative_maximum_amount` ($10,000). Blocked fail-closed. |
| **4.5** | **Benchmark V4-ADV-022 Structuring Heuristic Defense** | $4,999.99 | Smurfing Text Scan | **`FLAGGED (Risk Score: 85.0)`** — `PromptInjectionGuard` scans request memo and flags evasion patterns (`avoiding $5,000 review trigger`, `split tranche`). Layer 2 policy ensures zero unauthorized side-effects. |

---

### Pillar 5: Tamper-Evident Off-Chain Evidence & Merkle Ledger Provenance

Provides mathematical proof of execution integrity, offline auditability, and fault-tolerant consensus reconciliation.

| Check | Scenario | Threat Vector | Enforcement Mechanism | Result |
| :---: | :--- | :--- | :--- | :---: |
| **5.1** | **Deterministic Evidence Generation & Ledger Commit** | Post-hoc repudiation of transaction parameters | Gateway computes deterministic SHA-256 digest over request payload and execution response, storing raw JSON off-chain and anchoring digest to Hyperledger Fabric block ledger. | **`COMMITTED (Block Indexed)`** |
| **5.2 - 5.3** | **Database Tampering Attack & Audit Verification** | Rogue DBA altering records in traditional SQL database | Rogue administrator modifies stored off-chain amount from $4,200 to $999,999.00. Auditor recalculates SHA-256 digest and compares against immutable blockchain block hash. Hash mismatch immediately triggers `TAMPERING_DETECTED`. | **`TAMPERING_DETECTED (Verified=False)`** |
| **5.4** | **Orderer Partition & Durable Dead-Letter Queue (DLQ) Recovery** | Network split / Fabric consensus crash | Fabric orderer simulated partition. API execution response preserved off-chain and queued in durable transactional outbox. Upon network restoration, retry worker flushes transaction to blockchain without duplicating API calls. | **`RECOVERED (RETRY_SUCCESSFUL)`** |

---

## 💻 Sample Console Output

```text
===============================================================================================
  🛡️  AGENTTRUST ENTERPRISE AI GOVERNANCE — PRODUCTION DEMONSTRATION
     Version: 1.0.0 (General Availability) | Topology: Ephemeral Isolated Sandbox
===============================================================================================
  System Timestamp : 2026-10-27T09:47:07.389984+00:00
  Initializing Cryptographic Authority, Policy Engine, Gateway & Ledger...

  ✔ Registered Agent : FINANCE-AGENT-001 (X.509 PKI Fingerprint: SHA256:C44604E385EA86F05...)
  ✔ Configured Policy: Single Cap = $10,000 | Cumulative Threshold = $5,000 | Cumulative Cap = $10,000

▶ PILLAR 1: CRYPTOGRAPHIC AGENT IDENTITY & PKI NON-REPUDIATION
  Objective: Enforcing X.509 certificate chains, 2048-bit RSA digital signatures, and dynamic CRL revocation
-----------------------------------------------------------------------------------------------

  [1.1] Legitimate Request Signed with Registered Private Key
  ├── Status      : ALLOWED (EXECUTED)
  ├── Metrics     : Amount: $2,500.00 | Block #1 Committed
  └── Enforcement : X.509 certificate verified, RSA-PSS signature matched canonical payload bytes, executed on protected API.

  [1.2] Adversarial Payload Tampering / Forged Digital Signature
  ├── Status      : BLOCKED (INVALID_SIGNATURE)
  ├── Metrics     : Threat Vector: In-Transit Tampering | HTTP 401
  └── Enforcement : Gateway Stage 3 cryptographic verification detected mismatched digital signature. Rejected before policy or execution.

  [1.3] Revoked Agent Certificate Execution Attempt (CRL Defense)
  ├── Status      : BLOCKED (CERTIFICATE_REVOKED)
  ├── Metrics     : Lifecycle State: REVOKED | CRL Match: True
  └── Enforcement : Gateway Stage 2 checked CRL store; detected revoked X.509 serial. Blocked fail-closed instantly.

  [1.4] Unregistered Autonomous Agent Invocation
  ├── Status      : BLOCKED (UNKNOWN_AGENT)
  ├── Metrics     : Identity Status: UNREGISTERED | HTTP 403
  └── Enforcement : Agent ID not found in identity registry. Prevented from accessing protected enterprise resources.

▶ PILLAR 2: BOUNDED POLICY AUTHORIZATION & HUMAN-IN-THE-LOOP DUAL CUSTODY
  Objective: Enforcing multi-attribute limits, single-transaction monetary caps, and TOCTOU-protected supervisor approvals
-----------------------------------------------------------------------------------------------

  [2.1] Single-Transaction Policy Cap Breach ($50,000 > $10,000 Limit)
  ├── Status      : BLOCKED (AUTHORITY_LIMIT_EXCEEDED)
  ├── Metrics     : Requested: $50,000.00 | Policy Limit: $10,000.00
  └── Enforcement : Action Gateway Stage 7 evaluated maximum_amount rule. Transaction halted without external side effects.

  [2.2] High-Value Transaction Routing to Human Review & TOCTOU Resumption
  ├── Status      : ALLOWED_AFTER_APPROVAL (EXECUTED)
  ├── Metrics     : Requested: $12,500.00 | Approval Ticket: APPR-REQ-101
  └── Enforcement : Transaction exceeding $5,000 threshold was routed to human review queue. Once signed off by CFO, gateway verified certificate non-revocation, re-checked policy invariants, and executed downstream API call with cryptographic receipt.

▶ PILLAR 3: NONCE FRESHNESS & REPLAY ATTACK DEFENSE
  Objective: Preventing duplicate double-spend attacks and out-of-order execution using atomic nonce tracking
-----------------------------------------------------------------------------------------------

  [3.1] Initial Legitimate Action Submission
  ├── Status      : ALLOWED (EXECUTED)
  ├── Metrics     : Nonce: NONCE-REPLAY-01-043a9b | Request ID: REQ-REPLAY-01-d331cc
  └── Enforcement : Request executed cleanly and nonce recorded into RequestTracker.

  [3.2] Adversarial Replay Attack (Duplicate Packet Re-Transmission)
  ├── Status      : BLOCKED (REPLAY_DETECTED)
  ├── Metrics     : Duplicate Nonce Intercepted | HTTP 409 Conflict
  └── Enforcement : RequestTracker detected previously consumed nonce and request_id within the 300s window. Blocked without re-executing API.

▶ PILLAR 4: STATEFUL CUMULATIVE LIMITS & VELOCITY CONTROLS (SMURFING RESOLUTION)
  Objective: Preventing structured micro-transaction smurfing evasion across rolling 1-hour time windows
-----------------------------------------------------------------------------------------------

  [4.1] Routine Split Tranche 1 ($2,500.00)
  ├── Status      : ALLOWED (EXECUTED)
  ├── Metrics     : Rolling Window Volume: $2,500.00 / $5,000.00 Threshold
  └── Enforcement : Within single cap and cumulative threshold. Executed on protected financial backend.

  [4.2] Routine Split Tranche 2 ($2,499.00)
  ├── Status      : ALLOWED (EXECUTED)
  ├── Metrics     : Rolling Window Volume: $4,999.00 / $5,000.00 Threshold
  └── Enforcement : Cumulative total reaches $4,999.00 ($1.00 below threshold). Executed cleanly.

  [4.3] Structuring Tranche 3 ($500.00 — Cumulative Review Trigger)
  ├── Status      : PENDING_HUMAN_APPROVAL (CUMULATIVE_APPROVAL_REQUIRED)
  ├── Metrics     : Projected Volume: $5,499.00 > $5,000.00 Review Trigger
  └── Enforcement : Single amount ($500) is small, but cumulative total ($5,499) breaches $5,000 threshold. Gateway halts execution and requires human supervisor approval.

  [4.4] Excessive Cumulative Volume Tranche ($6,000.00 — Hard Cap Breach)
  ├── Status      : BLOCKED (CUMULATIVE_LIMIT_EXCEEDED)
  ├── Metrics     : Projected Volume: $10,999.00 > $10,000.00 Cumulative Cap
  └── Enforcement : Single amount ($6,000) is below $10,000 single cap, but cumulative total ($10,999) violates cumulative_maximum_amount ($10,000). Gateway blocks execution fail-closed.

  [4.5] Empirical Benchmark V4-ADV-022 Structuring Heuristic Defense
  ├── Status      : FLAGGED (Risk Score: 85.0)
  ├── Metrics     : Matched Regexes: 3 | Structuring Detected: True
  └── Enforcement : PromptInjectionGuard analyzed request memo; identified structuring patterns: ['avoiding\\s+\\$?\\d+.*(?:trigger|limit|review|threshold)', 'split\\s+(?:reimbursement|payment|transfer|invoice)\\s+tranche', 'tranche\\s+\\d+\\s+of\\s+\\d+']. Escalated risk score guarantees Layer 2 containment.

▶ PILLAR 5: TAMPER-EVIDENT OFF-CHAIN EVIDENCE & MERKLE LEDGER PROVENANCE
  Objective: Generating SHA-256 evidence digests, detecting post-facto database modifications, and outbox failure recovery
-----------------------------------------------------------------------------------------------

  [5.1] Deterministic Off-Chain Evidence Generation & Ledger Anchoring
  ├── Status      : COMMITTED (Block #11)
  ├── Metrics     : Evidence ID: EVIDENCE-REQ-AUDIT-01-cdc18b | Hash: d72d251fe096d59c441fa35f...
  └── Enforcement : Request payload and API execution response hashed into canonical SHA-256 digest and committed to block ledger.

  [5.2 - 5.3] Database Tampering Attack & On-Chain Audit Verification
  ├── Status      : TAMPERING_DETECTED (Verified=False)
  ├── Metrics     : Tamper Detection: 100% Certainty | Hash Mismatch: True
  └── Enforcement : Rogue DBA modified stored off-chain amount to $999,999.00. Auditor recalculated SHA-256 digest (97a1742828a5dd6c...) and compared it against the immutable blockchain block (d72d251fe096d59c...). Tampering was mathematically flagged.

  [5.4] Fabric Orderer Partition & Durable Dead-Letter Queue (DLQ) Reconciliation
  ├── Status      : RECOVERED (RETRY_SUCCESSFUL)
  ├── Metrics     : Zero Side-Effect Loss | Outbox Reconciled: True
  └── Enforcement : Orderer connection failed during block commit. Action execution was safely preserved off-chain and queued in the durable outbox. Upon network reconnection, background worker flushed transaction onto the blockchain.

===============================================================================================
  🛡️  LIVE DEMONSTRATION SUCCESSFULLY COMPLETED (16/16 CHECKS PASSED)
     Verified: Identity Verification ✔ | Policy Enforcement ✔ | Replay Defense ✔ | Cumulative Limits ✔ | Tamper Evidence ✔
===============================================================================================
```

---

## 🔒 Baseline Purity Verification

After running the demonstration, verify that zero test pollution was committed to the primary demo database:

```bash
python inspect_agenttrust_demo_db.py
```

Expected output:
```text
============================================================
INSPECTION PASSED: Database matches clean demo baseline perfectly.
```
