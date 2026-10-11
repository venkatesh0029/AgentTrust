# AgentTrust — Threat Model & Production Release Criteria

## 1. Protected Assets & Security Invariants

AgentTrust protects critical enterprise assets and distributed state machines when autonomous AI agents interact with high-value infrastructure:

| Asset | Description | Security Invariant |
|---|---|---|
| **Financial Reserves & Protected APIs** | Corporate treasury, procurement budgets, fund transfers, and vendor payments. | No unauthorized, unbudgeted, or unauthenticated transfer may execute. Strict at-most-once execution. |
| **Agent Cryptographic Identity** | Private RSA signing keys, X.509 certificates, and gateway service credentials. | Non-extractable (`CKA_EXTRACTABLE=FALSE`, `CKA_SENSITIVE=TRUE`), non-forgeable, revocable via CRL. |
| **Transaction Intents & Concurrency Leases** | Persistent SQLite state machine and in-flight lock records. | Leases are bound to monotonic fencing tokens; stale lease holders are rejected at side-effect boundaries. |
| **Audit Ledger & Evidence Integrity** | Off-chain SHA-256 evidence digests and permissioned blockchain blocks. | Immutable hash chains; tamper-evident with sequence gap detection; verifiable Merkle roots. |

---

## 2. Trust Boundaries & Architectural Topology

```text
  [ External User / Untrusted LLM Prompt ]
                     │
                     ▼
        [ Autonomous AI Agent ]  <─── (Semi-Trusted: Constrained by Policy & Cert)
                     │
        ┌────────────┴──────────────────────────────┐
        │ Trust Boundary 1: Ingestion Gateway       │
        ▼                                           ▼
[ Format & Schema ]                       [ X.509 & RSA Sig Verification ]
        │                                           │
        └────────────┬──────────────────────────────┘
                     │
        ┌────────────┴──────────────────────────────┐
        │ Trust Boundary 2: Replay & Policy Engine  │
        ▼                                           ▼
[ 300s Timestamp + SQLite Nonce ]          [ Maximum Authority & Working Hours ]
        │                                           │
        └────────────┬──────────────────────────────┘
                     │
        ┌────────────┴──────────────────────────────┐
        │ Trust Boundary 3: Concurrency & Fencing   │
        ▼                                           ▼
[ SQLite In-Flight Lock Lease ]             [ Monotonic Fencing Token (Check A) ]
        │                                           │
        └────────────┬──────────────────────────────┘
                     │
        ┌────────────┴──────────────────────────────┐
        │ Trust Boundary 4: Side-Effect Execution   │
        ▼                                           ▼
[ Signed mTLS / Service Headers ]          [ Protected Finance API (Checks Fencing) ]
        │                                           │
        └────────────┬──────────────────────────────┘
                     │
        ┌────────────┴──────────────────────────────┐
        │ Trust Boundary 5: Audit & Reconciliation  │
        ▼                                           ▼
[ Hash-Chain Evidence Store ]              [ Hyperledger Fabric Block Ledger ]
```

---

## 3. Attacker Capabilities & Threat Vectors

### 3.1. Adversarial AI Agents & Compromised LLMs
- **Capability**: Agent prompts may be manipulated via prompt injection, role-play jailbreaks, unicode homoglyphs, or invisible character payloads to request unauthorized fund transfers.
- **Mitigation**: Dual-layer defense. The pattern guardrail provides fast pre-filtering, while the **Policy Engine enforces hard cryptographic and budgetary limits independently of prompt content**. Even if an injection is completely missed by pattern filters, unauthorized amounts and actions are unconditionally blocked.

### 3.2. Concurrency Racing & Multi-Process Double Spending
- **Capability**: Attacker simultaneously spawns independent operating-system processes submitting the same request or conflicting idempotency keys.
- **Mitigation**: SQLite WAL immediate transactions (`BEGIN IMMEDIATE`) atomically acquire persistent in-flight locks. Only one process acquires the lease; all racing processes are rejected with `CONCURRENT_IDEMPOTENCY_CONFLICT`.

### 3.3. Stale Worker / Zombie Process Resumption (Split-Brain)
- **Capability**: Worker 1 acquires lock, verifies authorization, and pauses (e.g., GC pause or container freeze). Worker 1 loses its lease to Worker 2. Worker 1 resumes and attempts executing the side-effect.
- **Mitigation**: Monotonic fencing tokens. Worker 2 increments the fencing token (`token = 2`). When Worker 1 resumes with `token = 1`, both the gateway pre-execution check and the downstream `ProtectedFinanceAPI` boundary reject the side effect with `STALE_FENCING_TOKEN`.

### 3.4. Sub-Cent & Floating-Point Precision Exploitation
- **Capability**: Submitting non-canonical amounts (`1200.0001` vs `1200.0002` or excess decimals like `100.505` on a 2-decimal USD account) to induce penny-shaving or bypass authorization checks.
- **Mitigation**: Integer minor-unit canonicalization (`ActionGateway.canonicalize_financial_amount`). Currency-specific precision scales are strictly enforced (USD/EUR: 2, JPY: 0, BHD: 3). Excess precision is rejected under documented policy. Zero floating-point conversion occurs between policy approval and API execution.

### 3.5. Direct Downstream API Bypass
- **Capability**: Attacker probes internal network to call `ProtectedFinanceAPI` directly, bypassing the Action Gateway.
- **Mitigation**: `ProtectedFinanceAPI` requires both the internal gateway shared secret AND a valid RSA digital signature generated by the Gateway Service private key. Direct requests receive `DIRECT_ACCESS_DENIED`.

---

## 4. Operational Assumptions & Known Limitations

1. **Single-Host Coordination Scope**:
   - Concurrency locking, replay nonces, and WAL modes rely on SQLite OS-level file locking on a single machine.
   - **Explicit Limitation**: SQLite is NOT a multi-host distributed lock manager. Deploying across multiple distinct servers requires replacing the SQLite lease layer with a distributed consensus store (e.g., etcd, Raft, Consul).
2. **Clock Semantics**:
   - Leases and request windows use UTC wall-clock epoch timestamps (`datetime.datetime.now(datetime.timezone.utc).timestamp()`).
   - Timestamps are persisted across machine restarts.
   - Single-host assumptions rely on monotonic time synchronization. Multi-host deployments are vulnerable to NTP clock drift unless bounded by hardware clocks (e.g. TrueTime).
3. **Downstream Idempotency Assumptions**:
   - The gateway guarantees at-most-once execution against downstream APIs.
   - If downstream services do not support idempotent deduplication keys or fencing tokens, network partitions during external API calls can result in indeterminate outcomes requiring manual status reconciliation.

---

## 5. Production Release Criteria & Circuit Breakers

### 5.1. Mandatory Circuit Breakers (Zero-Tolerance Emergency Stop)
Transaction processing MUST immediately halt and trip the emergency circuit breaker upon encountering any of the following conditions:

| Trigger Event | Severity | Action Required |
|---|---|---|
| **Database Corruption Detected** | CRITICAL | Immediately stop gateway ingestion. Refuse new intents. Alert SecOps for database snapshot recovery. |
| **Monotonic Fencing Inversion** | CRITICAL | Stale token detected attempting execution after higher token accepted. Halt processing for affected account. |
| **Idempotency Payload Mismatch** | HIGH | Request payload fingerprint does not match existing idempotency key. Block request, alert security monitoring. |
| **Outbox DLQ Overflow (> 100 items)** | HIGH | Pause automated retries. Halt high-volume transfers. Investigate downstream ledger peer connectivity. |
| **CRL / Root CA Expiration** | HIGH | Reject all agent requests until Certificate Authority updates CRL and issues valid certificates. |

### 5.2. Go / No-Go Release Checklist
Before promoting any release to production:
- [x] Full automated test suite passes with zero failures (`155 passed, 2 skipped`).
- [x] Ruff linting clean with 0 warnings or errors.
- [x] Mypy strict type checking clean across all source files.
- [x] Real OS multiprocess stress tests pass with 0 duplicate executions.
- [x] Side-effect boundary enforces fencing tokens against stale workers.
- [x] Currency-specific precision scales reject excess fractional amounts.
- [x] Clean reproducibility guide and automated verification script verified.
- [x] Simulated integration clearly demarcated from live Hyperledger Fabric testnet.
