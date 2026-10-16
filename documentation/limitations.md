# AgentTrust System Limitations & Future Scope

## Overview
While AgentTrust provides a robust, empirical 10/10 security framework for AI procurement agents, certain architectural and operational trade-offs exist in the current research prototype.

---

## 1. System Limitations

### 1. Multi-Enterprise Fabric Consortium Simulation
- **Current State**: Hyperledger Fabric integration operates with simulated MSP authentication and in-memory ledger blocks.
- **Limitation**: Real multi-org production deployments require running gRPC Fabric Peer and Orderer Docker nodes with Raft consensus.

### 2. Risk Engine Feature Set
- **Current State**: RiskEvaluator assesses 8 rule-based risk factors (amount thresholds, resource sensitivity, off-hours execution, frequency, key version).
- **Limitation**: Machine-learning-based anomaly detection models (e.g. Isolation Forest or Autoencoders trained on historical agent trajectories) are not yet integrated into the live risk engine.

### 3. Human Approval Notification Mechanism
- **Current State**: Pending human approvals are polled via `GET /approvals/pending` and resolved through REST endpoints.
- **Limitation**: Push-based real-time notification channels (e.g. WebSockets, Slack Webhooks, or PagerDuty integration) are not configured.

### 4. Key Storage Security
- **Current State**: Agent private keys are stored in encrypted PEM format on local disk using AES-256-GCM.
- **Limitation**: High-security enterprise environments require Hardware Security Modules (HSM) or AWS KMS / HashiCorp Vault key management integrations.

### 5. In-Flight External Writes and Retry Recovery
- **Current State**: AgentTrust uses persistent retry records, worker lease acquisition with explicit TTLs, monotonic fencing tokens, and authoritative ledger queries to reconcile uncertain submission outcomes.
- **Limitation**: A retry lease governs ownership of a persistent retry record; it does not cancel an external Fabric write that is already in flight. If a lease expires while a write is pending, another worker may acquire the record even though the earlier operation can still complete.
  - Monotonic fencing tokens protect guarded persistence operations, but they cannot revoke a write already submitted to the external ledger. Pre-write lease validation reduces the race window without eliminating it.
  - AgentTrust mitigates this condition through ledger reconciliation, guarded finalization, fail-closed handling of persistence errors, and dead-letter routing for conflicting events. In live mode, an absent event is treated as uncertain, and query failures do not authorize a new write.
  - Consequently, the implementation does not guarantee universal exactly-once external execution. Recovery depends on authoritative ledger visibility, deterministic event identity, and downstream transaction semantics. If the ledger cannot resolve the outcome, the retry record must remain subject to reconciliation or operator investigation rather than being blindly resubmitted.
  - Operational recovery procedures are documented in [`../fabric/retry_recovery_runbook.md`](../fabric/retry_recovery_runbook.md).

---

## 2. Future Scope & Research Directions

1. **Hardware Security Module (HSM) Integration**: Support PKCS#11 HSM integration for hardware-isolated agent key storage.
2. **Zero-Knowledge Evidence Proofs (zk-SNARKs)**: Enable agents to prove policy compliance to external auditors without revealing underlying financial parameter values.
3. **ML-Driven Adaptive Risk Engine**: Incorporate unsupervised behavioral anomaly detection trained on agent execution embeddings.
4. **Multi-Tenant Chaincode Deployment**: Deploy live multi-peer Fabric network on Kubernetes (K8s) for cross-enterprise procurement validation.
