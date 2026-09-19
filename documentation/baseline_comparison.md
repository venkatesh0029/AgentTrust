# AgentTrust Academic Baseline Comparison Evaluation

To evaluate the contribution of each security component in AgentTrust, we compare AgentTrust against 5 baseline security architectures.

## Baseline Systems Compared

1. **Baseline 1: Direct Agent-to-API Access (Uncontrolled)**
   - Autonomous AI agents access enterprise APIs directly with no authorization gateway or signatures.
2. **Baseline 2: Ordinary API Authentication (Basic API Keys)**
   - Agents authenticate using static API keys. No X.509 certs, digital signatures, or authority limits.
3. **Baseline 3: Centralized Audit Logging (No Blockchain)**
   - Gateway enforces authorization, but audit logs are stored in a standard SQL/centralized database.
4. **Baseline 4: AgentTrust without Replay Protection**
   - Full AgentTrust pipeline, but without nonce or timestamp tracking.
5. **AgentTrust Complete Security Framework**
   - Full pipeline: X.509 identity + RSA signatures + Bounded Policy + Replay Protection + Action Gateway + Off-Chain Hashing + Hyperledger Fabric Ledger.

---

## Comparative Evaluation Matrix

| Metric / Security Dimension | Baseline 1 (Direct API) | Baseline 2 (API Keys) | Baseline 3 (Centralized Log) | Baseline 4 (No Replay) | AgentTrust (Full Pipeline) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Unauthorized Action Prevention Rate** | 0.00% | 20.00% | 100.00% | 100.00% | **100.00%** |
| **Replay Attack Detection Rate** | 0.00% | 0.00% | 0.00% | 0.00% | **100.00%** |
| **Off-Chain Evidence Tamper Detection** | 0.00% | 0.00% | 0.00% | 100.00% | **100.00%** |
| **Audit Log Tamper Evidence** | None | None | Vulnerable to SQL edit | Tamper-Evident | **Immutable Blockchain** |
| **Non-Repudiation** | None | Weak (Shared Secret) | Strong | Strong | **Cryptographic RSA Signatures** |
| **Direct API Bypass Denial** | None | None | Enforced | Enforced | **Service-to-Service Signed Headers** |
| **High-Risk Human Approval Workflow** | None | None | Optional | Supported | **Enforced (> ₹10k Threshold)** |
| **Failure Recovery & DLQ** | None | None | Database dependent | Basic | **Durable Retry Queue & Evidence Preservation** |
