# AgentTrust Formal Security Model & Invariants

AgentTrust provides cryptographically verifiable, policy-bounded, and tamper-evident guarantees for autonomous AI agents.

## Security Guarantees & Properties

| Property | Formal Guarantee | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Authentication** | Only registered agents with valid X.509 certs and RSA signatures are accepted. | Root CA cert verification + RSA-PSS Signature Manager |
| **Bounded Authorization** | Requests are denied unless active policy permits action, resource, amount & working hours. | Policy Engine rule evaluator + Conflict Resolver |
| **Least Privilege** | Agents receive strictly bounded permissions and authority limits. | Fine-grained Policy schema (`maximum_amount`, `allowed_resource`) |
| **Non-Repudiation** | Every action request is cryptographically bound to agent identity. | RSA 2048 Digital Signatures on canonical payloads |
| **Replay Resistance** | Reused request IDs, nonces, or expired requests are rejected. | RequestTracker, NonceManager & TimestampValidator |
| **Execution Isolation** | Protected APIs accept calls strictly from the mandatory Gateway. | Gateway Service-to-Service Signed Headers & Token |
| **Evidence Integrity** | Modified off-chain evidence produces an immediate hash mismatch. | Deterministic SHA-256 Canonical Evidence Hashing |
| **Auditability** | All decisions (allowed & blocked) generate traceable ledger events. | Hyperledger Fabric Chaincode & Ledger Engine |
| **Administrative Security** | Administrative actions are restricted by role permissions. | Admin RBAC Manager (`SYSTEM_ADMIN`, `POLICY_ADMIN`, etc.) |
| **Failure Safety** | Evidence is preserved safely if ledger commitment fails. | Failure Recovery Retry Queue & Dead-Letter Queue (DLQ) |

## Formal Security Invariants

- **Invariant 1**: A protected API must never execute an unauthorized request.
- **Invariant 2**: A revoked or suspended agent must never execute a new action.
- **Invariant 3**: Every executed action must have a corresponding audit event and evidence payload.
- **Invariant 4**: Every audit event must reference a verifiable SHA-256 evidence hash.
- **Invariant 5**: A replayed request (same request ID or nonce) must never execute twice.
- **Invariant 6**: Only authorized administrators with proper RBAC roles may modify policies, roll back policies, or alter agent lifecycle states.
