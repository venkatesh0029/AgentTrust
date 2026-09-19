# AgentTrust Threat Model & Security Boundaries

## 1. Threat Environment & Adversary Assumptions

AgentTrust assumes a zero-trust execution environment where AI agents act autonomously but may experience model hallucinations, key compromise, prompt injection attacks, or adversary tampering.

### Adversary Capabilities
1. **Network Interceptor**: Can inspect, drop, or replay network traffic.
2. **Malicious / Compromised Agent**: Possesses an agent's private key (or stolen key) and attempts unauthorized or high-value transactions.
3. **Malicious Client**: Attempts payload tampering, client-side risk score injection, or approval status parameter manipulation.
4. **Untrusted Off-Chain Storage**: Off-chain evidence storage (database or filesystem) may be tampered with or corrupted.
5. **Unauthorized Ledger Invoker**: External entities attempting unauthorized writes to the Hyperledger Fabric ledger.

---

## 2. Threat Matrix & Countermeasures

| Threat ID | Threat Description | Attack Vector | AgentTrust Countermeasure | Tested In |
|---|---|---|---|---|
| **T-01** | Identity Forgery | Attacker submits unsigned or fake signature | RSA SHA-256 verification against registered public key | Attack #1 |
| **T-02** | Payload Modification | Attacker modifies amount or parameters after signing | JCS SHA-256 signature verification invalidation | Attack #2 |
| **T-03** | Replay Attack | Attacker resubmits recorded valid transaction | RequestTracker nonce tracking + 300s window | Attack #3 |
| **T-04** | Stale / Expired Request | Attacker submits old request after timestamp window | Strict timestamp freshness evaluation (<=300s) | Attack #4 |
| **T-05** | Duplicate Execution | Autonomous agent retries failed call creating double PO | Idempotency key tracking in Protected API | Attack #5 |
| **T-06** | Compromised Agent Action | Revoked agent attempts to execute action | StatusManager instant revocation check | Attack #6 |
| **T-07** | Suspended Agent Action | Agent under investigation attempts action | StatusManager instant suspension check | Attack #7 |
| **T-08** | Unauthorized Function | Agent attempts unauthorized action (`DELETE_ACCOUNT`) | Explicit policy allowlist check | Attack #8 |
| **T-09** | Authority Limit Bypass | Agent attempts high-value PO exceeding limit | Strict policy numeric boundary enforcement | Attack #9 |
| **T-10** | Risk Score Injection | Client includes `"risk_score": 0` in request | Server-side trusted RiskEvaluator strictly overrides | Attack #10 |
| **T-11** | Approval Flag Injection | Client includes `"approved": true` in payload | Gateway ignores client flags; enforces ticket | Attack #11 |
| **T-12** | Approval Token Replay | Attacker reuses single-use approval token | ApprovalManager single-use token tracking | Attack #12 |
| **T-13** | Approval Substitution | Attacker uses token from Request A on Request B | Token HMAC hash bound to `request_id` | Attack #13 |
| **T-14** | Post-Approval Tamper | Attacker modifies PO amount after human approval | Signature verification fails upon resume | Attack #14 |
| **T-15** | Direct API Bypass | Attacker calls Protected API directly, bypassing Gateway | Secret gateway token + signed header enforcement | Attack #15 |
| **T-16** | Off-Chain Data Tamper | Attacker alters database evidence record | Fabric ledger SHA-256 hash comparison | Attack #16 |
| **T-17** | Audit Chain Tamper | Attacker alters historical record in audit log | Sequence & previous hash broken link detection | Attack #17 |
| **T-18** | Ledger Write Forgery | Unauthorized caller calls Fabric chaincode write | Caller MSP authorization check (`Org1MSP`) | Attack #18 |
| **T-19** | Compromised Key Reuse | Attacker uses old key after key rotation | Key version check (`key_version` mismatch) | Attack #19 |
| **T-20** | Concurrency Race | Race condition during simultaneous multi-agent writes | Thread-locked atomic sequence counter | Attack #20 |

---

## 3. Trust Boundaries
- **Trusted Component**: Action Gateway, Risk Engine, Policy Evaluator, Human Approval Manager, Audit Chain Writer, Hyperledger Fabric Chaincode.
- **Untrusted Component**: Agent clients, network transport, external database storage, client-side input parameters.
