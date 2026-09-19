# AgentTrust REST API Specification

## 1. Agent Management APIs

### `POST /agents/register`
Registers a new autonomous AI Agent and issues X.509 certificate.
- **Request Body**:
  ```json
  {
    "agent_id": "FINANCE-AGENT-001",
    "agent_name": "FinanceAgent",
    "owner": "Finance Department",
    "capabilities": ["CREATE_REIMBURSEMENT"],
    "policy_id": "FIN-POLICY-001"
  }
  ```
- **Response**: `200 OK` with certificate fingerprint, public key, and private key.

### `GET /agents`
Lists all registered AI Agents.

### `PATCH /agents/{agent_id}/status`
Updates operational status (ACTIVE, SUSPENDED, REVOKED, EXPIRED).

### `POST /agents/{agent_id}/revoke`
Revokes X.509 certificate for specified agent.

---

## 2. Policy Engine APIs

### `POST /policies`
Creates a fine-grained authorization policy.
- **Request Body**:
  ```json
  {
    "policy_id": "FIN-POLICY-001",
    "agent_id": "FINANCE-AGENT-001",
    "allowed_actions": ["CREATE_REIMBURSEMENT"],
    "allowed_resource": "FINANCE_API",
    "maximum_amount": 10000.0,
    "human_approval_above": 10000.0,
    "working_hours_start": "09:00",
    "working_hours_end": "18:00",
    "version": "1.0"
  }
  ```

---

## 3. Action Gateway APIs

### `POST /actions/submit`
Mandatory entry point for submitting signed AI agent action requests.
- **Request Body**:
  ```json
  {
    "request_id": "REQ-1001",
    "agent_id": "FINANCE-AGENT-001",
    "action": "CREATE_REIMBURSEMENT",
    "resource": "FINANCE_API",
    "parameters": { "employee_id": "EMP-001", "amount": 7500.0 },
    "nonce": "N-847291",
    "timestamp": "2026-09-12T10:30:00Z",
    "signature": "BASE64_RSA_SIGNATURE"
  }
  ```
- **Response**: Gateway decision (`ALLOWED`, `BLOCKED`, `PENDING_HUMAN_APPROVAL`), protected API result, evidence hash, and Hyperledger Fabric block details.

---

## 4. Human Approval APIs

### `GET /approvals/pending`
Lists all high-risk transactions waiting for human sign-off.

### `POST /approvals/{approval_id}/approve`
Approves ticket and executes protected transaction.

### `POST /approvals/{approval_id}/reject`
Rejects transaction request.

---

## 5. Evidence & Tamper Detection APIs

### `POST /evidence/{evidence_id}/verify`
Compares off-chain evidence SHA-256 hash against Hyperledger Fabric ledger record.

### `POST /evidence/{evidence_id}/simulate-tamper`
Modifies off-chain evidence data to test tamper detection (`TAMPERING_DETECTED`).

---

## 6. Audit & Blockchain APIs

### `GET /audit/events`
Returns transaction history stored in Hyperledger Fabric chaincode.

### `GET /audit/blockchain/blocks`
Returns complete block list from permissioned ledger.
