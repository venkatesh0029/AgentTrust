# AgentTrust REST API Specification

## System Information & Health
- **Base URL**: `http://127.0.0.1:8000`
- **Specification**: OpenAPI 3.0 (FastAPI)

---

## 1. Operational Mode Management
### `GET /mode`
Returns current active operational mode and list of available modes.

### `POST /mode`
Sets active operational mode.
**Payload**:
```json
{
  "mode": "MODE_D_AGENTTRUST_FABRIC"
}
```

---

## 2. Agent Identity & Lifecycle APIs

### `POST /agents/register`
Registers a new AI agent and issues an X.509 Certificate and RSA Keypair.
**Headers**: `X-Admin-Role: SYSTEM_ADMIN`
**Payload**:
```json
{
  "agent_id": "PROCUREMENT-AGENT-001",
  "agent_name": "ProcurementAgent",
  "owner": "Procurement Dept",
  "capabilities": ["CREATE_PURCHASE_ORDER", "TRANSFER_FUNDS"],
  "policy_id": "PROC-POLICY-001",
  "agent_version": "1.0",
  "organization": "OrgA",
  "role": "procurement_agent"
}
```

### `GET /agents`
Lists all registered AI agents.

### `GET /agents/{agent_id}`
Returns identity details and public key for a specific agent.

### `POST /agents/{agent_id}/rotate-key`
Rotates an agent's cryptographic key pair and increments `key_version`.

### `POST /agents/{agent_id}/suspend`
Suspends an active agent (`ACTIVE` -> `SUSPENDED`).

### `POST /agents/{agent_id}/reactivate`
Reactivates a suspended agent (`SUSPENDED` -> `ACTIVE`).

### `POST /agents/{agent_id}/revoke`
Revokes an agent certificate (`ACTIVE` -> `REVOKED`).

### `DELETE /agents/{agent_id}`
Deactivates and removes an agent record.

---

## 3. Action Gateway Submission

### `POST /actions/submit`
Submits a digitally signed agent request to the Action Gateway.
**Payload**:
```json
{
  "request_id": "REQ-1001",
  "agent_id": "FINANCE-AGENT-001",
  "action": "CREATE_PURCHASE_ORDER",
  "resource": "SUPPLIER-101",
  "parameters": {
    "item_name": "High-Performance Workstations",
    "quantity": 5,
    "amount": 25000.0
  },
  "amount": 25000.0,
  "nonce": "N-UNIQUE-NONCE-01",
  "timestamp": "2026-09-15T18:00:00Z",
  "key_version": 1,
  "idempotency_key": "IDEMP-PO-1001",
  "signature": "<B64_RSA_SIGNATURE>"
}
```

---

## 4. Helper Domain Endpoints
### `POST /purchase-orders`
Helper endpoint to create purchase orders (automatically signs request with registered agent key).

### `POST /fund-transfers`
Helper endpoint to execute fund transfers (automatically signs request with registered agent key).

---

## 5. Human Approval Endpoints
### `GET /approvals/pending`
Lists all transactions currently held for human approval.

### `POST /approvals/{approval_id}/approve`
Approves a pending request and resumes gateway execution.

### `POST /approvals/grant`
Alias endpoint for granting human approval.

### `POST /approvals/{approval_id}/reject`
Rejects a pending request.

---

## 6. Audit Chain & Hyperledger Fabric APIs
### `GET /audit/chain`
Returns the in-memory Audit Hash Chain records.

### `GET /audit/chain/verify`
Verifies integrity of the Audit Hash Chain.

### `POST /audit/chain/simulate-tamper`
Simulates historical record tampering for research verification.

### `POST /fabric/record-evidence`
Records evidence hash on Hyperledger Fabric ledger.

### `GET /fabric/evidence/{request_id}`
Retrieves evidence hash from Fabric chaincode.

### `POST /fabric/verify-evidence`
Verifies off-chain evidence hash against Fabric ledger record.

---

## 7. Attack Matrix & Performance Benchmarks
### `GET /scenarios/attack-matrix`
Returns metadata for all 20 attack lab scenarios.

### `POST /scenarios/attack-matrix/run-all`
Runs all 20 attack simulations and returns pass/fail matrix.

### `POST /benchmark/run`
Triggers full performance benchmark suite (stage latencies, 1–100 agent concurrency scale, ablation study).
