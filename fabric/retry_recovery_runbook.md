# AgentTrust Retry and Reconciliation Recovery Runbook

## 1. Purpose
This runbook describes how to investigate and recover retry records when an external Fabric write has an uncertain outcome, retry finalization fails, ledger reconciliation detects a conflict, or persistent state cannot be read.

The primary safety objective is to avoid treating an uncertain external outcome as proof that no write occurred.

## 2. Core Operating Rules
1. **Do not assume that lease expiry cancels an external operation.**
2. **Do not assume that a failed client request means the ledger did not commit the transaction.**
3. **Do not bypass owner and fencing-token checks to force finalization.**
4. **Do not blindly resubmit a live-mode event because a query returns no event.**
5. **Preserve retry records, ledger evidence, and error details during investigation.**
6. **If authoritative state cannot be established, preserve uncertainty and escalate rather than guessing.**

## 3. Initial Incident Triage
Record the following before taking recovery action:
- Retry event ID and associated action or agent identifier.
- Retry record status, attempt count, and dead-letter status, if applicable.
- Lease owner, lease expiration, and fencing token, when available.
- Active operating mode: simulator or live Fabric (`FABRIC_GATEWAY_MODE`).
- Last retry error and its timestamp.
- Whether a Fabric write was attempted and whether its response was definitive.
- Ledger query result, including query errors and timeouts.
- Relevant application, gateway, persistence, and Fabric logs.

> [!CAUTION]
> Protect sensitive information. Do not record PINs, private keys, authentication tokens, or other secrets in incident notes.

## 4. Recovery Decision Table

| Observed Condition | Required Response |
| :--- | :--- |
| **Persisted retry record cannot be read or decoded** | Fail closed. Investigate database availability, integrity, and logs. Do not issue a write from incomplete state. |
| **Ledger query fails or times out** | Preserve the pending record and uncertainty. Do not increment the retry count merely because reconciliation failed. Retry the query when the ledger is available. |
| **Ledger contains a matching event** | Allow normal reconciliation and fenced finalization using a valid current claim. Confirm that the event identity and expected fields match. |
| **Ledger contains an event with conflicting fields** | Keep the evidence and route the record through the guarded dead-letter path (`RETRY_FAILED: RECONCILIATION_CONFLICT`). Investigate event identity reuse, payload mismatch, and concurrent submissions. |
| **Live ledger query returns no event** | Treat the result as `RETRY_FAILED: LIVE_LEDGER_STATE_UNCERTAIN`. Do not blindly resubmit. Establish whether the query is authoritative for the relevant transaction and whether the original operation can still complete. |
| **External write succeeds but retry finalization fails** | Treat `RETRY_FAILED: FINALIZATION_ERROR_RECONCILE_REQUIRED` as an uncertain recovery state. Query the ledger by deterministic event ID before any subsequent submission. |
| **Lease is expired or superseded** | Do not finalize using a stale owner or fencing token. Reacquire a valid claim through the supported retry workflow and reconcile first. |
| **Retry reaches its configured maximum and is dead-lettered** | Preserve the record and diagnostics (`DEAD_LETTER_QUEUE`). Investigate the root cause before any authorized recovery or requeue. |

## 5. Recovery Procedure for an Uncertain Live Submission
1. **Stop unsafe resubmission**: Do not manually invoke the write path again merely because the original caller timed out or received a network disconnection.
2. **Preserve evidence**: Record the event ID, retry record payload, lease metadata, error string, and relevant timestamps.
3. **Establish ledger query health**: Confirm that the configured live ledger endpoint is reachable and that query failures or transient network partitions are not being mistaken for event absence.
4. **Query by deterministic event identity**: Use the supported reconciliation interface and authoritative ledger source (`fabric_client.get_event(event_id)`).
5. **Compare the event**: Validate all expected event fields (`request_id`, `agent_id`, `action`, `resource`, `decision`, `reason`, `policy_id`, `policy_version`, `evidence_reference`, `evidence_hash`), not just the event ID.
6. **Resolve the outcome**:
   - If a **matching event** exists, complete normal fenced reconciliation and finalization under the active claim.
   - If a **conflicting event** exists, use the guarded dead-letter workflow and investigate payload divergence.
   - If the **query fails or times out**, retain uncertainty and retry reconciliation later.
   - If the **event is absent** but the outcome remains uncertain in live mode, do not resubmit without external authoritative confirmation.
7. **Authorize any exceptional recovery explicitly**: Resubmission must follow a documented operational policy supported by verified evidence that the original operation cannot later take effect, or by a verified downstream idempotency mechanism. Do not infer this from lease expiry alone.
8. **Verify final state**: Confirm the persisted retry status in SQLite and authoritative ledger outcome, and retain all incident evidence in audit logs.

## 6. Lease Expiry and Fencing
A fencing token protects guarded database state transitions from stale workers. It does not revoke a Fabric write that was submitted before the worker lost its lease.

Pre-write validation reduces the chance of a stale worker submitting a write, but lease expiry can occur immediately after validation while the network call is in flight. Therefore, a newer lease owner must reconcile the external ledger before deciding what to do next.

> [!WARNING]
> Do not edit lease fields, reset fencing tokens, or force finalization directly in the database as a substitute for the supported claim and finalization operations.

## 7. Dead-Letter Handling
For a dead-lettered record:
1. Preserve the original record and its diagnostic fields (`payload`, `error_msg`, `retry_count`, `fencing_token`).
2. Determine whether the cause was a reconciliation conflict, repeated write failure, retry exhaustion, or an operational error.
3. Inspect the authoritative ledger before deciding whether the original action occurred.
4. Resolve conflicting event identity or payload issues before considering a new submission.
5. Use the application's supported recovery mechanism and ensure the current owner and fencing token remain valid.
6. Document the reason for recovery and the evidence used to authorize it.

> [!IMPORTANT]
> Do not silently delete a dead-letter record to make monitoring appear healthy.

## 8. Escalation Conditions
Escalate to the system maintainer when:
- Ledger state cannot be queried authoritatively.
- The same event ID appears with conflicting payloads across systems.
- The external operation may still be in flight and its final outcome cannot be established.
- Persistent retry state is corrupt or inconsistent.
- Fencing validation or finalization fails repeatedly.
- The downstream ledger's deduplication or transaction-visibility behavior is unknown.

Until the outcome is established, prefer an explicitly unresolved incident over an unsafe retry.

## 9. Reliability Limitations
AgentTrust uses leases, fencing tokens, persistent retry records, and reconciliation to reduce unsafe retries and support recovery. These mechanisms do not guarantee universal exactly-once external execution.

A safe recovery decision depends on authoritative ledger visibility, deterministic event identity, persistent state integrity, and the actual semantics of the downstream ledger.

## 10. Related Documentation
- [Project README](../README.md)
- [Security Boundary Audit](../documentation/security_boundary_audit.md)
- [System Limitations](../documentation/limitations.md)
- [Fabric Production Deployment Guide](production_deployment_guide.md)
