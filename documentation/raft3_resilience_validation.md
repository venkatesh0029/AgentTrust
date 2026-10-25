# AgentTrust Raft-3 Consensus Resilience & CCaaS Fault-Tolerance Validation (Steps 3F & 3G)

## 1. Executive Summary

This report documents the design, deployment, fault injection, and recovery validation of the isolated 3-orderer Raft consensus cluster and Chaincode-as-a-Service (CCaaS) architecture on the `agenttrust-raft3` testbed, alongside the resolution of critical authentication vulnerabilities in the published application.

All tests passed with zero ledger divergence, full fail-closed quorum behavior, seamless leader re-election, clean CCaaS reconnection, and complete isolation from the frozen `v1.0.0-rc1` single-orderer release network and demo database.

---

## 2. Complete Ledger-Height Chronology & Forensics

Each disruption, transaction invocation, and recovery step advanced the ledger on the isolated `agenttrust-raft3` application channel with matching block heights and SHA-256 block hashes across both `peer0.org1.agenttrust.com` and `peer0.org2.agenttrust.com`:

| Block Index | Ledger Height | Trigger Event / Milestone | Transaction ID / Action Event ID | Current Block Hash | Status & Forensics |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **0** | **1** | Genesis Block | Genesis config tx | `f80bb870...` | Initial channel bootstrap |
| **1** | **2** | Org1 Anchor / Definition | Org1 anchor update | `cf251761...` | Channel configuration update |
| **2** | **3** | Org2 Anchor / Definition | Org2 anchor update | `441777dc...` | Channel configuration update |
| **3** | **4** | CCaaS Commit Definition | Lifecycle commit (Seq 1) | `rMXnlndV...` | `AND('Org1MSP.peer','Org2MSP.peer')` |
| **4** | **5** | **Step 3F Smoke Test** | `EVENT-RAFT3-A12B89FC` | `fLFN+vhL3zfRGQQv+usVpb7ANiUwAsUB6BbcWwXlNkQ=` | Deterministic proposal timestamp verified |
| **5** | **6** | **Scenario A: Leader Failover** | `EVENT-RAFT3-1E42A0CC` | `VKhytwp46WQEDHJvGdRIJi2uNy3hYHveC8iw1WntHxE=` | `orderer2` stopped; `orderer3` elected leader at term 4; transaction committed |
| — | **6** | **Scenario C: Quorum Loss Probe** | `PROBE-QUORUM-LOSS-f4c46874` | *N/A (Uncommitted)* | `orderer3` stopped (1/3 online); orderer returned `SERVICE_UNAVAILABLE -- no Raft leader`. Height frozen at 6; query returned 500 Not Found |
| **6** | **7** | **Scenario D: Recovery Part 1 (Attempt 1)** | `EVENT-RAFT3-67801FB3` | `hBROTMpI6KgwEzRFGhBh268pCvd1uO6Fdphe4RwB0NE=` | `orderer3` restarted (2/3 online); transaction ordered by leader `orderer3` |
| **7** | **8** | **Scenario D: Recovery Part 1 (Attempt 2)** | `EVENT-RAFT3-1E647C25` | `6mLcT0tR0MiM0/2xdi5f4hNrSl5dd4PCO1k5N9905ew=` | Target orderer pointed to leader `orderer3`; transaction committed |
| **8** | **9** | **Scenario D: Recovery Part 2 (Full 3/3)** | `EVENT-RAFT3-ED77BD14` | `+7cKZzQyn3qsxqTxRn6+KEQKK0qNOZ2iA4k/RPSCaZU=` | `orderer2` restarted; full 3/3 cluster active; synchronized without divergence |
| **9** | **10** | **Scenario E: CCaaS Restoration** | `EVENT-RAFT3-A943E62F` | `t1d7ztw9mqg8f8czk65CCxY8LKbSUUNMTITNmqQXR+o=` | CCaaS stopped (fails closed) -> restarted -> smoke test verified |

---

## 3. Fault-Tolerance Scenario Results

### Scenario A — Leader Failover
- **Fault Injected**: Stopped active Raft leader (`agenttrust-raft3-orderer2.agenttrust.com-1`).
- **Cluster Response**: Surviving orderers (`orderer1` and `orderer3`) detected loss of leader heartbeat and held an election. `orderer3` was elected the new Raft leader at term 4 (`run -> raft.node: 1 elected leader 3 at term 4`).
- **Transaction Result**: Client submitted `RecordActionEvent` (`EVENT-RAFT3-1E42A0CC`) requiring dual endorsement `AND('Org1MSP.peer','Org2MSP.peer')`. Both peers endorsed, leader `orderer3` ordered the block, and the transaction committed as Block 5 (Height 6).

### Scenario B — Quorum Maintenance
- **Condition**: Kept `orderer2` stopped, maintaining a 2/3 active orderer majority.
- **Cluster Response**: Consensus remained fully functional. Queries for authentic evidence hash returned `VERIFIED`, while deliberately mismatched hashes returned `TAMPERING_DETECTED`.

### Scenario C — Quorum Loss (Fail-Closed Enforcement)
- **Fault Injected**: Stopped `orderer3`, leaving only `orderer1` online (1 of 3 orderers; sub-majority).
- **Cluster Response**: Orderer returned `SERVICE_UNAVAILABLE -- no Raft leader`.
- **Integrity Validation**: Bounded probe transaction `PROBE-QUORUM-LOSS-f4c46874` was submitted with a 15-second timeout. Ledger height remained at 6. Direct ledger queries confirmed the probe event was **never committed** (`status: 500, action event not found`).

### Scenario D — Cluster Recovery & Catch-up
- **Recovery Phase 1 (2/3 Quorum)**: Started `orderer3`. Cluster regained majority quorum and elected `orderer3` as leader at term 7 with active lease. Transactions resumed committing (Blocks 6 and 7).
- **Recovery Phase 2 (3/3 Full Cluster)**: Started `orderer2`. Logs confirmed `orderer2` caught up and rejoined as follower under leader `orderer3` at term 5 (`raft.node: 2 elected leader 3 at term 5`). Rerun of smoke test (`EVENT-RAFT3-ED77BD14`) committed cleanly at height 9 with matching block hashes across both peer organizations.

### Scenario E — CCaaS Container Interruption & Resilience
- **Fault Injected**: Stopped CCaaS container (`agenttrust-raft3-agenttrust-raft3-chaincode-1`).
- **Peer Response**: Chaincode invocations failed with status 500: `could not launch chaincode ... error creating grpc connection to agenttrust-raft3-chaincode:9999 ... dial tcp: lookup agenttrust-raft3-chaincode on 127.0.0.11:53: no such host`.
- **Recovery**: Restarted CCaaS container. Re-ran smoke test (`EVENT-RAFT3-A943E62F`); connection re-established, transaction committed, advancing both peers to height 10 with matching block hashes.

---

## 4. Release Candidate Isolation & Inventory Verification

The isolated Raft-3 network runs on custom bridge network `agenttrust-raft3-net` and non-conflicting host ports (15984, 16984, 17050, 18050, 19050, 17051, 19051). 

### Complete Release Network Inventory & Isolation Status (10 Containers)
The `v1.0.0-rc1` release network was strictly isolated from all fault-injection testing. 

*Operational Note on Container Restoration*: Prior to running the Raft-3 fault-tolerance experiments, a host Docker daemon restart caused 7 standalone release containers (`orderer.agenttrust.com`, `peer0.org1.agenttrust.com`, `peer0.org2.agenttrust.com`, `couchdb0.org1.agenttrust.com`, `couchdb0.org2.agenttrust.com`, `ca.org1.agenttrust.com`, `ca.org2.agenttrust.com`) to exit with exit code 255, while 3 Compose-managed containers (`fabric-fabric-gateway-bridge-1`, `fabric-agenttrust-ccaas-1`, `fabric-agenttrust-ccaas-v3-1`) remained active. All 7 containers were promptly restored via `docker start`, and all 10 containers were confirmed online and healthy via `scripts/fabric_lifecycle.py status`. Throughout the subsequent Raft consensus and CCaaS fault-injection validation, the release network remained fully isolated on `agenttrust-net` without interference.

Active Release Containers (10/10 verified healthy):
1. `ca.org1.agenttrust.com` (State: running)
2. `ca.org2.agenttrust.com` (State: running)
3. `couchdb0.org1.agenttrust.com` (State: running, Port 5984)
4. `couchdb0.org2.agenttrust.com` (State: running, Port 6984)
5. `fabric-agenttrust-ccaas-1` (State: running)
6. `fabric-agenttrust-ccaas-v3-1` (State: running)
7. `fabric-fabric-gateway-bridge-1` (State: running, Port 8090)
8. `orderer.agenttrust.com` (State: running, Port 7050)
9. `peer0.org1.agenttrust.com` (State: running, Port 7051)
10. `peer0.org2.agenttrust.com` (State: running, Port 9051)

### Demo SQLite Database State
The demo database file `agenttrust_persistent.db` remained completely untouched throughout all fault-injection tests:
- **Length**: 1,605,632 bytes
- **SHA-256**: `08BB7E04FE8BFCAAD29674931C2A3CD0F83A8BC863E9988618825BC8DECF5771`

---

## 5. Security Remediation Checkpoint (Steps 3F, 3G & Step 4 Hardening)

| Vulnerability / Milestone | Remediation | Verification |
| :--- | :--- | :--- |
| **Unauthenticated /auth/login** | Added `AdminAuthManager` in `identity_manager/admin_auth.py` with salted PBKDF2-HMAC-SHA256 hashing. Mandated password verification on login. | Verified in `tests/test_auth_security.py`. |
| **Password Hashing Strength (OWASP)** | Upgraded PBKDF2-HMAC-SHA256 from 100,000 to **600,000 iterations** in accordance with current OWASP Password Storage guidelines (FIPS-compliant work factor). Benchmarked on host: ~0.229s (229ms) per hash. Default passwords rejected in production startup. | Verified in `identity_manager/admin_auth.py` and `tests/test_auth_security.py`. |
| **JWT Secret Mathematical Entropy** | Enhanced secret validation in `identity_manager/jwt_auth.py` and `server.py` beyond minimum length. Enforced mathematical Shannon entropy ($H \ge 3.0$ bits/char), character diversity ($\ge 8$ unique characters), and repeated-pattern rejection. Predictable patterns (e.g. `'a'*32` or `'12121212'*4`) fail closed immediately. | Verified in `tests/test_production_resilience.py` (diversity, repeated patterns, entropy). |
| **Persona Switcher Security Gate** | Confirmed and enforced that the persona switcher is strictly **demo-only**: <br>1. **Server-Side**: Default demo credentials (`AdminTrust#2026!Secured`, etc.) are rejected with `RuntimeError` during production startup. No shortcut or role-selection bypass exists on the backend. `/auth/login` requires valid password.<br>2. **Frontend UI**: In production (`isDemoAuthMode() == false`), the 1-click persona switcher is completely disabled and replaced with a prominent Production Security Banner. Auto-minting and credential fallback are disabled. | Verified in `frontend/src/lib/api.ts`, `frontend/src/components/ui/auth-modal.tsx`, and `dashboard/app.js`. |
| **Role Self-Assignment** | Bound roles strictly to authenticated administrative accounts (`admin`, `policy_admin`, `finance_approver`, `auditor`). Request-supplied role parameters are ignored. | Role self-granting prevented and tested. |
| **Plaintext X-Admin-Role Escalation** | Strictly prohibited plaintext `X-Admin-Role` headers across all backend routes with HTTP 401 Unauthorized. Supported cryptographically signed JWT bearer tokens. | Regression suites passing (12/12 in `test_audit_findings_regression.py`, 7/7 in `test_delegation_api_security.py`). |
| **Frontend & Dashboard Auth Integration** | Updated `frontend/src/lib/api.ts`, `frontend/src/app/(console)/layout.tsx`, and `dashboard/app.js` to obtain tokens via `/auth/login`, store sessions in `localStorage`, and send `Authorization: Bearer <token>` for all protected endpoints. | Frontend build passing (`next build` 0 errors); zero plaintext role headers sent. |
| **Hardcoded Gateway Token** | Scrubbed hardcoded token from `scripts/test_live_fabric_integration.py` and implemented `scripts/rotate_fabric_gateway_token.ps1`. | Zero secrets tracked in git; previous token revoked. |

Total test suite pass rate: **279 passing, 5 skipped, 0 failures** in pytest. All 14 Next.js production routes compiled successfully. Fabric release candidate (`agenttrust-net`, 10 containers) and isolated Raft-3 consensus network (`agenttrust-raft3-net`, 8 containers + CCaaS) online and healthy.
