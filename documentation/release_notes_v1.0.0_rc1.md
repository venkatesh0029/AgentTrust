# AgentTrust — Release Candidate Notes (v1.0.0-rc1)

## Executive Summary

AgentTrust **v1.0.0-rc1** marks the official **Release Candidate Freeze** for the cryptographic security and distributed governance platform protecting enterprise systems against autonomous AI agent misbehavior.

This release candidate consolidates all deliverables across:
1. **Multi-Peer Hyperledger Fabric Raft-3 Resilience**: Isolated 3-node Raft consensus topology, crash fault tolerance, dynamic leader re-election, deterministic CCaaS chaincode, and outbox reconciliation.
2. **Cryptographic Identity & Policy Enforcement**: X.509 certificate chains, RSA signature verification, monotonic fencing tokens, and zero-float-drift integer minor-unit accounting.
3. **OWASP-Hardened Administrative Security**: Double-submit CSRF protection, HttpOnly `__Host-` session cookies, durable multi-worker token revocation, 600,000 PBKDF2 iterations, and build-time production demo-mode gates.

---

## Release Checkpoint Identification
- **Release Candidate Version**: `v1.0.0-rc1`
- **Candidate Checkpoint Commit**: `dff4cb076da8c6981a7168fc7323d48816dd3d88` (`dff4cb0`)
- **Branch**: `feat/fabric-resilience`
- **Repository**: `https://github.com/venkatesh0029/AgentTrust`
- **Release Verification Date**: `2026-10-26`

---

## Summary of Completed Security Hardening

### 1. Dual-Layer CSRF & Origin Validation
- **State-Changing Protection**: All cookie-authenticated mutating requests (`POST`, `PUT`, `DELETE`, `PATCH`) require both:
  1. A matching `Origin` or `Referer` matching explicit HTTPS origins configured in `CORS_ORIGINS`.
  2. A matching `X-CSRF-Token` HTTP header paired with the issued `agenttrust_csrf_token` cookie.
- **Prefix Isolation**: In production mode (`AGENTTRUST_ENV=production`), session cookies enforce the `__Host-` prefix (`__Host-agenttrust_session`), mandating `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`.
- **API Exemption**: Machine-to-machine direct API requests utilizing `Authorization: Bearer <JWT>` and read-only `GET` endpoints are exempt from CSRF checks.

### 2. Durable Multi-Worker Token Revocation
- **Durable SQLite Blacklist**: Token blacklisting records token JTIs and SHA-256 hashes into the durable SQLite table `jwt_revoked_tokens`.
- **Crash & Multi-Worker Resilience**: Revoked tokens cannot be re-used even after a complete process crash, container restart, or across separate worker instances in a multi-worker cluster.

### 3. Password Storage Hardening
- **OWASP Alignment**: Administrative passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations (benchmarked at ~229ms latency), per OWASP password storage guidelines.
- **Production Password Constraints**: Production startup fails closed if default passwords, weak passwords, or passwords under 16 characters are configured.

### 4. JWT Secret Validation & Weak-Secret Heuristics
- **Entropy Heuristics**: Supplementary Shannon entropy ($H \ge 3.0$ bits/char), character diversity ($\ge 8$ unique characters), minimum length ($\ge 32$ characters), and pattern checks reject trivial keys.
- **Unpredictability Standard**: Cryptographic unpredictability derives from CSPRNG generation (`secrets.token_bytes(32)`) or an enterprise secret manager.

### 5. Production Demo-Mode Precedence
- **Strict Precedence**: `isDemoAuthMode()` returns `false` unconditionally when `NODE_ENV=production` or `NEXT_PUBLIC_ENV=production` regardless of `NEXT_PUBLIC_DEMO_MODE=true`.
- **Build Gate**: `next.config.ts` fails closed during `npm run build` if demo mode flags are detected in a production build.
- **Backend Independence**: Backend endpoints enforce authentication and reject requests attempting to bypass auth via client demo headers.

---

## Test Suite & Verification Results

### 1. Test Suite Reconciliation (325 Total Items)
- **325 Total Test Items Defined**:
  - **320 Passed**: Full functional, property-based, adversarial, and concurrency regression tests passed with zero failures.
  - **4 Runtime Skips**: 3 tests in `tests/test_kms_softhsm2.py` skip gracefully when the optional SoftHSM2 daemon is not present; 1 test in `tests/test_fabric_live_network.py` skips when a live Docker peer on port 7051 is not connected.
  - **1 Collection-Time Skip**: `tests/test_property_based.py` uses `pytest.importorskip("hypothesis")` and skips at the module collection boundary in environments lacking hypothesis.
  - **Result**: `320 passed, 5 skipped, 0 failures` (Total items evaluated = 325).

### 2. 5-Stage Automated Reproducibility Harness (`verify_all.py`)
- **Stage 1**: Ruff Static Analysis — **PASS** (0 warnings, 0.06s)
- **Stage 2**: Mypy Strict Type Checking — **PASS** (89 source files, 8.24s)
- **Stage 3**: Full Pytest Regression Suite — **PASS** (320 passed, 5 skipped, 167.30s)
- **Stage 4**: Held-Out V2 Adversarial Benchmark — **PASS** (100% precision, 0% FPR, 3.35s)
- **Stage 5**: Held-Out V3 Adversarial Benchmark — **PASS** (100% precision, 0% FPR, 0.90s)

### 3. Production-Profile Acceptance Suite (`verify_production_acceptance.py`)
- **9 of 9 Acceptance Checks Passed**:
  1. Production Configuration Sanity (Entropy, Passwords, CORS) — **PASS**
  2. Production Session Cookie (`__Host-` prefix, Secure, HttpOnly, SameSite=Lax) — **PASS**
  3. CSRF Defense: Cross-Site Origin Rejection (403 Forbidden) — **PASS**
  4. CSRF Defense: Missing Header Rejection (403 Forbidden) — **PASS**
  5. CSRF Defense: Mismatched Header Rejection (403 Forbidden) — **PASS**
  6. CSRF Defense: Valid Request Acceptance (200 OK) — **PASS**
  7. RBAC Matrix: Least Privilege Enforcement across All 4 Roles — **PASS**
  8. Durable Revocation: Restart and Multi-Worker Persistence — **PASS**
  9. Frontend Demo Mode: Strict Production Precedence — **PASS**

### 4. Database Baseline & Credential Scan
- **Database Baseline**: `inspect_agenttrust_demo_db.py` confirms clean state: exactly 41 canonical demo agents, 0 transient test records.
- **Credential Scan**: Automated pattern scanning across source files identified 0 unencrypted keys or exposed tokens outside test fixtures.

---

## User Interface Consolidation Decision Record (ADR)

- **Primary Enterprise Interface**: The Next.js application in `frontend/` is the primary, production-grade interface. It implements full Next.js App Router architecture, responsive UI components, live websocket telemetry, and strict production build gating.
- **Legacy Dashboard Retention**: The static HTML/JS dashboard in `dashboard/` is maintained as a lightweight fallback inspection interface.
- **Maintenance Policy**: The legacy dashboard has been upgraded to support `X-CSRF-Token` headers and in-memory session management. It will **not** be removed without prior deprecation notice and validation that no monitoring scripts or enterprise environments depend on `/static`.

---

## Deployment & Operational Guide

### 1. Production Deployment Prerequisites
Before running in production mode:
```bash
# 1. Generate high-entropy secrets (min 32 bytes CSPRNG)
export AGENTTRUST_ENV="production"
export GATEWAY_SECRET="$(openssl rand -hex 32)"
export AGENTTRUST_JWT_SECRET="$(openssl rand -hex 32)"

# 2. Configure administrative passwords (min 16 chars)
export AGENTTRUST_ADMIN_PASSWORD="YourEnterpriseAdminSecret#2026!"
export AGENTTRUST_POLICY_ADMIN_PASSWORD="YourEnterprisePolicySecret#2026!"
export AGENTTRUST_FINANCE_APPROVER_PASSWORD="YourEnterpriseFinanceSecret#2026!"
export AGENTTRUST_AUDITOR_PASSWORD="YourEnterpriseAuditorSecret#2026!"

# 3. Explicit HTTPS CORS origin (no localhost, no wildcard)
export CORS_ORIGINS="https://agenttrust.yourdomain.com"

# 4. Fabric Gateway connectivity (if Mode D)
export FABRIC_GATEWAY_MODE="live"
export FABRIC_GATEWAY_URL="https://fabric-gateway.yourdomain.com:7051"
export FABRIC_GATEWAY_TOKEN="$(cat /run/secrets/fabric_gateway_token)"
```

### 2. Startup Verification
```bash
# Verify database integrity before starting service
python inspect_agenttrust_demo_db.py

# Launch production server
uvicorn server:app --host 0.0.0.0 --port 8000 --workers 4
```

### 3. Rollback Procedure
If rollback is triggered:
1. Revert container deployment to previous stable image tag.
2. If database schema was modified, restore SQLite snapshot:
   ```bash
   cp agenttrust_persistent.db.backup_<TIMESTAMP> agenttrust_persistent.db
   ```
3. Re-verify database baseline using `python inspect_agenttrust_demo_db.py`.

---

## Known Limitations & Boundaries

1. **Single-Host Coordination**: Concurrency locking, replay nonces, and WAL modes rely on SQLite OS-level file locking on a single host. Distributed multi-host operation requires etcd/Consul or distributed consensus.
2. **Clock Semantics**: Epoch timestamps require monotonic NTP time synchronization across host environments.
3. **Independent Security Validation**: Automated testing confirms deterministic reproducibility. Formal production certification requires external third-party security review per `documentation/adversarial_review_guide.md`.
