# AgentTrust — Clean-Machine Deployment & Operations Guide

## 1. Overview & Architectural Readiness

This guide provides reproducible deployment procedures for provisioning AgentTrust on a clean machine (Windows, Linux, or macOS) with zero pre-existing project state.

AgentTrust supports two deployment modalities:
1. **Local Developer & Simulation Profile** (Recommended for rapid evaluation, benchmarks, and functional testing): Runs the 13-stage security gateway with an in-memory/SQLite hash-chain audit ledger. Requires only Python 3.10+.
2. **Enterprise Docker & Raft-3 Consensus Profile** (Recommended for end-to-end distributed fault-tolerance evaluation): Runs the gateway, backend services, and isolated 3-node Hyperledger Fabric Raft consensus cluster inside containerized networks.

---

## 2. System Requirements & Prerequisites

| Component | Minimum Version | Verification Command | Purpose |
|:---|:---:|:---|:---|
| **Python** | `>= 3.10` (3.11 recommended) | `python --version` | Gateway server, policy engine, crypto operations |
| **Node.js** | `>= 18.0.0` (LTS) | `node --version` | Next.js enterprise console compilation |
| **npm** | `>= 9.0.0` | `npm --version` | Frontend dependency management |
| **Docker Engine** | `>= 24.0.0` (Optional for local) | `docker --version` | Multi-container consensus deployment |
| **Docker Compose** | `>= 2.20.0` (Optional for local) | `docker compose version` | Orchestrates gateway and Fabric network |

---

## 3. Fast-Track One-Command Setup

The repository provides automated setup scripts that validate prerequisites, configure `.env` with cryptographically secure random secrets (without overwriting existing configurations), provision virtual environments, ensure Docker networks are initialized, and execute deployment health probes.

### On Windows (PowerShell)
Open PowerShell in the repository root:
```powershell
# Default setup (Development profile, Mode C simulation)
.\scripts\setup_clean_machine.ps1

# Optional: Automatic server launch and immediate health verification
.\scripts\setup_clean_machine.ps1 -StartServer

# Optional: Docker container deployment
.\scripts\setup_clean_machine.ps1 -UseDocker -StartServer
```

### On Linux / macOS (Bash)
Open a terminal in the repository root:
```bash
# Make script executable
chmod +x scripts/setup_clean_machine.sh

# Default setup (Development profile, Mode C simulation)
./scripts/setup_clean_machine.sh

# Optional: Automatic server launch and immediate health verification
./scripts/setup_clean_machine.sh --start-server

# Optional: Docker container deployment
./scripts/setup_clean_machine.sh --use-docker
```

---

## 4. Key Deployment Dependency: Docker Network (`agenttrust-net`)

> [!IMPORTANT]
> **Clean-Machine Dependency Note**:
> In [`docker-compose.yml`](docker-compose.yml), the primary application service binds to an external Docker network:
> ```yaml
> networks:
>   agenttrust-fabric:
>     name: agenttrust-net
>     external: true
> ```
> On a clean host, running `docker compose up` without prior network creation will fail with:
> `network agenttrust-net declared as external, but could not be found`.
>
> The setup scripts (`setup_clean_machine.ps1` and `setup_clean_machine.sh`) automatically detect and create this network (`docker network create agenttrust-net`) prior to launching any containers.

---

## 5. Ledger Modes: Simulation vs. Live Fabric

AgentTrust strictly distinguishes between **Simulator Mode** and **Live Fabric Mode**:

| Feature / Behavior | Mode C (`MODE_C_AGENTTRUST_NO_FABRIC`) | Mode D (`MODE_D_AGENTTRUST_FABRIC`) |
|:---|:---|:---|
| **Consensus Mechanism** | In-Memory / SQLite Hash-Chain | 3-Node Raft Consensus (CFT) |
| **Infrastructure Overhead** | Zero (Runs on standard Python) | High (Requires Docker, Orderers, Peers) |
| **Endorsement Flow** | Local SHA-256 digest link | Multi-Peer CCaaS Chaincode Endorsement |
| **Fault-Tolerance Boundary** | Single-host process crash isolation | Node crash, leader re-election, network partition |
| **Default In** | Development, CI/CD, Demo | Production (Mandatory), Raft Resilience Suites |
| **Fail-Closed Gate** | N/A | Production mode rejects simulated ledger |

### Explicit Mode Setting in `.env`:
```ini
# For local developer or evaluation runs:
AGENTTRUST_MODE=MODE_C_AGENTTRUST_NO_FABRIC
FABRIC_GATEWAY_MODE=simulator

# For live distributed Hyperledger Fabric validation:
AGENTTRUST_MODE=MODE_D_AGENTTRUST_FABRIC
FABRIC_GATEWAY_MODE=live
FABRIC_GATEWAY_URL=http://localhost:8090
FABRIC_GATEWAY_TOKEN=<minimum-32-char-token>
```

---

## 6. Environment Separation Rules

AgentTrust enforces strict boundary separation across three operational profiles:

### 1. `development` (Default)
- **CORS**: Allows `http://localhost:3000` and `http://127.0.0.1:3000`.
- **Secrets**: Generates local cryptographically random secrets via `secrets.token_hex(32)` if missing.
- **Ledger**: Defaults to Mode C simulator.
- **Mode Switching**: Allows dynamic switching via `/mode` API for benchmark comparisons.

### 2. `demo`
- **Database**: Binds to isolated `agenttrust_demo.db` to prevent accidental access to or mutation of canonical state.
- **UI Persona Selector**: Enabled in frontend for role-switching walkthroughs.
- **Production Precedence**: Demo mode flags are unconditionally ignored if `NODE_ENV=production` or `AGENTTRUST_ENV=production`.

### 3. `production` (Fail-Closed)
- **CORS**: Requires explicit HTTPS origins configured in `CORS_ORIGINS`. Wildcards (`*`) or non-HTTPS origins cause immediate startup crash.
- **Cookies**: Mandates `__Host-agenttrust_session` prefix (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`).
- **CSRF**: Enforces double-submit `X-CSRF-Token` headers for all mutating cookie operations.
- **Passwords**: Fails closed if default passwords (e.g. `AdminTrust#2026!Secured`) or passwords under 16 characters are configured.
- **Live Ledger**: If Mode D is active, `FABRIC_GATEWAY_MODE` must be `live`. Silently falling back to a simulator is strictly prohibited.

---

## 7. Deployment Health Verification (`verify_deployment.py`)

After starting the application, run the automated verification tool to confirm readiness:

```bash
# Verify local default instance
python scripts/verify_deployment.py --url http://127.0.0.1:8000

# Verify with expected profile and mode constraints
python scripts/verify_deployment.py --url http://127.0.0.1:8000 --expected-mode MODE_C_AGENTTRUST_NO_FABRIC --expected-profile development
```

### Expected Output:
```text
===========================================================================
  AGENTTRUST DEPLOYMENT VERIFICATION
  Target Server: http://127.0.0.1:8000
===========================================================================

[1/4] Probing server liveness at http://127.0.0.1:8000/api/health...
      Connected successfully (HTTP 200 on attempt 1/5)

[2/4] Probing gateway telemetry probe at http://127.0.0.1:8000/healthz...
      Telemetry Status: UP (Uptime: 14.2s, Invariants: 12)

[3/4] Inspecting operational security mode at http://127.0.0.1:8000/mode...
      Active Mode: MODE_C_AGENTTRUST_NO_FABRIC
      Ledger Type: Local Hash-Chain Simulator (Zero Network Overhead)

[4/4] Verification Summary Scorecard:
---------------------------------------------------------------------------
  Server Target      : http://127.0.0.1:8000
  Health Endpoint    : ONLINE (HTTP 200)
  Telemetry Probe    : UP
  Operational Mode   : MODE_C_AGENTTRUST_NO_FABRIC
  Consensus Backend  : Local Hash-Chain Simulator (Zero Network Overhead)
  Cache Backend      : in-memory-fallback
---------------------------------------------------------------------------

[DEPLOYMENT CHECK: PASSED]
AgentTrust instance at http://127.0.0.1:8000 is healthy and ready for traffic.
```

---

## 8. Teardown & Safe Cleanup

To stop and clean up AgentTrust without deleting unrelated system resources or databases:

### Stopping Local Process
- Press `Ctrl + C` in the server terminal, or terminate the uvicorn process.

### Stopping Docker Deployment
```bash
# Stop containers gracefully
docker compose down

# Stop containers and remove volumes (Warning: resets transient data in volumes)
docker compose down -v
```

> [!TIP]
> **Safe Cleanup Invariant**:
> Teardown scripts and Compose commands do not delete external Docker networks or unrelated project containers. The external network `agenttrust-net` is preserved across teardown cycles for persistent development convenience.
