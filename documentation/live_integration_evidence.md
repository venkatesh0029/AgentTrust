# AgentTrust — Live Integration Evidence & External Verification Guide

## 1. Overview
This document outlines the protocols, infrastructure requirements, and operational steps for executing live integration testing against external, stateful distributed dependencies:
1. **Hyperledger Fabric Test Network** (multi-organization peer endorsement, Raft orderer, chaincode validation).
2. **SoftHSM2 PKCS#11 Hardware Security Module** (cryptographic token key generation, non-extractable private keys, hardware signature generation).

> [!IMPORTANT]
> **Separation of Claims**:
> AgentTrust's default test suite verifies local multi-process operating system concurrency, persistent SQLite WAL coordination, and simulated permissioned ledger consensus. Live multi-peer Fabric endorsement and hardware-backed PKCS#11 token signing require external daemons and are maintained as separate integration suites enabled via environment flags.

---

## 2. Live Hyperledger Fabric Integration

### 2.1. Infrastructure Prerequisites
- Docker Engine 24.0+ & Docker Compose v2+
- Hyperledger Fabric Binaries (`peer`, `orderer`, `configtxgen`, `fabric-ca-client`) v2.5 LTS
- Minimum 8 GB RAM, 4 vCPUs allocated to Docker

### 2.2. Test Network Provisioning
To launch a standard Fabric two-organization test network with Raft ordering:

```bash
# 1. Clone fabric-samples or navigate to local Fabric test-network
git clone https://github.com/hyperledger/fabric-samples.git
cd fabric-samples/test-network

# 2. Bring up the network with an application channel
./network.sh up createChannel -c agenttrust-channel -ca

# 3. Deploy the AgentTrust audit chaincode
./network.sh deployCC -ccn agenttrust-audit -ccp /path/to/AgentTrust/chaincode -ccl go
```

### 2.3. Executing Live Endorsement Tests
When the network is active, configure the environment variables and run the live integration test:

```bash
# Set connection environment variables
export FABRIC_LIVE_NETWORK=1
export FABRIC_PEER_ENDPOINT="localhost:7051"
export FABRIC_ORDERER_ENDPOINT="localhost:7050"
export FABRIC_CHANNEL="agenttrust-channel"
export FABRIC_MSP_ID="Org1MSP"
export FABRIC_CERT_PATH=".../organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/cert.pem"
export FABRIC_KEY_PATH=".../organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/priv_sk"

# Execute live endorsement test
pytest tests/test_fabric_live_network.py -k test_live_fabric_testnet_endorsement_boundary -v
```

### 2.4. Scenarios Validated Under Live Network
1. **Multi-Org Endorsement**: Requests require dual endorsement signatures (`Org1MSP` and `Org2MSP`) before orderer commit.
2. **Endorsement Failure**: If one organization denies or returns diverging state, the transaction fails endorsement and is rejected.
3. **Immutability & Peer Disconnect**: If a peer drops offline, AgentTrust enqueues the commit into its durable SQLite outbox; upon peer reconnect, the reconciliation worker safely drains the outbox without duplicating downstream business side effects.

---

## 3. Live SoftHSM2 PKCS#11 Token Integration

### 3.1. Infrastructure Prerequisites
- SoftHSM2 v2.6.1+ installed on system:
  - **Linux (Ubuntu/Debian)**: `sudo apt-get install softhsm2`
  - **Windows**: SoftHSM2 for Windows installed to `C:\Program Files\SoftHSM2` with `softhsm2-x64.dll` on PATH.

### 3.2. Token Initialization
Initialize a dedicated security token for AgentTrust:

```bash
# Initialize SoftHSM2 token labeled 'AgentTrustToken' with SO PIN and User PIN
softhsm2-util --init-token --slot 0 --label "AgentTrustToken" --so-pin 12345678 --pin 1234
```

### 3.3. Executing Live PKCS#11 Tests
Set environment variables and run KMS verification:

```bash
export SOFTHSM2_LIB="/usr/lib/softhsm/libsofthsm2.so"  # or C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll on Windows
export SOFTHSM2_TOKEN_LABEL="AgentTrustToken"
export SOFTHSM2_PIN="1234"

# Execute live token tests
pytest tests/test_kms.py -k test_live_softhsm2_token_presence -v
```

### 3.4. Cryptographic Guarantees Validated
1. **Non-Extractable Keys**: `CKA_EXTRACTABLE = FALSE` and `CKA_SENSITIVE = TRUE` enforced at hardware token driver level. Private key material never leaves the token boundaries.
2. **Hardware Signature Verification**: Digital signatures produced inside the token slot are verified against the exported public key with SHA-256 RSA PSS.
3. **Telemetry & Graceful Fallback**: If the token disconnects or slot fails, telemetry records provider state (`TOKEN_AVAILABLE: False`), falling back to software isolation while alerting operators.
