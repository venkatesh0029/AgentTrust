# Hyperledger Fabric Production Network Deployment Guide

This guide provides instructions for deploying a multi-peer **Hyperledger Fabric v2.5** permissioned blockchain network and connecting the **AgentTrust** SDK bridge.

---

## 1. Network Topology Overview

The AgentTrust production topology consists of:
- **Certificate Authority (`ca.org1.agenttrust.com`)**: Issues identities and X.509 MSP credentials.
- **Raft Consensus Orderer (`orderer.agenttrust.com`)**: Orders transactions into immutable blocks.
- **Peer 0 Org1 (`peer0.org1.agenttrust.com`)**: Endorsing and committing peer for Organization 1.
- **Peer 0 Org2 (`peer0.org2.agenttrust.com`)**: Endorsing and committing peer for Organization 2.
- **Channel (`agenttrust-channel`)**: Ledger channel for AgentTrust audit events.
- **Chaincode (`agenttrust-cc`)**: Smart contract compiled in Go or TypeScript.

---

## 2. Prerequisites

- Docker Engine v24.0+ and Docker Compose v2.20+
- Go 1.20+ (for chaincode compilation)
- Node.js 18+ or Python 3.10+ (for Fabric SDK Client)

---

## 3. Step-by-Step Network Setup

### Step 1: Start Docker Containers
```bash
docker-compose -f fabric/docker-compose-fabric.yaml up -d
```

### Step 2: Create and Join Channel
```bash
# Create channel genesis block
peer channel create -o orderer.agenttrust.com:7050 -c agenttrust-channel -f ./channel-artifacts/channel.tx --tls --cafile $ORDERER_CA

# Join peers to channel
peer channel join -b agenttrust-channel.block
```

### Step 3: Package & Install Chaincode
```bash
# Package Go chaincode
peer lifecycle chaincode package agenttrust-cc.tar.gz --path ./fabric/chaincode/ --lang golang --label agenttrust-cc_1.0

# Install chaincode on Peer0 Org1 and Peer0 Org2
peer lifecycle chaincode install agenttrust-cc.tar.gz
```

### Step 4: Approve & Commit Chaincode
```bash
# Approve definition for Org1
peer lifecycle chaincode approveformyorg -o orderer.agenttrust.com:7050 --channelID agenttrust-channel --name agenttrust-cc --version 1.0 --package-id $CC_PACKAGE_ID --sequence 1

# Commit chaincode to channel
peer lifecycle chaincode commit -o orderer.agenttrust.com:7050 --channelID agenttrust-channel --name agenttrust-cc --version 1.0 --sequence 1
```

---

## 4. Connecting AgentTrust SDK Bridge

Configure runtime process environment variables (or forward them explicitly through `docker-compose.yml`):

```bash
export AGENTTRUST_ENV="production"
export AGENTTRUST_MODE="MODE_D_AGENTTRUST_FABRIC"
export FABRIC_GATEWAY_MODE="live"
export FABRIC_GATEWAY_URL="http://127.0.0.1:8090"
export GATEWAY_SECRET="<secure-production-secret>"
export CORS_ORIGINS="https://console.agenttrust.internal"
```

> **Note on Network Topology:** `FABRIC_GATEWAY_URL` is topology-dependent. `http://127.0.0.1:8090` applies when running the server and bridge directly on the host. When running the server in Docker, `127.0.0.1` refers to the container itself; use the bridge's container service name (e.g. `http://fabric-gateway-bridge:8090`) or host gateway (`http://host.docker.internal:8090`).

When deployed via Docker Compose, these variables must be explicitly defined in your environment or local `.env` and forwarded through the service's `environment:` mapping. The application does not load `.env` or `config/settings.yaml` directly at runtime.

When `FABRIC_GATEWAY_MODE` is set to `live`, `FabricClient` in `fabric/fabric_client.py` routes ledger writes and queries through the Go Gateway Bridge at `FABRIC_GATEWAY_URL` to the running Hyperledger Fabric network endpoints.
