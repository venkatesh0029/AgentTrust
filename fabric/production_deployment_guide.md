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

Set the environment variable in `.env` or `config/settings.yaml`:
```yaml
blockchain:
  mode: "PRODUCTION_FABRIC_SDK"
  connection_profile: "fabric/connection-profile.json"
  channel_name: "agenttrust-channel"
  chaincode_name: "agenttrust-cc"
```

When `mode` is set to `PRODUCTION_FABRIC_SDK`, `FabricClient` in `fabric/fabric_client.py` routes ledger commits through gRPC to the running Hyperledger Fabric network endpoints.
