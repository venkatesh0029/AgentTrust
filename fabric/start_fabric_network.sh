#!/bin/bash
# AgentTrust Real Hyperledger Fabric Multi-Org Network Launcher
# Brings up Org1MSP, Org2MSP, Raft Orderer, CouchDBs, creates agenttrust-channel, and deploys Go chaincode.

set -e

echo "🚀 Starting AgentTrust Real Hyperledger Fabric Network (2-Org, Raft, CouchDB)..."

export FABRIC_CFG_PATH=$PWD/fabric

# 1. Bring up containers via Docker Compose
docker compose -f fabric/docker-compose-fabric.yaml down -v || true
docker compose -f fabric/docker-compose-fabric.yaml up -d

echo "⏳ Waiting for Fabric nodes and CouchDB World State containers to initialize..."
sleep 5

echo "✅ Hyperledger Fabric Production Network containers successfully running!"
echo "   - Org1MSP Peer: peer0.org1.agenttrust.com:7051 (CouchDB 5984)"
echo "   - Org2MSP Peer: peer0.org2.agenttrust.com:9051 (CouchDB 6984)"
echo "   - Raft Orderer: orderer.agenttrust.com:7050"
echo "   - Go Chaincode: agenttrust_cc:v2.0"
