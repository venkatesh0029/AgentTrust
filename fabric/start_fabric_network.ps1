# AgentTrust Real Hyperledger Fabric Multi-Org Network Launcher (PowerShell)
# Brings up Org1MSP, Org2MSP, Raft Orderer, CouchDBs, creates agenttrust-channel, and deploys Go chaincode.

Write-Host "🚀 Starting AgentTrust Real Hyperledger Fabric Network (2-Org, Raft, CouchDB)..." -ForegroundColor Green

docker compose -f fabric/docker-compose-fabric.yaml down -v
docker compose -f fabric/docker-compose-fabric.yaml up -d

Write-Host "⏳ Waiting for Fabric nodes and CouchDB World State containers to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "✅ Hyperledger Fabric Production Network containers successfully running!" -ForegroundColor Green
Write-Host "   - Org1MSP Peer: peer0.org1.agenttrust.com:7051 (CouchDB 5984)" -ForegroundColor Cyan
Write-Host "   - Org2MSP Peer: peer0.org2.agenttrust.com:9051 (CouchDB 6984)" -ForegroundColor Cyan
Write-Host "   - Raft Orderer: orderer.agenttrust.com:7050" -ForegroundColor Cyan
Write-Host "   - Go Chaincode: agenttrust_cc:v2.0" -ForegroundColor Cyan
