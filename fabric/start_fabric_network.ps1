# AgentTrust Hyperledger Fabric Network Launcher
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

$composeFile = "fabric/docker-compose-fabric.yaml"

Write-Host "Validating Compose configuration..." -ForegroundColor Cyan
docker compose -f $composeFile config --quiet
if ($LASTEXITCODE -ne 0) {
    throw "Compose validation failed. No containers were started."
}

Write-Host "Starting AgentTrust Fabric services..." -ForegroundColor Cyan
docker compose -f $composeFile up -d
if ($LASTEXITCODE -ne 0) {
    throw "Compose startup failed. Inspect Docker Compose output."
}

Write-Host "Current container status:" -ForegroundColor Cyan
docker compose -f $composeFile ps

Write-Host ""
Write-Host "Startup requested. Container status does not yet prove Fabric is operational." -ForegroundColor Yellow
Write-Host "No volumes were deleted. Channel creation and chaincode deployment remain separate steps."
