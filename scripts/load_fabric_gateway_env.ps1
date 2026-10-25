$ErrorActionPreference = 'Stop'
$secretPath = Join-Path $env:LOCALAPPDATA 'AgentTrust\FabricGateway\fabric-gateway.env'
if (-not (Test-Path $secretPath -PathType Leaf)) {
    throw "Local Fabric Gateway secret not found at $secretPath. Run scripts\rotate_fabric_gateway_token.ps1 first."
}
$raw = [System.IO.File]::ReadAllText($secretPath)
$match = [regex]::Match($raw, '(?m)^FABRIC_GATEWAY_TOKEN=([^\r\n]+)\s*$')
if (-not $match.Success -or $match.Groups[1].Value.Length -lt 48) {
    throw 'Local Fabric Gateway secret file is malformed or the token is too short.'
}
$env:FABRIC_GATEWAY_TOKEN = $match.Groups[1].Value
Write-Host 'FABRIC_GATEWAY_TOKEN loaded into this PowerShell process (value hidden).'
