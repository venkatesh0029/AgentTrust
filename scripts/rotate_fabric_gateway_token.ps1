param(
    [ValidateRange(30, 300)]
    [int]$ReadinessTimeoutSeconds = 90
)
$ErrorActionPreference = 'Stop'

$repoRoot = (Get-Location).Path
$composePath = Join-Path $repoRoot 'fabric\docker-compose-fabric.yaml'
if (-not (Test-Path $composePath -PathType Leaf)) {
    throw "Run from AgentTrust repository root. $composePath not found."
}

$secretDir = Join-Path $env:LOCALAPPDATA 'AgentTrust\FabricGateway'
New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
$secretPath = Join-Path $secretDir 'fabric-gateway.env'

# Generate 48 random bytes (base64 URL-safe, ~64 characters)
$bytes = New-Object byte[] 48
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$token = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

$envContent = "FABRIC_GATEWAY_TOKEN=$token`r`n"
[System.IO.File]::WriteAllText($secretPath, $envContent, [System.Text.UTF8Encoding]::new($false))

# Restrict permissions to the current user
try {
    $acl = Get-Acl $secretPath
    $acl.SetAccessRuleProtection($true, $false)
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
    $acl.SetAccessRule($rule)
    Set-Acl $secretPath $acl
} catch {
    Write-Warning "Could not restrict ACL on ${secretPath}: $($_.Exception.Message)"
}

$env:FABRIC_GATEWAY_TOKEN = $token
Write-Host "New secret generated at $secretPath and set in session." -ForegroundColor Cyan

Write-Host "Recreating fabric-gateway-bridge container..." -ForegroundColor Cyan
& docker compose -f $composePath up -d --no-deps fabric-gateway-bridge
if ($LASTEXITCODE -ne 0) {
    throw "Failed to recreate fabric-gateway-bridge container."
}

Write-Host "Waiting up to $ReadinessTimeoutSeconds seconds for bridge readiness..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($ReadinessTimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-RestMethod -Uri 'http://127.0.0.1:8090/health' -TimeoutSec 2 -ErrorAction Stop
        if ($resp.status -eq 'ONLINE' -and $resp.fabric -eq 'READY') {
            $ready = $true
            break
        }
    } catch {
        # continue polling
    }
}

if (-not $ready) {
    throw "fabric-gateway-bridge did not report ONLINE and READY within $ReadinessTimeoutSeconds seconds."
}

Write-Host "[PASS] fabric-gateway-bridge recreated and healthy with rotated token." -ForegroundColor Green
