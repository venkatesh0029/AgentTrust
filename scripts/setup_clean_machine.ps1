# ==============================================================================
# AgentTrust Clean-Machine Setup and Deployment Automation for Windows
# ==============================================================================

[CmdletBinding()]
param(
    [ValidateSet("development", "demo", "production")]
    [string]$Profile = "development",

    [ValidateSet("MODE_A_DIRECT_API", "MODE_B_AUTH_RBAC", "MODE_C_AGENTTRUST_NO_FABRIC", "MODE_D_AGENTTRUST_FABRIC")]
    [string]$Mode = "MODE_C_AGENTTRUST_NO_FABRIC",

    [switch]$UseDocker,
    [switch]$StartServer
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([int]$Step, [int]$Total, [string]$Message)
    Write-Host "`n[$Step/$Total] $Message..." -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "      Status: [PASS] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "      Warning: $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message, [string]$Remediation = "")
    Write-Host "`n[FATAL ERROR] $Message" -ForegroundColor Red
    if ($Remediation) {
        Write-Host "Remediation: $Remediation" -ForegroundColor Yellow
    }
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "  AGENTTRUST - CLEAN-MACHINE SETUP AND DEPLOYMENT (WINDOWS)" -ForegroundColor Cyan
Write-Host "  Project Directory : $ProjectRoot" -ForegroundColor DarkGray
Write-Host "  Target Profile    : $Profile" -ForegroundColor DarkGray
Write-Host "  Security Mode     : $Mode" -ForegroundColor DarkGray
Write-Host "  Deployment Target : $(if ($UseDocker) { 'Docker Compose' } else { 'Local Virtualenv' })" -ForegroundColor DarkGray
Write-Host "===========================================================================" -ForegroundColor Cyan

$TotalSteps = 6

# ------------------------------------------------------------------------------
# STEP 1: Validate Prerequisites (Python, Node.js, Docker)
# ------------------------------------------------------------------------------
Write-Step 1 $TotalSteps "Validating system prerequisites"

# Check Python
$pythonCmd = Get-Command "python" -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Fail "Python is not installed or not available on PATH." `
               "Install Python 3.10+ via 'winget install Python.Python.3.11' or https://python.org."
}

$pythonVersionRaw = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
$pythonMajorMinor = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ([version]$pythonMajorMinor -lt [version]"3.10") {
    Write-Fail "Python version $pythonVersionRaw is too old. AgentTrust requires Python >= 3.10." `
               "Please upgrade Python to 3.10, 3.11, or 3.12."
}
Write-Pass "Python $pythonVersionRaw detected (version 3.10 or higher satisfied)"

# Check Node.js
$nodeCmd = Get-Command "node" -ErrorAction SilentlyContinue
if ($nodeCmd) {
    $nodeVer = node --version
    Write-Pass "Node.js $nodeVer detected"
} else {
    Write-WarnMsg "Node.js not detected on PATH. Frontend compilation requires Node.js 18 or higher."
}

# Check Docker
if ($UseDocker) {
    $dockerCmd = Get-Command "docker" -ErrorAction SilentlyContinue
    if (-not $dockerCmd) {
        Write-Fail "Docker CLI is not found on PATH." `
                   "Install Docker Desktop for Windows or run setup without -UseDocker."
    }
    docker info >$null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Docker daemon is not responding." `
                   "Ensure Docker Desktop is running and WSL2 backend is active."
    }
    Write-Pass "Docker daemon is active and responsive"
}

# ------------------------------------------------------------------------------
# STEP 2: Docker Network Initialization (agenttrust-net)
# ------------------------------------------------------------------------------
Write-Step 2 $TotalSteps "Checking Docker network requirements"

if ($UseDocker) {
    try {
        $existingNet = docker network ls --filter "name=^agenttrust-net$" --format "{{.Name}}" 2>$null
        if (-not $existingNet) {
            Write-Host "      Creating external Docker network 'agenttrust-net'..." -ForegroundColor DarkGray
            docker network create agenttrust-net >$null 2>&1
            Write-Pass "Created external Docker network 'agenttrust-net'"
        } else {
            Write-Pass "External Docker network 'agenttrust-net' already exists"
        }
    } catch {
        Write-WarnMsg "Docker network check encountered: $_"
    }
} else {
    Write-Pass "Skipped Docker network check (running in local Python mode; pass -UseDocker for containers)"
}

# ------------------------------------------------------------------------------
# STEP 3: Safe .env Environment Configuration
# ------------------------------------------------------------------------------
Write-Step 3 $TotalSteps "Configuring environment settings (.env)"

$envPath = Join-Path $ProjectRoot ".env"
$envExamplePath = Join-Path $ProjectRoot ".env.example"

if (Test-Path $envPath) {
    Write-Pass "Preserved existing .env file (not overwritten)"
} else {
    if (-not (Test-Path $envExamplePath)) {
        Write-Fail "Missing template file .env.example at $envExamplePath."
    }
    Copy-Item $envExamplePath $envPath

    $genSecret = python -c "import secrets; print(secrets.token_hex(32))"
    $genJwt = python -c "import secrets; print(secrets.token_urlsafe(32) + '1234!')"

    $envContent = Get-Content $envPath
    $envContent = $envContent -replace 'AGENTTRUST_ENV=development', "AGENTTRUST_ENV=$Profile"
    $envContent = $envContent -replace 'AGENTTRUST_MODE=MODE_C_AGENTTRUST_NO_FABRIC', "AGENTTRUST_MODE=$Mode"
    $envContent = $envContent -replace 'GATEWAY_SECRET=.*', "GATEWAY_SECRET=$genSecret"
    $envContent = $envContent -replace 'AGENTTRUST_JWT_SECRET=.*', "AGENTTRUST_JWT_SECRET=$genJwt"

    if ($Profile -eq "demo") {
        $envContent = $envContent -replace 'AGENTTRUST_DEMO_MODE=false', 'AGENTTRUST_DEMO_MODE=true'
        $envContent = $envContent -replace 'AGENTTRUST_DB_PATH=.*', 'AGENTTRUST_DB_PATH=agenttrust_demo.db'
    }

    Set-Content -Path $envPath -Value $envContent -Encoding UTF8
    Write-Pass "Created safe local .env with generated secrets (Profile: $Profile, Mode: $Mode)"
}

# ------------------------------------------------------------------------------
# STEP 4: Local Virtual Environment and Dependencies
# ------------------------------------------------------------------------------
Write-Step 4 $TotalSteps "Setting up Python virtual environment"

$venvDir = Join-Path $ProjectRoot ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "      Creating virtual environment in .venv..." -ForegroundColor DarkGray
    python -m venv .venv
    Write-Pass "Created virtual environment in .venv"
} else {
    Write-Pass "Existing virtual environment detected in .venv"
}

Write-Host "      Installing/verifying Python dependencies..." -ForegroundColor DarkGray
& "$venvPython" -m pip install --quiet --upgrade pip
& "$venvPython" -m pip install --quiet -r requirements.txt
Write-Pass "Python dependencies satisfied"

# ------------------------------------------------------------------------------
# STEP 5: Data Directory and Local State Storage
# ------------------------------------------------------------------------------
Write-Step 5 $TotalSteps "Verifying local data storage directory"

$dataDir = Join-Path $ProjectRoot "data"
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force >$null
    Write-Pass "Created storage directory $dataDir"
} else {
    Write-Pass "Storage directory $dataDir verified"
}

# ------------------------------------------------------------------------------
# STEP 6: Deployment Verification and Instructions
# ------------------------------------------------------------------------------
Write-Step 6 $TotalSteps "Completing setup and operational checks"

if ($UseDocker) {
    Write-Host "`nTo start AgentTrust using Docker Compose:" -ForegroundColor Cyan
    Write-Host "  docker compose up -d --build" -ForegroundColor White
    Write-Host "  python scripts\verify_deployment.py --url http://127.0.0.1:8000" -ForegroundColor White
} elseif ($StartServer) {
    Write-Host "      Starting AgentTrust server locally on http://127.0.0.1:8000..." -ForegroundColor Cyan
    Start-Process -FilePath "$venvPython" -ArgumentList "-m uvicorn server:app --host 127.0.0.1 --port 8000" -NoNewWindow
    Write-Host "      Waiting for server startup..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 3
    & "$venvPython" (Join-Path $ProjectRoot "scripts\verify_deployment.py") --url "http://127.0.0.1:8000"
} else {
    Write-Host "`nSetup successfully completed!" -ForegroundColor Green
    Write-Host "To launch the server locally:" -ForegroundColor Cyan
    Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor White
    Write-Host "  uvicorn server:app --host 127.0.0.1 --port 8000" -ForegroundColor White
    Write-Host "`nTo verify deployment health:" -ForegroundColor Cyan
    Write-Host "  python scripts\verify_deployment.py --url http://127.0.0.1:8000" -ForegroundColor White
}

Write-Host "`n===========================================================================" -ForegroundColor Green
Write-Host "  AGENTTRUST SETUP COMPLETE (Profile: $Profile, Mode: $Mode)" -ForegroundColor Green
Write-Host "===========================================================================" -ForegroundColor Green
