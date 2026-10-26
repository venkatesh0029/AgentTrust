#!/usr/bin/env bash
# ==============================================================================
# AgentTrust Clean-Machine Setup and Deployment Automation (Linux / macOS)
# ==============================================================================
# Strict error handling: exit immediately on error, unassigned var, or pipeline fail
set -euo pipefail

PROFILE="development"
MODE="MODE_C_AGENTTRUST_NO_FABRIC"
USE_DOCKER=false
START_SERVER=false

# ANSI Color formatting
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Parse CLI options
while [[ $# -gt 0 ]]; do
  case $1 in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --use-docker)
      USE_DOCKER=true
      shift
      ;;
    --start-server)
      START_SERVER=true
      shift
      ;;
    -h|--help)
      echo "Usage: ./scripts/setup_clean_machine.sh [--profile development|demo|production] [--mode MODE_C_AGENTTRUST_NO_FABRIC] [--use-docker] [--start-server]"
      exit 0
      ;;
    *)
      echo -e "${RED}[ERROR] Unknown argument: $1${NC}"
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo -e "${CYAN}===========================================================================${NC}"
echo -e "${CYAN}  AGENTTRUST — CLEAN-MACHINE SETUP & DEPLOYMENT (POSIX / LINUX)${NC}"
echo -e "  Project Directory : ${PROJECT_ROOT}"
echo -e "  Target Profile    : ${PROFILE}"
echo -e "  Security Mode     : ${MODE}"
echo -e "  Deployment Target : $(if [ "$USE_DOCKER" = true ]; then echo 'Docker Compose'; else echo 'Local Virtualenv'; fi)"
echo -e "${CYAN}===========================================================================${NC}"

TOTAL_STEPS=6

# ------------------------------------------------------------------------------
# STEP 1: Validate Prerequisites (Python, Node.js, Docker)
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[1/${TOTAL_STEPS}] Validating system prerequisites...${NC}"

# Python check
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo -e "${RED}[FATAL ERROR] Python is not installed or not available on PATH.${NC}"
    echo "Remediation: Install Python >= 3.10 via 'apt install python3 python3-venv' or your package manager."
    exit 1
fi

if ! ${PYTHON_BIN} -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"; then
    PY_VER=$(${PYTHON_BIN} -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
    echo -e "${RED}[FATAL ERROR] Python version ${PY_VER} is too old. AgentTrust requires Python >= 3.10.${NC}"
    exit 1
fi
PY_VER=$(${PYTHON_BIN} -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
echo -e "      Status: ${GREEN}[PASS]${NC} Python ${PY_VER} detected (>= 3.10 satisfied)"

# Node.js check (optional for backend, needed for frontend build)
if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node --version)
    echo -e "      Status: ${GREEN}[PASS]${NC} Node.js ${NODE_VER} detected"
else
    echo -e "      Warning: ${YELLOW}Node.js not detected on PATH. Local frontend compilation requires Node.js >= 18.${NC}"
fi

# Docker check
if [ "$USE_DOCKER" = true ]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}[FATAL ERROR] Docker CLI is not installed on PATH.${NC}"
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}[FATAL ERROR] Docker daemon is not responding.${NC}"
        echo "Remediation: Start Docker service ('sudo systemctl start docker' or start Docker Desktop)."
        exit 1
    fi
    echo -e "      Status: ${GREEN}[PASS]${NC} Docker daemon is active and responsive"
fi

# ------------------------------------------------------------------------------
# STEP 2: Docker Network Initialization (agenttrust-net)
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[2/${TOTAL_STEPS}] Checking Docker network requirements...${NC}"

if [ "$USE_DOCKER" = true ]; then
    if ! docker network inspect agenttrust-net >/dev/null 2>&1; then
        echo "      Creating external Docker network 'agenttrust-net'..."
        docker network create agenttrust-net >/dev/null
        echo -e "      Status: ${GREEN}[PASS]${NC} Created external Docker network 'agenttrust-net'"
    else
        echo -e "      Status: ${GREEN}[PASS]${NC} External Docker network 'agenttrust-net' already exists"
    fi
else
    echo -e "      Status: ${GREEN}[PASS]${NC} Skipped Docker network check (running in local mode; use --use-docker for containers)"
fi

# ------------------------------------------------------------------------------
# STEP 3: Safe .env Environment Configuration
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[3/${TOTAL_STEPS}] Configuring environment settings (.env)...${NC}"

if [ -f ".env" ]; then
    echo -e "      Status: ${GREEN}[PASS]${NC} Preserved existing .env file (not overwritten)"
else
    if [ ! -f ".env.example" ]; then
        echo -e "${RED}[FATAL ERROR] Missing template file .env.example.${NC}"
        exit 1
    fi
    cp .env.example .env

    # Generate cryptographically secure random secrets
    GEN_SECRET=$(${PYTHON_BIN} -c "import secrets; print(secrets.token_hex(32))")
    GEN_JWT=$(${PYTHON_BIN} -c "import secrets; print(secrets.token_urlsafe(32) + '1234!')")

    # Replace placeholders safely
    sed -i.bak "s/AGENTTRUST_ENV=development/AGENTTRUST_ENV=${PROFILE}/" .env
    sed -i.bak "s/AGENTTRUST_MODE=MODE_C_AGENTTRUST_NO_FABRIC/AGENTTRUST_MODE=${MODE}/" .env
    sed -i.bak "s/GATEWAY_SECRET=.*/GATEWAY_SECRET=${GEN_SECRET}/" .env
    sed -i.bak "s/AGENTTRUST_JWT_SECRET=.*/AGENTTRUST_JWT_SECRET=${GEN_JWT}/" .env

    if [ "${PROFILE}" = "demo" ]; then
        sed -i.bak "s/AGENTTRUST_DEMO_MODE=false/AGENTTRUST_DEMO_MODE=true/" .env
        sed -i.bak "s/AGENTTRUST_DB_PATH=.*/AGENTTRUST_DB_PATH=agenttrust_demo.db/" .env
    fi

    rm -f .env.bak
    echo -e "      Status: ${GREEN}[PASS]${NC} Created safe local .env with generated secrets (Profile: ${PROFILE}, Mode: ${MODE})"
fi

# ------------------------------------------------------------------------------
# STEP 4: Local Virtual Environment & Dependencies
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[4/${TOTAL_STEPS}] Setting up Python virtual environment...${NC}"

VENV_DIR="${PROJECT_ROOT}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"

if [ ! -f "${VENV_PYTHON}" ]; then
    echo "      Creating virtual environment in .venv..."
    ${PYTHON_BIN} -m venv .venv
    echo -e "      Status: ${GREEN}[PASS]${NC} Created virtual environment in .venv"
else
    echo -e "      Status: ${GREEN}[PASS]${NC} Existing virtual environment detected in .venv"
fi

echo "      Installing/verifying Python dependencies..."
"${VENV_PYTHON}" -m pip install --quiet --upgrade pip
"${VENV_PYTHON}" -m pip install --quiet -r requirements.txt
echo -e "      Status: ${GREEN}[PASS]${NC} Python dependencies satisfied"

# ------------------------------------------------------------------------------
# STEP 5: Data Directory & Local State Storage
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[5/${TOTAL_STEPS}] Verifying local data storage directory...${NC}"

mkdir -p "${PROJECT_ROOT}/data"
echo -e "      Status: ${GREEN}[PASS]${NC} Storage directory verified at ${PROJECT_ROOT}/data"

# ------------------------------------------------------------------------------
# STEP 6: Deployment Verification / Startup
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[6/${TOTAL_STEPS}] Completing setup & operational checks...${NC}"

if [ "$USE_DOCKER" = true ]; then
    echo -e "\nTo start AgentTrust using Docker Compose:"
    echo "  docker compose up -d --build"
    echo "  python3 scripts/verify_deployment.py --url http://127.0.0.1:8000"
elif [ "$START_SERVER" = true ]; then
    echo -e "      Starting AgentTrust server locally on http://127.0.0.1:8000..."
    "${VENV_PYTHON}" -m uvicorn server:app --host 127.0.0.1 --port 8000 &
    SERVER_PID=$!
    echo "      Server process launched with PID ${SERVER_PID}. Waiting 3s for readiness..."
    sleep 3
    "${VENV_PYTHON}" scripts/verify_deployment.py --url http://127.0.0.1:8000
else
    echo -e "\n${GREEN}Setup successfully completed!${NC}"
    echo -e "To launch the server locally:"
    echo "  source .venv/bin/activate"
    echo "  uvicorn server:app --host 127.0.0.1 --port 8000"
    echo -e "\nTo verify deployment health:"
    echo "  python3 scripts/verify_deployment.py --url http://127.0.0.1:8000"
fi

echo -e "\n${GREEN}===========================================================================${NC}"
echo -e "${GREEN}  AGENTTRUST SETUP COMPLETE (Profile: ${PROFILE}, Mode: ${MODE})${NC}"
echo -e "${GREEN}===========================================================================${NC}"
