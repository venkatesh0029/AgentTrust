"""
Pytest configuration and session-wide test environment fixtures for AgentTrust.

Guarantees strict isolation of the persistent production/demo database (agenttrust_persistent.db):
1. Immediately at conftest import time (prior to collection or module loading of any test files),
   allocates an ephemeral SQLite test database in a temporary directory.
2. Clones the existing schema and canonical records so all test suites run against valid entities.
3. Sets AGENTTRUST_DB_PATH at module level, ensuring that any module-level imports of server.py
   or database resolvers bind exclusively to the isolated test database.
4. Auto-loads local FABRIC_GATEWAY_TOKEN from fabric-gateway.env if present so live Fabric Gateway
   bridge integration tests authenticate successfully.
5. Preserves FABRIC_GATEWAY_MODE='simulator' default for standard test execution while allowing
   individual test cases to patch 'live' mode cleanly.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import pytest

# Module-level setup: runs BEFORE any test files are imported by pytest
_TEST_TEMP_DIR = tempfile.mkdtemp(prefix="agenttrust_test_env_")
_ISOLATED_DB_PATH = os.path.join(_TEST_TEMP_DIR, "isolated_test_agenttrust.db")

_BASELINE_FILE = os.path.abspath("agenttrust_persistent.db")
if os.path.exists(_BASELINE_FILE):
    shutil.copy2(_BASELINE_FILE, _ISOLATED_DB_PATH)

_ORIGINAL_DB_PATH_ENV = os.environ.get("AGENTTRUST_DB_PATH")
os.environ["AGENTTRUST_DB_PATH"] = _ISOLATED_DB_PATH

# Default to simulator mode for standard unit/flow suites unless overridden
os.environ.setdefault("FABRIC_GATEWAY_MODE", "simulator")

# Auto-load FABRIC_GATEWAY_TOKEN if not already configured in environment
_REAL_FABRIC_GATEWAY_TOKEN = None
local_env_path = os.path.join(
    os.environ.get("LOCALAPPDATA", ""), "AgentTrust", "FabricGateway", "fabric-gateway.env"
)
if os.path.exists(local_env_path):
    try:
        with open(local_env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("FABRIC_GATEWAY_TOKEN="):
                    _REAL_FABRIC_GATEWAY_TOKEN = line.split("=", 1)[1].strip()
                    break
    except Exception:
        pass

if _REAL_FABRIC_GATEWAY_TOKEN and "FABRIC_GATEWAY_TOKEN" not in os.environ:
    os.environ["FABRIC_GATEWAY_TOKEN"] = _REAL_FABRIC_GATEWAY_TOKEN


def _cleanup_test_database():
    if _ORIGINAL_DB_PATH_ENV is not None:
        os.environ["AGENTTRUST_DB_PATH"] = _ORIGINAL_DB_PATH_ENV
    else:
        os.environ.pop("AGENTTRUST_DB_PATH", None)
    try:
        shutil.rmtree(_TEST_TEMP_DIR, ignore_errors=True)
    except Exception:
        pass


atexit.register(_cleanup_test_database)


@pytest.fixture(scope="session", autouse=True)
def isolated_agenttrust_database_session():
    """Confirms database isolation is active for all tests in the session."""
    assert os.environ.get("AGENTTRUST_DB_PATH") == _ISOLATED_DB_PATH
    yield _ISOLATED_DB_PATH


@pytest.fixture(autouse=True)
def preserve_test_environment_invariants():
    """Restores baseline environment defaults after each test function."""
    yield
    os.environ["FABRIC_GATEWAY_MODE"] = "simulator"
    if _REAL_FABRIC_GATEWAY_TOKEN:
        os.environ["FABRIC_GATEWAY_TOKEN"] = _REAL_FABRIC_GATEWAY_TOKEN
