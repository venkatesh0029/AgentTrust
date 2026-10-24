#!/usr/bin/env python3
"""
Test Fresh Bootstrap in an Isolated SQLite Database.

Confirms that seeding creates the expected 41 agents and certificate/revocation state
from an empty database without relying on previously persisted records.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_isolated_bootstrap():
    temp_dir = tempfile.mkdtemp(prefix="agenttrust_clean_boot_")
    temp_db = os.path.join(temp_dir, "fresh_bootstrap.db")

    print("=" * 65)
    print("STEP 4: TEST CLEAN BOOTSTRAP IN ISOLATED DATABASE")
    print("=" * 65)
    print(f"Isolated Temp Database : {temp_db}")

    env = os.environ.copy()
    env["AGENTTRUST_DB_PATH"] = temp_db

    # Subprocess bootstrap to ensure isolated module import and clean globals
    boot_script = """
import os
import sys
import datetime

from fabric.persistent_db import PersistentStorageEngine
from identity_manager.certificate_manager import CertificateManager
from agent_registry.identity_store import IdentityStore
from agent_registry.registration import AgentRegistry

db_path = os.environ["AGENTTRUST_DB_PATH"]
storage = PersistentStorageEngine(db_path)
cert_manager = CertificateManager(ca_common_name="AgentTrust Root CA", db_path=db_path)
identity_store = IdentityStore(db_path=db_path)
agent_registry = AgentRegistry(cert_manager, identity_store)

# Create Genesis Block 0
genesis_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
conn = storage._get_connection()
conn.execute('''
    INSERT OR REPLACE INTO block_ledger (block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp)
    VALUES (0, '0000000000000000000000000000000000000000000000000000000000000000',
            'GENESIS_BLOCK_AGENTTRUST_ROOT_HASH_00000000000000000000000000000000',
            1, '{"tx_id":"TX-GENESIS-000","type":"GENESIS"}', ?)
''', (genesis_time,))
conn.commit()
conn.close()

# Import and execute canonical seeding logic
import server
server.agent_registry = agent_registry
server.cert_manager = cert_manager
server.identity_store = identity_store
server.seed_41_demo_agents()

agents = agent_registry.list_agents()
print(f"Seeding completed successfully: {len(agents)} agents in fresh database.")
"""

    res = subprocess.run([sys.executable, "-c", boot_script], env=env, capture_output=True, text=True)
    print("\n--- Bootstrap Output ---")
    print(res.stdout.strip())
    if res.stderr:
        print("Bootstrap stderr:", res.stderr.strip())

    if res.returncode != 0:
        print(f"ERROR: Fresh bootstrap failed with return code {res.returncode}", file=sys.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    # Now run inspect_agenttrust_demo_db.py directly against the fresh database
    print("\n--- Running Read-Only Inspection on Fresh Database ---")
    inspect_script = os.path.join(str(PROJECT_ROOT), "inspect_agenttrust_demo_db.py")
    inspect_res = subprocess.run([sys.executable, inspect_script, temp_db], capture_output=True, text=True)
    print(inspect_res.stdout.strip())
    if inspect_res.stderr:
        print(inspect_res.stderr.strip())

    # Verify certificate cryptographic integrity on fresh database
    verify_script = """
import os
from identity_manager.certificate_manager import CertificateManager
from agent_registry.identity_store import IdentityStore

db_path = os.environ["AGENTTRUST_DB_PATH"]
cm = CertificateManager(db_path=db_path)
store = IdentityStore(db_path=db_path)

f1 = store.get_agent("FINANCE-AGENT-001")
res_f1 = cm.verify_agent_certificate(f1["certificate"])
assert res_f1["valid"] is True, f"FINANCE-AGENT-001 certificate invalid: {res_f1}"

r40 = store.get_agent("REVOKED-AGENT-040")
res_r40 = cm.verify_agent_certificate(r40["certificate"])
assert res_r40["valid"] is False and res_r40["reason"] == "CERTIFICATE_REVOKED", f"REVOKED-AGENT-040 not revoked: {res_r40}"

t41 = store.get_agent("TERMINATED-AGENT-041")
res_t41 = cm.verify_agent_certificate(t41["certificate"])
assert res_t41["valid"] is False and res_t41["reason"] == "CERTIFICATE_REVOKED", f"TERMINATED-AGENT-041 not revoked: {res_t41}"

print("Cryptographic verification on fresh database: PASSED")
"""
    ver_res = subprocess.run([sys.executable, "-c", verify_script], env=env, capture_output=True, text=True)
    print("\n--- Cryptographic Signature & Revocation Check ---")
    print(ver_res.stdout.strip())
    if ver_res.stderr:
        print(ver_res.stderr.strip())

    # Cleanup temp directory
    shutil.rmtree(temp_dir, ignore_errors=True)
    print(f"\nTemporary directory cleaned up: {temp_dir}")

    success = (inspect_res.returncode == 0 and ver_res.returncode == 0)
    print("\n" + "=" * 65)
    if success:
        print("FRESH BOOTSTRAP TEST PASSED: Complete independent verification.")
        print("=" * 65)
        return 0
    else:
        print("FRESH BOOTSTRAP TEST FAILED.")
        print("=" * 65)
        return 1


if __name__ == "__main__":
    sys.exit(run_isolated_bootstrap())
