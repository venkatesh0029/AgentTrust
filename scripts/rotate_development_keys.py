#!/usr/bin/env python3
"""
AgentTrust Development Key & Root CA Rotation Utility.

Treats any previously exposed historical development keys as compromised.
Generates a brand-new Root CA keypair and re-issues all 41 agent identities,
RSA keypairs, X.509 certificates, and CRL revocation entries from a clean baseline.
"""

import datetime
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database_config import resolve_database_path  # noqa: E402
from fabric.persistent_db import PersistentStorageEngine  # noqa: E402
from identity_manager.certificate_manager import CertificateManager  # noqa: E402
from agent_registry.identity_store import IdentityStore  # noqa: E402
from agent_registry.registration import AgentRegistry  # noqa: E402


def rotate_development_keys(db_path: str | None = None) -> dict[str, str]:
    target_path = resolve_database_path(db_path)

    print("=" * 65)
    print("AGENTTRUST ROOT CA & DEVELOPMENT KEY ROTATION")
    print("=" * 65)
    print(f"Target Database: {os.path.abspath(target_path)}")

    # Remove old database file to guarantee complete key eradication
    if os.path.exists(target_path):
        os.remove(target_path)
        print("Removed compromised/historical persistent database.")

    # Initialize fresh persistent storage
    storage = PersistentStorageEngine(target_path)

    # Generate brand new 2048-bit Root CA
    cert_manager = CertificateManager(ca_common_name="AgentTrust Root CA", db_path=target_path)
    ca_creds = storage.get_ca_credentials("root_ca")
    ca_fp = CertificateManager.calculate_fingerprint(ca_creds["certificate_pem"])
    print(f"Generated NEW Root CA Certificate Fingerprint:\n  {ca_fp}\n")

    identity_store = IdentityStore(db_path=target_path)
    agent_registry = AgentRegistry(cert_manager, identity_store)

    # Initialize Genesis Block 0
    genesis_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = storage._get_connection()
    conn.execute(
        "INSERT INTO block_ledger (block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp) "
        "VALUES (0, '0000000000000000000000000000000000000000000000000000000000000000', "
        "'GENESIS_BLOCK_AGENTTRUST_ROOT_HASH_00000000000000000000000000000000', 1, "
        "'{\"tx_id\":\"TX-GENESIS-000\",\"type\":\"GENESIS\"}', ?)",
        (genesis_time,)
    )
    conn.commit()
    conn.close()

    # Re-seed all 41 canonical demo agents with fresh keypairs and certs signed by NEW Root CA
    import server
    server.agent_registry = agent_registry
    server.cert_manager = cert_manager
    server.identity_store = identity_store
    server.seed_41_demo_agents()

    agents = agent_registry.list_agents()
    print(f"Registered and issued {len(agents)} new agent identities with fresh certificates.")

    # Reload CRL in cert_manager from storage
    cert_manager.revoked_fingerprints = storage.get_crl_revocations()

    # Verify active vs revoked verification
    f1 = identity_store.get_agent("FINANCE-AGENT-001")
    r40 = identity_store.get_agent("REVOKED-AGENT-040")
    t41 = identity_store.get_agent("TERMINATED-AGENT-041")

    assert cert_manager.verify_agent_certificate(f1["certificate"])["valid"] is True
    assert cert_manager.verify_agent_certificate(r40["certificate"])["valid"] is False
    assert cert_manager.verify_agent_certificate(t41["certificate"])["valid"] is False
    print("Verified cryptographic enforcement against NEW Root CA: PASS")

    print("\nRotation complete. All development credentials refreshed.")
    return {"root_ca_fingerprint": ca_fp, "total_agents": len(agents)}


if __name__ == "__main__":
    rotate_development_keys()
