#!/usr/bin/env python3
"""
AgentTrust Demo Data Controlled Reset Utility.

Safely purges transient test artifacts (from benchmarks, unit tests, and attack lab runs)
while strictly preserving the 41 canonical demo agents, Root CA credentials, and CRL state.
Creates a timestamped backup before performing any modifications.
"""

import argparse
import datetime
import hashlib
import os
import shutil
import sqlite3
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database_config import resolve_database_path  # noqa: E402

CANONICAL_DEMO_AGENT_IDS = [
    # 1-25: Active Valid Agents
    "FINANCE-AGENT-001", "PROCUREMENT-AGENT-002", "TREASURY-AGENT-003",
    "REIMBURSEMENT-AGENT-004", "AUDIT-AGENT-005", "PAYROLL-AGENT-006",
    "INVENTORY-AGENT-007", "SUPPLY-CHAIN-AGENT-008", "VENDOR-PAYMENT-AGENT-009",
    "TAX-COMPLIANCE-AGENT-010", "HEALTHCARE-AGENT-011", "CLOUDOPS-AGENT-012",
    "DATAPIPELINE-AGENT-013", "SECURITY-AGENT-014", "LEGAL-AGENT-015",
    "GRANT-AGENT-016", "MARKETING-AGENT-017", "CUSTOMER-AGENT-018",
    "FACILITIES-AGENT-019", "RETAIL-AGENT-020", "ENERGY-AGENT-021",
    "INSURANCE-AGENT-022", "LOGISTICS-AGENT-023", "TELECOM-AGENT-024",
    "ASSET-AGENT-025",
    # 26-32: Active High-Threshold Agents (Human Approval)
    "CAPEX-AGENT-026", "MERGER-AGENT-027", "BONUS-AGENT-028",
    "EMERGENCY-AGENT-029", "RESEARCH-AGENT-030", "PARTNER-AGENT-031",
    "SOFTWARE-AGENT-032",
    # 33-37: Active Strict-Limit Agents (Policy Rejection)
    "STRICT-LIMIT-AGENT-033", "MICRO-AGENT-034", "INTERN-AGENT-035",
    "TEMP-AGENT-036", "RESTRICTED-AGENT-037",
    # 38-39: Suspended Agents
    "SUSPENDED-AGENT-038", "COMPROMISED-AGENT-039",
    # 40-41: Revoked Certificate Agents
    "REVOKED-AGENT-040", "TERMINATED-AGENT-041"
]

CANONICAL_REVOKED_IDS = ["REVOKED-AGENT-040", "TERMINATED-AGENT-041"]


def get_table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Returns row counts for all user tables in the SQLite database."""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [row[0] for row in cursor.fetchall()]
    counts = {}
    for table in tables:
        try:
            cursor.execute(f"SELECT count(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        except Exception:
            counts[table] = 0
    return counts


def reset_demo_data(db_path: str, reset_ledger: bool = False, dry_run: bool = False) -> None:
    """Performs a controlled pruning of transient test records."""
    target_path = resolve_database_path(db_path)
    if not os.path.exists(target_path):
        print(f"Error: Database file not found at '{target_path}'.", file=sys.stderr)
        sys.exit(1)

    print("AgentTrust Test Data Reset Utility")
    print(f"Target Database : {os.path.abspath(target_path)}")
    print(f"Mode            : {'DRY RUN' if dry_run else 'EXECUTE'}")
    print(f"Reset Ledger    : {reset_ledger}\n")

    conn = sqlite3.connect(target_path)
    before_counts = get_table_counts(conn)

    print("Current State (Before Reset):")
    for tbl, cnt in before_counts.items():
        print(f"  - {tbl:<26}: {cnt:>6} rows")
    print()

    # Verify canonical demo agents exist
    cursor = conn.cursor()
    placeholders = ",".join("?" for _ in CANONICAL_DEMO_AGENT_IDS)
    cursor.execute(
        f"SELECT agent_id, certificate FROM agents WHERE agent_id IN ({placeholders})",
        CANONICAL_DEMO_AGENT_IDS
    )
    found_demo_agents = cursor.fetchall()
    found_ids = {row[0] for row in found_demo_agents}
    missing_ids = set(CANONICAL_DEMO_AGENT_IDS) - found_ids

    if missing_ids:
        print(f"Warning: {len(missing_ids)} canonical agents are missing from the database: {missing_ids}")
    else:
        print(f"Verified: All {len(CANONICAL_DEMO_AGENT_IDS)} canonical demo agents are present.")

    # Calculate fingerprints for revoked demo agents
    canonical_revoked_fps = set()
    for aid, cert_pem in found_demo_agents:
        if aid in CANONICAL_REVOKED_IDS and cert_pem:
            fp = "SHA256:" + hashlib.sha256(cert_pem.encode("utf-8")).hexdigest().upper()
            canonical_revoked_fps.add(fp)

    print(f"Canonical CRL Revocation Fingerprints to retain: {len(canonical_revoked_fps)}")

    if dry_run:
        print("\nDry run completed. No files modified.")
        conn.close()
        return

    # Safety Backup
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file_timestamped = f"{target_path}.backup_{timestamp}"
    backup_file_standard = f"{target_path}.bak"

    conn.close()  # Close connection before copy to flush WAL
    shutil.copy2(target_path, backup_file_timestamped)
    shutil.copy2(target_path, backup_file_standard)
    print("\nSafety Backups Created:")
    print(f"  - {backup_file_timestamped}")
    print(f"  - {backup_file_standard}")

    # Reconnect and execute controlled purge
    conn = sqlite3.connect(target_path)
    cursor = conn.cursor()

    try:
        # 1. Prune agents table to only canonical demo agents
        cursor.execute(
            f"DELETE FROM agents WHERE agent_id NOT IN ({placeholders})",
            CANONICAL_DEMO_AGENT_IDS
        )
        pruned_agents = cursor.rowcount

        # 2. Prune CRL revocations
        if canonical_revoked_fps:
            crl_placeholders = ",".join("?" for _ in canonical_revoked_fps)
            cursor.execute(
                f"DELETE FROM crl_revocations WHERE fingerprint NOT IN ({crl_placeholders})",
                list(canonical_revoked_fps)
            )
        else:
            cursor.execute("DELETE FROM crl_revocations")
        pruned_crl = cursor.rowcount

        # 3. Clean transient test approvals
        cursor.execute("DELETE FROM human_approvals")
        pruned_approvals = cursor.rowcount

        # 4. Clean transient operational state (locks, nonces, intents, reconciliation)
        cursor.execute("DELETE FROM in_flight_locks")
        cursor.execute("DELETE FROM request_nonces")
        cursor.execute("DELETE FROM transaction_intents")
        cursor.execute("DELETE FROM delegation_revocations")
        cursor.execute("DELETE FROM downstream_fencing_tokens")
        if "reconciliation_queue" in before_counts:
            cursor.execute("DELETE FROM reconciliation_queue")

        # 5. Optionally reset ledger & evidence
        if reset_ledger:
            cursor.execute("DELETE FROM evidence_store")
            cursor.execute("DELETE FROM block_ledger")
            # Insert Genesis Block 0
            genesis_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO block_ledger (block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp)
                VALUES (0, '0000000000000000000000000000000000000000000000000000000000000000',
                        'GENESIS_BLOCK_AGENTTRUST_ROOT_HASH_00000000000000000000000000000000',
                        1, '{"tx_id":"TX-GENESIS-000","type":"GENESIS"}', ?)
            """, (genesis_time,))

        conn.commit()

        # Vacuum database to shrink disk footprint
        cursor.execute("VACUUM")
        conn.commit()
        print("\nDatabase VACUUM completed.")

    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"Error during purge: {e}. Restoring from backup...", file=sys.stderr)
        shutil.copy2(backup_file_standard, target_path)
        sys.exit(1)

    after_counts = get_table_counts(conn)
    conn.close()

    print("\nResulting State (After Reset):")
    for tbl, cnt in after_counts.items():
        delta = cnt - before_counts.get(tbl, 0)
        delta_str = f"({delta:+d})" if delta != 0 else ""
        print(f"  - {tbl:<26}: {cnt:>6} rows {delta_str}")

    db_size_mb = os.path.getsize(target_path) / (1024 * 1024)
    print(f"\nFinal SQLite database size: {db_size_mb:.2f} MB")
    print(f"Pruned: {pruned_agents} test agents, {pruned_crl} stale CRL records, {pruned_approvals} test approvals.")
    print("Controlled reset successful. Exactly 41 canonical demo agents are ready.")


def main():
    parser = argparse.ArgumentParser(description="AgentTrust Demo Data Controlled Reset Utility")
    parser.add_argument("--db-path", default=None, help="Path to SQLite database (default: resolve from environment)")
    parser.add_argument("--reset-ledger", action="store_true", help="Also reset block ledger and evidence store to genesis block")
    parser.add_argument("--dry-run", action="store_true", help="Simulate reset without altering data")
    args = parser.parse_args()

    reset_demo_data(args.db_path, reset_ledger=args.reset_ledger, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
