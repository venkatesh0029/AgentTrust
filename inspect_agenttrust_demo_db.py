#!/usr/bin/env python3
"""Read-only inspection of AgentTrust's persistent demo SQLite database.

Run from the AgentTrust repository root:
    py -3.11 inspect_agenttrust_demo_db.py

Optionally pass a database path:
    py -3.11 inspect_agenttrust_demo_db.py path\\to\\agenttrust_persistent.db

This script never writes to the database. It checks the clean demo baseline
reported for scripts/reset_demo_data.py and reports any deviations.
"""
from __future__ import annotations

import sqlite3
import sys
from collections import Counter
from pathlib import Path

EXPECTED_COUNTS = {
    "agents": 41,
    "crl_revocations": 2,
    "ca_store": 1,
    "block_ledger": 1,
    "evidence_store": 0,
    "human_approvals": 0,
    "in_flight_locks": 0,
    "transaction_intents": 0,
}
EXPECTED_AGENT_IDS = {
    "FINANCE-AGENT-001",
    "SUSPENDED-AGENT-038",
    "COMPROMISED-AGENT-039",
    "REVOKED-AGENT-040",
    "TERMINATED-AGENT-041",
}
TEST_ID_MARKERS = (
    "TEST-", "TEST_", "APPR-", "SCALE-", "ABLATE-", "E2E-",
    "BENCHMARK-", "REGRESSION-", "PYTEST-",
)


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def open_read_only(db_path: Path) -> sqlite3.Connection:
    # Path.as_uri() correctly handles Windows drive letters and spaces.
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    rows = connection.execute(f"PRAGMA table_info({quote_identifier(table)})").fetchall()
    return [str(row[1]) for row in rows]


def pick_column(columns: list[str], candidates: tuple[str, ...]) -> str | None:
    by_lower = {column.lower(): column for column in columns}
    for candidate in candidates:
        if candidate.lower() in by_lower:
            return by_lower[candidate.lower()]
    return None


def main() -> int:
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "agenttrust_persistent.db"
    if not db_path.is_file():
        print(f"ERROR: Database file not found: {db_path.resolve()}")
        print("Run this from the AgentTrust repository root or pass the database path.")
        return 2

    print("AgentTrust read-only database inspection")
    print(f"Database: {db_path.resolve()}")
    print("Mode: READ ONLY (no rows or schema will be changed)\n")

    try:
        connection = open_read_only(db_path)
    except sqlite3.Error as exc:
        print(f"ERROR: Could not open database read-only: {exc}")
        return 2

    failures: list[str] = []
    warnings: list[str] = []
    try:
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        tables = [str(row[0]) for row in table_rows]
        if not tables:
            print("ERROR: No application tables were found.")
            return 2

        print("--- Table Counts ---")
        for table, expected in EXPECTED_COUNTS.items():
            if table not in tables:
                failures.append(f"Missing expected table: {table}")
                print(f"[FAIL] {table:<22} missing (expected {expected})")
                continue
            count = connection.execute(f"SELECT count(*) FROM {quote_identifier(table)}").fetchone()[0]
            status = "PASS" if count == expected else "FAIL"
            if status == "FAIL":
                failures.append(f"Table '{table}' has {count} rows (expected {expected})")
            print(f"[{status}] {table:<22} {count:>6} rows (expected {expected})")

        # Report row counts for other existing tables
        other_tables = [t for t in tables if t not in EXPECTED_COUNTS]
        if other_tables:
            print("\n--- Additional Application Tables ---")
            for table in other_tables:
                count = connection.execute(f"SELECT count(*) FROM {quote_identifier(table)}").fetchone()[0]
                print(f"[INFO] {table:<22} {count:>6} rows")

        # Check agents status breakdown and anchor IDs
        print("\n--- Agent Registry Inspection ---")
        if "agents" in tables:
            cols = table_columns(connection, "agents")
            id_col = pick_column(cols, ("agent_id", "id"))
            status_col = pick_column(cols, ("status", "state"))
            if not id_col or not status_col:
                failures.append("Could not find agent_id or status column in agents table")
            else:
                agent_rows = connection.execute(
                    f"SELECT {quote_identifier(id_col)}, {quote_identifier(status_col)} FROM {quote_identifier('agents')}"
                ).fetchall()
                agent_ids = {str(r[0]) for r in agent_rows}
                statuses = Counter(str(r[1]).upper() for r in agent_rows)

                expected_statuses = {"ACTIVE": 37, "SUSPENDED": 2, "REVOKED": 2}
                print(f"Agent Status Distribution: {dict(statuses)}")
                for st, exp_count in expected_statuses.items():
                    act_count = statuses.get(st, 0)
                    pass_fail = "PASS" if act_count == exp_count else "FAIL"
                    if pass_fail == "FAIL":
                        failures.append(f"Agent status '{st}' count is {act_count} (expected {exp_count})")
                    print(f"[{pass_fail}] Status {st:<10}: {act_count} (expected {exp_count})")

                print("\n--- Anchor Agents Check ---")
                for anchor in sorted(EXPECTED_AGENT_IDS):
                    if anchor in agent_ids:
                        print(f"[PASS] Anchor agent present: {anchor}")
                    else:
                        failures.append(f"Missing anchor agent: {anchor}")
                        print(f"[FAIL] Missing anchor agent: {anchor}")

                # Check for test markers
                test_agents_found = [aid for aid in agent_ids if any(marker in aid.upper() for marker in TEST_ID_MARKERS)]
                if test_agents_found:
                    warnings.append(f"Found {len(test_agents_found)} generated test IDs: {test_agents_found[:10]}")
                    print(f"\n[WARN] Found {len(test_agents_found)} IDs resembling test records: {test_agents_found[:5]}")
                else:
                    print("\n[PASS] No generated test agent markers detected.")

        print("\n" + "=" * 60)
        if failures:
            print(f"INSPECTION FAILED: {len(failures)} discrepancy/discrepancies detected:")
            for f in failures:
                print(f"  - {f}")
            return 1
        elif warnings:
            print(f"INSPECTION PASSED WITH WARNINGS: {len(warnings)} warning(s):")
            for w in warnings:
                print(f"  - {w}")
            return 0
        else:
            print("INSPECTION PASSED: Database matches clean demo baseline perfectly.")
            return 0
    finally:
        connection.close()


if __name__ == "__main__":
    sys.exit(main())
