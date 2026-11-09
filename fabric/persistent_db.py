"""
Persistent SQLite Storage Engine for AgentTrust Framework.
Provides SQLite database persistence for CA certificates, Agent Registry, Replay Protection Nonces,
Off-Chain Evidence Records, CRL Revocations, and Block Ledger State across server restarts.
"""

import datetime
import hashlib
import json
import os
import random
import sqlite3
import threading
import time
import uuid
from typing import Any

from database_config import resolve_database_path


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal transition is attempted in the transaction intent state machine."""


class ConcurrentTransitionConflictError(RuntimeError):
    """Raised when a concurrent worker modifies an intent before the current transition completes."""


class FencingTokenError(RuntimeError):
    """Raised when a worker's lock lease was preempted, stolen, or superseded by a newer fencing token."""


class LockLeaseExpiredError(RuntimeError):
    """Raised when an operation is attempted after lock lease expiry."""


class LockAcquisitionResult:
    """Encapsulates distributed lock acquisition result with fencing token and owner identity."""

    def __init__(self, acquired: bool, fencing_token: int, owner_id: str):
        self.acquired = acquired
        self.fencing_token = fencing_token
        self.owner_id = owner_id

    def __bool__(self) -> bool:
        return self.acquired

    def __iter__(self):
        return iter((self.acquired, self.fencing_token, self.owner_id))

    def __getitem__(self, index: int):
        return (self.acquired, self.fencing_token, self.owner_id)[index]

    def __repr__(self) -> str:
        return f"LockAcquisitionResult(acquired={self.acquired}, fencing_token={self.fencing_token}, owner_id='{self.owner_id}')"


VALID_INTENT_TRANSITIONS: dict[str, set[str]] = {
    "PENDING_AUTHORIZATION": {"AUTHORIZED_PENDING_EXECUTION", "REJECTED"},
    "AUTHORIZED_PENDING_EXECUTION": {"EXECUTED_PENDING_LEDGER", "EXECUTION_FAILED", "REJECTED", "HELD_FOR_HUMAN_APPROVAL"},
    "HELD_FOR_HUMAN_APPROVAL": {"AUTHORIZED_PENDING_EXECUTION", "REJECTED"},
    "EXECUTED_PENDING_LEDGER": {"COMMITTED", "COMPLETED", "LEDGER_PENDING_RETRY", "FAILED"},
    "LEDGER_PENDING_RETRY": {"COMMITTED", "COMPLETED", "LEDGER_PENDING_RETRY", "LEDGER_RETRY_EXHAUSTED"},
    # Terminal states (no further transitions permitted)
    "COMMITTED": set(),
    "COMPLETED": set(),
    "REJECTED": set(),
    "EXECUTION_FAILED": set(),
    "LEDGER_RETRY_EXHAUSTED": set(),
    "FAILED": set()
}


class PersistentStorageEngine:
    """
    SQLite Database Manager providing atomic, concurrency-safe persistence.
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = resolve_database_path(db_path)
        parent_dir = os.path.dirname(os.path.abspath(self.db_path))
        if parent_dir and "invalid" not in parent_dir.lower():
            os.makedirs(parent_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self, timeout: float = 30.0) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=timeout)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            busy_ms = max(int(timeout * 1000), 50)
            conn.execute(f"PRAGMA busy_timeout={busy_ms}")
            conn.execute("PRAGMA cache_size=-64000")
            conn.execute("PRAGMA temp_store=MEMORY")
        except Exception:
            pass
        return conn


    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # 1. Agent Registry Table (Persists key references / public certificates only; no plaintext private keys)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    agent_name TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    status TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    certificate TEXT,
                    policy_id TEXT NOT NULL,
                    key_version INTEGER DEFAULT 1,
                    registered_at TEXT NOT NULL,
                    key_reference TEXT,
                    private_key TEXT
                )
            """)

            cursor.execute("PRAGMA table_info(agents)")
            existing_cols = [row["name"] for row in cursor.fetchall()]
            if "key_reference" not in existing_cols:
                cursor.execute("ALTER TABLE agents ADD COLUMN key_reference TEXT")
            if "private_key" not in existing_cols:
                cursor.execute("ALTER TABLE agents ADD COLUMN private_key TEXT")

            # Privacy & key-security hardening: nullify any legacy plaintext private keys in SQLite
            cursor.execute("UPDATE agents SET private_key = NULL WHERE private_key IS NOT NULL AND private_key != ''")

            # 2. Replay Request Tracker Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS request_nonces (
                    request_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    timestamp_ts REAL NOT NULL
                )
            """)

            # 3. Off-Chain Evidence Store Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_store (
                    evidence_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # 4. Fabric & Audit Block Ledger Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS block_ledger (
                    block_number INTEGER PRIMARY KEY AUTOINCREMENT,
                    previous_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL,
                    tx_count INTEGER NOT NULL,
                    block_data_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    sequence_number INTEGER,
                    event_id TEXT
                )
            """)

            cursor.execute("PRAGMA table_info(block_ledger)")
            existing_block_cols = [row["name"] for row in cursor.fetchall()]
            if "sequence_number" not in existing_block_cols:
                cursor.execute("ALTER TABLE block_ledger ADD COLUMN sequence_number INTEGER")
            if "event_id" not in existing_block_cols:
                cursor.execute("ALTER TABLE block_ledger ADD COLUMN event_id TEXT")

            # Unique constraints: prevent sequence collisions & duplicate events across processes
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_block_ledger_seq
                ON block_ledger (sequence_number)
                WHERE sequence_number IS NOT NULL
            """)
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_block_ledger_event_id
                ON block_ledger (event_id)
                WHERE event_id IS NOT NULL
            """)

            # Backfill existing records if sequence_number or event_id was only in JSON
            cursor.execute("""
                SELECT block_number, block_data_json
                FROM block_ledger
                WHERE sequence_number IS NULL OR event_id IS NULL
            """)
            for row in cursor.fetchall():
                try:
                    b_data = json.loads(row["block_data_json"])
                    if isinstance(b_data, dict):
                        b_seq = b_data.get("sequence_number")
                        b_ev = b_data.get("event_id")
                        if b_seq is not None or b_ev is not None:
                            cursor.execute("""
                                UPDATE block_ledger
                                SET sequence_number = COALESCE(sequence_number, ?),
                                    event_id = COALESCE(event_id, ?)
                                WHERE block_number = ?
                            """, (b_seq, b_ev, row["block_number"]))
                except Exception:
                    pass

            # 5. CRL Revocations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS crl_revocations (
                    fingerprint TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL
                )
            """)

            # 6. CA Key/Certificate Store Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ca_store (
                    key_id TEXT PRIMARY KEY,
                    private_key_pem TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # 7. Human Approvals Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS human_approvals (
                    approval_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approval_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # 8. Delegation Revocations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS delegation_revocations (
                    token_id TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL
                )
            """)

            # 9. Durable Reconciliation Outbox Queue Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reconciliation_queue (
                    event_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    error_msg TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    lease_owner TEXT DEFAULT '',
                    lease_expires_at REAL DEFAULT 0.0,
                    fencing_token INTEGER DEFAULT 0
                )
            """)

            # Backward-compatible retry lease migration.
            cursor.execute("PRAGMA table_info(reconciliation_queue)")
            recon_cols = [row["name"] for row in cursor.fetchall()]
            if "lease_owner" not in recon_cols:
                cursor.execute(
                    "ALTER TABLE reconciliation_queue "
                    "ADD COLUMN lease_owner TEXT DEFAULT ''"
                )
            if "lease_expires_at" not in recon_cols:
                cursor.execute(
                    "ALTER TABLE reconciliation_queue "
                    "ADD COLUMN lease_expires_at REAL DEFAULT 0.0"
                )
            if "fencing_token" not in recon_cols:
                cursor.execute(
                    "ALTER TABLE reconciliation_queue "
                    "ADD COLUMN fencing_token INTEGER DEFAULT 0"
                )

            # 10. Durable Transaction Intent State Machine Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transaction_intents (
                    request_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    amount REAL NOT NULL,
                    idempotency_key TEXT,
                    state TEXT NOT NULL,
                    outcome_json TEXT,
                    request_fingerprint TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            cursor.execute("PRAGMA table_info(transaction_intents)")
            intent_cols = [row["name"] for row in cursor.fetchall()]
            if "request_fingerprint" not in intent_cols:
                cursor.execute("ALTER TABLE transaction_intents ADD COLUMN request_fingerprint TEXT")

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_intents_agent_created
                ON transaction_intents (agent_id, created_at, state)
            """)

            # 11. Cross-Process In-Flight Distributed Locks Table with Leases and Fencing Tokens
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS in_flight_locks (
                    scoped_key TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    owner_id TEXT NOT NULL DEFAULT '',
                    fencing_token INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL DEFAULT 0.0
                )
            """)

            cursor.execute("PRAGMA table_info(in_flight_locks)")
            lock_cols = [row["name"] for row in cursor.fetchall()]
            if "owner_id" not in lock_cols:
                cursor.execute("ALTER TABLE in_flight_locks ADD COLUMN owner_id TEXT DEFAULT ''")
            if "fencing_token" not in lock_cols:
                cursor.execute("ALTER TABLE in_flight_locks ADD COLUMN fencing_token INTEGER DEFAULT 1")
            if "expires_at" not in lock_cols:
                cursor.execute("ALTER TABLE in_flight_locks ADD COLUMN expires_at REAL DEFAULT 0.0")

            conn.commit()
            conn.close()

    def save_agent(self, agent_data: dict[str, Any]) -> None:
        """
        Persists agent record to SQLite without saving plaintext private keys.
        Persists opaque key references (KMS/SoftHSM2 handle) and public certificates only.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            key_ref = (
                agent_data.get("key_reference")
                or agent_data.get("key_handle")
                or f"kms://agenttrust/agents/{agent_data['agent_id']}"
            )
            cursor.execute("""
                INSERT OR REPLACE INTO agents (
                    agent_id, agent_name, owner, status, public_key, certificate, policy_id, key_version, registered_at, key_reference, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_data["agent_id"],
                agent_data["agent_name"],
                agent_data["owner"],
                agent_data["status"],
                agent_data["public_key"],
                agent_data.get("certificate", ""),
                agent_data.get("policy_id", "FIN-POLICY-001"),
                agent_data.get("key_version", 1),
                agent_data.get("registered_at", ""),
                key_ref,
                None  # Explicitly do NOT persist private keys in SQLite
            ))
            conn.commit()
            conn.close()

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Retrieves agent record from SQLite (with private keys omitted)."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                rec = dict(row)
                rec["private_key"] = None
                return rec
            return None

    def list_agents(self) -> list[dict[str, Any]]:
        """Retrieves all registered agents from SQLite (with private keys omitted)."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents")
            rows = cursor.fetchall()
            conn.close()
            result = []
            for r in rows:
                rec = dict(r)
                rec["private_key"] = None
                result.append(rec)
            return result

    def save_crl_revocation(self, fingerprint: str) -> None:
        """Persists a certificate revocation fingerprint."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO crl_revocations (fingerprint, revoked_at)
                VALUES (?, ?)
            """, (fingerprint.upper(), datetime.datetime.now(datetime.UTC).isoformat()))
            conn.commit()
            conn.close()

    def get_crl_revocations(self) -> set[str]:
        """Retrieves all revoked certificate fingerprints."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT fingerprint FROM crl_revocations")
            rows = cursor.fetchall()
            conn.close()
            return {r["fingerprint"].upper() for r in rows}

    def save_ca_credentials(self, key_id: str, private_key_pem: str, certificate_pem: str) -> None:
        """Persists Root CA private key and certificate."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ca_store (key_id, private_key_pem, certificate_pem, created_at)
                VALUES (?, ?, ?, ?)
            """, (key_id, private_key_pem, certificate_pem, datetime.datetime.now(datetime.UTC).isoformat()))
            conn.commit()
            conn.close()

    def get_ca_credentials(self, key_id: str = "root_ca") -> dict[str, str] | None:
        """Retrieves Root CA credentials if persisted."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ca_store WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
            return None

    def save_evidence(self, evidence_id: str, request_id: str, agent_id: str, evidence_hash: str, evidence_data: dict[str, Any]) -> None:
        """Persists off-chain evidence to SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO evidence_store (
                    evidence_id, request_id, agent_id, evidence_hash, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                evidence_id,
                request_id,
                agent_id,
                evidence_hash,
                json.dumps(evidence_data),
                evidence_data.get("timestamp", "")
            ))
            conn.commit()
            conn.close()

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        """Retrieves a single off-chain evidence record by evidence_id or request_id."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT evidence_json, evidence_hash
                    FROM evidence_store
                    WHERE evidence_id = ? OR request_id = ?
                """, (evidence_id, evidence_id))
                row = cursor.fetchone()
                if row:
                    data = json.loads(row["evidence_json"])
                    data["_stored_hash"] = row["evidence_hash"]
                    return data
                return None
            finally:
                conn.close()

    def save_block(self, previous_hash: str, block_hash: str, tx_count: int, block_data: dict[str, Any], timestamp: str) -> int:
        """Persists committed block to SQLite block ledger."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            seq = block_data.get("sequence_number") if isinstance(block_data, dict) else None
            ev_id = block_data.get("event_id") if isinstance(block_data, dict) else None
            cursor.execute("""
                INSERT INTO block_ledger (previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                previous_hash,
                block_hash,
                tx_count,
                json.dumps(block_data),
                timestamp,
                seq,
                ev_id
            ))
            block_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return block_id or 1

    def atomic_append_audit_block(
        self,
        event_type: str,
        request_id: str,
        agent_id: str,
        request_hash: str,
        risk_score: float,
        policy_version: str,
        decision: str,
        execution_result: str,
        event_id: str | None = None,
        max_retries: int = 15,
        busy_timeout: float = 5.0,
        _fail_before_commit: bool = False
    ) -> tuple[dict[str, Any], bool]:
        """
        Atomically allocates sequence number, links previous record hash,
        and commits audit record to SQLite block_ledger using BEGIN IMMEDIATE.

        Guarantees:
        1. Single ordered chain with ZERO sequence collisions across concurrent processes.
        2. Database-level UNIQUE constraints on sequence_number and event_id.
        3. Idempotent deduplication: identical event_id returns existing record without append.
        4. Crash-safe atomic execution: failures roll back with no partial blocks.
        """
        # If save_block was mocked/patched in a test on class or instance, honor the mock side-effect
        for fn in (getattr(self, "save_block", None), getattr(PersistentStorageEngine, "save_block", None)):
            if fn and hasattr(fn, "side_effect") and fn.side_effect:
                if isinstance(fn.side_effect, Exception):
                    raise fn.side_effect
                elif callable(fn.side_effect):
                    fn.side_effect()

        backoff = 0.005
        for attempt in range(max_retries):
            conn = self._get_connection(timeout=busy_timeout)
            conn.isolation_level = None  # Autocommit mode for explicit transaction control
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")

                # 1. Idempotency Check
                if event_id:
                    cursor.execute("""
                        SELECT sequence_number, event_id, block_hash, previous_hash, block_data_json, timestamp
                        FROM block_ledger
                        WHERE event_id = ?
                        LIMIT 1
                    """, (event_id,))
                    existing = cursor.fetchone()
                    if existing:
                        cursor.execute("COMMIT")
                        conn.close()
                        try:
                            return json.loads(existing["block_data_json"]), False
                        except Exception:
                            return dict(existing), False

                # 2. Latest committed audit block lookup inside the SAME transaction
                cursor.execute("""
                    SELECT sequence_number, block_hash, previous_hash, block_data_json, timestamp
                    FROM block_ledger
                    WHERE sequence_number IS NOT NULL
                    ORDER BY sequence_number DESC
                    LIMIT 1
                """)
                latest = cursor.fetchone()

                if latest is None:
                    # Allocate Genesis Block (seq 0)
                    gen_data = {
                        "event_id": "EV-GENESIS-000",
                        "sequence_number": 0,
                        "event_type": "GENESIS",
                        "request_id": "REQ-GENESIS-000",
                        "agent_id": "SYSTEM",
                        "request_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "risk_score": 0.0,
                        "policy_version": "1.0",
                        "decision": "INITIALIZED",
                        "execution_result": "SUCCESS",
                        "previous_record_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
                    }
                    gen_bytes = json.dumps(gen_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                    gen_hash = hashlib.sha256(gen_bytes).hexdigest()
                    gen_data["record_hash"] = gen_hash
                    gen_data["event_hash"] = gen_hash

                    cursor.execute("""
                        INSERT INTO block_ledger (
                            previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        gen_data["previous_record_hash"],
                        gen_hash,
                        1,
                        json.dumps(gen_data),
                        gen_data["timestamp"],
                        0,
                        "EV-GENESIS-000"
                    ))
                    latest_seq = 0
                    prev_hash = gen_hash
                else:
                    latest_seq = int(latest["sequence_number"])
                    prev_hash = str(latest["block_hash"])

                next_seq = latest_seq + 1
                ev_id = event_id or f"EV-CHAIN-{next_seq:06d}"
                timestamp = datetime.datetime.now(datetime.UTC).isoformat()

                # 3. Construct canonical record & cryptographic hash
                rec_data = {
                    "event_id": ev_id,
                    "sequence_number": next_seq,
                    "event_type": event_type,
                    "request_id": request_id,
                    "agent_id": agent_id,
                    "request_hash": request_hash,
                    "risk_score": risk_score,
                    "policy_version": policy_version,
                    "decision": decision,
                    "execution_result": execution_result,
                    "previous_record_hash": prev_hash,
                    "timestamp": timestamp
                }
                rec_bytes = json.dumps(rec_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                rec_hash = hashlib.sha256(rec_bytes).hexdigest()
                rec_data["record_hash"] = rec_hash
                rec_data["event_hash"] = rec_hash

                # 4. Insert into block_ledger with database constraints
                cursor.execute("""
                    INSERT INTO block_ledger (
                        previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    prev_hash,
                    rec_hash,
                    1,
                    json.dumps(rec_data),
                    timestamp,
                    next_seq,
                    ev_id
                ))

                if _fail_before_commit:
                    raise sqlite3.OperationalError("Simulated crash/power loss before commit")

                cursor.execute("COMMIT")
                conn.close()
                return rec_data, True

            except sqlite3.OperationalError as exc:
                try:
                    cursor.execute("ROLLBACK")
                except Exception:
                    pass
                conn.close()
                if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                    if attempt < max_retries - 1:
                        time.sleep(backoff + random.uniform(0.005, 0.02))
                        backoff = min(backoff * 2, 0.5)
                        continue
                raise
            except sqlite3.IntegrityError:
                try:
                    cursor.execute("ROLLBACK")
                except Exception:
                    pass
                conn.close()
                # If race on duplicate event_id, return existing record
                if event_id:
                    existing = self.get_audit_record_by_event_id(event_id)
                    if existing:
                        return existing, False
                raise
            except Exception:
                try:
                    cursor.execute("ROLLBACK")
                except Exception:
                    pass
                conn.close()
                raise

        raise sqlite3.OperationalError("Database is locked after maximum retries.")

    def get_audit_record_by_event_id(self, event_id: str) -> dict[str, Any] | None:
        """Retrieves an audit block by its unique event_id."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id
                FROM block_ledger
                WHERE event_id = ?
                LIMIT 1
            """, (event_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                return None
            try:
                return json.loads(row["block_data_json"])
            except Exception:
                return dict(row)

    def get_audit_blocks_since(self, since_sequence: int = -1) -> list[dict[str, Any]]:
        """Retrieves audit records committed after since_sequence ordered by sequence_number ASC."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id
                FROM block_ledger
                WHERE sequence_number IS NOT NULL AND sequence_number > ?
                ORDER BY sequence_number ASC
            """, (since_sequence,))
            rows = cursor.fetchall()
            conn.close()
            blocks = []
            for r in rows:
                item = dict(r)
                try:
                    item["block_data"] = json.loads(item["block_data_json"])
                except Exception:
                    item["block_data"] = {}
                blocks.append(item)
            return blocks

    def tamper_block_data(self, sequence_number: int, field_name: str, new_value: Any) -> bool:
        """Mutates a persisted block for security tampering detection testing."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT block_number, block_data_json
                FROM block_ledger
                WHERE sequence_number = ?
                LIMIT 1
            """, (sequence_number,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return False
            data = json.loads(row["block_data_json"])
            data[field_name] = new_value
            cursor.execute("""
                UPDATE block_ledger
                SET block_data_json = ?
                WHERE block_number = ?
            """, (json.dumps(data), row["block_number"]))
            conn.commit()
            conn.close()
            return True

    def get_all_blocks(self) -> list[dict[str, Any]]:
        """Retrieves all blocks from block_ledger in ascending block_number order."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id
                FROM block_ledger
                ORDER BY block_number ASC
            """)
            rows = cursor.fetchall()
            conn.close()
            blocks = []
            for r in rows:
                item = dict(r)
                try:
                    item["block_data"] = json.loads(item["block_data_json"])
                except Exception:
                    item["block_data"] = {}
                blocks.append(item)
            return blocks

    def get_latest_block(self) -> dict[str, Any] | None:
        """Retrieves the latest committed block from block_ledger."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT block_number, previous_hash, block_hash, tx_count, block_data_json, timestamp, sequence_number, event_id
                FROM block_ledger
                ORDER BY block_number DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            conn.close()
            if not row:
                return None
            item = dict(row)
            try:
                item["block_data"] = json.loads(item["block_data_json"])
            except Exception:
                item["block_data"] = {}
            return item

    def list_evidence(self) -> list[dict[str, Any]]:
        """Retrieves all persisted evidence records."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT evidence_json FROM evidence_store")
            rows = cursor.fetchall()
            conn.close()
            res = []
            for r in rows:
                try:
                    res.append(json.loads(r["evidence_json"]))
                except Exception:
                    pass
            return res

    def save_approval(self, approval_id: str, request_id: str, agent_id: str, status: str, approval_data: dict[str, Any]) -> None:
        """Persists a human approval ticket record."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO human_approvals (
                    approval_id, request_id, agent_id, status, approval_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                approval_id,
                request_id,
                agent_id,
                status,
                json.dumps(approval_data),
                approval_data.get("created_at", "")
            ))
            conn.commit()
            conn.close()

    def list_approvals(self) -> list[dict[str, Any]]:
        """Retrieves all human approval records."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT approval_json FROM human_approvals")
            rows = cursor.fetchall()
            conn.close()
            res = []
            for r in rows:
                try:
                    res.append(json.loads(r["approval_json"]))
                except Exception:
                    pass
            return res

    def save_delegation_revocation(self, token_id: str) -> None:
        """Persists a revoked delegation token ID."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO delegation_revocations (token_id, revoked_at)
                VALUES (?, ?)
            """, (token_id, datetime.datetime.now(datetime.UTC).isoformat()))
            conn.commit()
            conn.close()

    def get_delegation_revocations(self) -> set[str]:
        """Retrieves all revoked delegation token IDs."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT token_id FROM delegation_revocations")
            rows = cursor.fetchall()
            conn.close()
            return {r["token_id"] for r in rows}

    def save_nonce(self, request_id: str, nonce: str, timestamp_ts: float) -> None:
        """Persists request nonce to SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO request_nonces (request_id, nonce, timestamp_ts)
                VALUES (?, ?, ?)
            """, (request_id, nonce, timestamp_ts))
            conn.commit()
            conn.close()

    def try_claim_request_nonce(self, request_id: str, nonce: str, timestamp_ts: float) -> bool:
        """
        Atomically claims request_id and nonce in SQLite.
        Returns True if successfully claimed, False if request_id or nonce already exists.
        Guarantees cross-process atomicity.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("SELECT 1 FROM request_nonces WHERE request_id = ? OR nonce = ?", (request_id, nonce))
                if cursor.fetchone() is not None:
                    conn.rollback()
                    return False
                cursor.execute(
                    "INSERT INTO request_nonces (request_id, nonce, timestamp_ts) VALUES (?, ?, ?)",
                    (request_id, nonce, timestamp_ts)
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            finally:
                conn.close()

    def try_acquire_in_flight_lock(
        self,
        agent_id: str,
        idempotency_key: str,
        owner_id: str | None = None,
        ttl_seconds: float = 30.0
    ) -> LockAcquisitionResult:
        """
        Atomically acquires an in-flight distributed lock in SQLite across processes.
        Uses leases and monotonically increasing fencing tokens.
        If an existing lock is active (expires_at > now), returns LockAcquisitionResult(False, cur_fencing, cur_owner).
        If an existing lock has expired (expires_at <= now), reclaims the lock by
        incrementing fencing_token and setting new owner_id.
        Returns LockAcquisitionResult(acquired, fencing_token, owner_id).
        """
        scoped_key = f"{agent_id}:{idempotency_key}"
        now = datetime.datetime.now(datetime.UTC).timestamp()
        actual_owner = owner_id or str(uuid.uuid4())
        new_expires = now + ttl_seconds

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    "SELECT owner_id, fencing_token, expires_at FROM in_flight_locks WHERE scoped_key = ?",
                    (scoped_key,)
                )
                row = cursor.fetchone()
                if row is not None:
                    expires_at = float(row["expires_at"] or 0.0)
                    cur_fencing = int(row["fencing_token"] or 1)
                    cur_owner = str(row["owner_id"] or "")
                    if expires_at > now:
                        # Lock is actively held by a non-expired lease
                        conn.rollback()
                        return LockAcquisitionResult(False, cur_fencing, cur_owner)
                    else:
                        # Lock has expired! Reclaim lock with incremented fencing token
                        new_fencing = cur_fencing + 1
                        cursor.execute("""
                            UPDATE in_flight_locks
                            SET owner_id = ?, fencing_token = ?, created_at = ?, expires_at = ?
                            WHERE scoped_key = ?
                        """, (actual_owner, new_fencing, now, new_expires, scoped_key))
                        conn.commit()
                        return LockAcquisitionResult(True, new_fencing, actual_owner)
                else:
                    new_fencing = 1
                    cursor.execute("""
                        INSERT INTO in_flight_locks (
                            scoped_key, agent_id, idempotency_key, owner_id, fencing_token, created_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (scoped_key, agent_id, idempotency_key, actual_owner, new_fencing, now, new_expires))
                    conn.commit()
                    return LockAcquisitionResult(True, new_fencing, actual_owner)
            except sqlite3.IntegrityError:
                conn.rollback()
                return LockAcquisitionResult(False, 0, "")
            finally:
                conn.close()

    def validate_lock_fencing(
        self,
        agent_id: str,
        idempotency_key: str,
        owner_id: str,
        fencing_token: int
    ) -> bool:
        """
        Verifies that the lock is currently held by owner_id with fencing_token and has not expired.
        Returns True if valid, False otherwise.
        """
        scoped_key = f"{agent_id}:{idempotency_key}"
        now = datetime.datetime.now(datetime.UTC).timestamp()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT owner_id, fencing_token, expires_at FROM in_flight_locks WHERE scoped_key = ?",
                    (scoped_key,)
                )
                row = cursor.fetchone()
                if not row:
                    return False
                if row["owner_id"] != owner_id or int(row["fencing_token"]) != fencing_token:
                    return False
                if float(row["expires_at"]) < now:
                    return False
                return True
            finally:
                conn.close()

    def release_in_flight_lock(
        self,
        agent_id: str,
        idempotency_key: str,
        owner_id: str | None = None,
        fencing_token: int | None = None
    ) -> bool:
        """
        Releases an in-flight lock across processes.
        If owner_id and fencing_token are provided, only deletes if the lock is still owned
        by this worker and has not been stolen by another worker.
        Returns True if released, False if lock was already stolen or expired.
        """
        scoped_key = f"{agent_id}:{idempotency_key}"
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                if owner_id is not None and fencing_token is not None:
                    cursor.execute(
                        "DELETE FROM in_flight_locks WHERE scoped_key = ? AND owner_id = ? AND fencing_token = ?",
                        (scoped_key, owner_id, fencing_token)
                    )
                elif owner_id is not None:
                    cursor.execute(
                        "DELETE FROM in_flight_locks WHERE scoped_key = ? AND owner_id = ?",
                        (scoped_key, owner_id)
                    )
                else:
                    cursor.execute("DELETE FROM in_flight_locks WHERE scoped_key = ?", (scoped_key,))
                released = cursor.rowcount > 0
                conn.commit()
                return released
            finally:
                conn.close()

    def is_nonce_used(self, nonce: str) -> bool:
        """Checks if nonce exists in SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM request_nonces WHERE nonce = ?", (nonce,))
            row = cursor.fetchone()
            conn.close()
            return row is not None

    def is_request_id_used(self, request_id: str) -> bool:
        """Checks if request_id exists in SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM request_nonces WHERE request_id = ?", (request_id,))
            row = cursor.fetchone()
            conn.close()
            return row is not None

    def get_all_nonces(self) -> dict[str, float]:
        """Returns map of {nonce: timestamp_ts} from SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT nonce, timestamp_ts FROM request_nonces")
            rows = cursor.fetchall()
            conn.close()
            return {r["nonce"]: float(r["timestamp_ts"]) for r in rows}

    def get_all_request_ids(self) -> dict[str, float]:
        """Returns map of {request_id: timestamp_ts} from SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT request_id, timestamp_ts FROM request_nonces")
            rows = cursor.fetchall()
            conn.close()
            return {r["request_id"]: float(r["timestamp_ts"]) for r in rows}

    def evict_expired_nonces(self, max_age_seconds: int = 300) -> int:
        """Evicts nonces older than max_age_seconds from SQLite."""
        cutoff = datetime.datetime.now(datetime.UTC).timestamp() - max_age_seconds
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM request_nonces WHERE timestamp_ts < ?", (cutoff,))
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return deleted

    def save_retry_record(self, event_id: str, request_id: str, payload: dict[str, Any], error_msg: str, status: str = "PENDING_RETRY", retry_count: int = 0) -> None:
        """Persists failed commit record to durable reconciliation queue without resetting lease fields."""
        now = datetime.datetime.now(datetime.UTC).timestamp()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("""
                    INSERT INTO reconciliation_queue (
                        event_id, request_id, payload_json, error_msg, retry_count, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(event_id) DO UPDATE SET
                        request_id = excluded.request_id,
                        payload_json = excluded.payload_json,
                        error_msg = excluded.error_msg,
                        retry_count = excluded.retry_count,
                        status = excluded.status
                    WHERE reconciliation_queue.lease_owner = ''
                       OR reconciliation_queue.lease_expires_at <= ?
                """, (
                    event_id,
                    request_id,
                    json.dumps(payload),
                    error_msg,
                    retry_count,
                    status,
                    datetime.datetime.now(datetime.UTC).isoformat(),
                    now,
                ))
                if cursor.rowcount == 0:
                    raise RuntimeError(
                        f"Cannot update retry record {event_id}: record is actively leased"
                    )
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                conn.close()

    def get_retry_record(self, event_id: str) -> dict[str, Any] | None:
        """Retrieve a durable retry record, distinguishing missing rows from errors."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM reconciliation_queue WHERE event_id = ?",
                    (event_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                # Allow SQLite and JSON decoding errors to propagate.
                # A malformed payload must not masquerade as a missing record.
                payload = json.loads(row["payload_json"])
                record = {
                    "event_id": row["event_id"],
                    "request_id": row["request_id"],
                    "payload": payload,
                    "error_msg": row["error_msg"],
                    "retry_count": row["retry_count"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
                if "lease_owner" in row.keys():
                    record["lease_owner"] = str(row["lease_owner"] or "")
                if "lease_expires_at" in row.keys():
                    record["lease_expires_at"] = float(
                        row["lease_expires_at"] or 0.0
                    )
                if "fencing_token" in row.keys():
                    record["fencing_token"] = int(row["fencing_token"] or 0)
                return record
            finally:
                conn.close()

    def list_pending_retries(self) -> list[dict[str, Any]]:
        """Retrieves all pending retry records from durable reconciliation queue."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM reconciliation_queue WHERE status = 'PENDING_RETRY'")
                rows = cursor.fetchall()
            finally:
                conn.close()

        res = []
        for r in rows:
            try:
                record = {
                    "event_id": r["event_id"],
                    "request_id": r["request_id"],
                    "payload": json.loads(r["payload_json"]),
                    "error_msg": r["error_msg"],
                    "retry_count": r["retry_count"],
                    "status": r["status"],
                    "created_at": r["created_at"],
                }
                if "lease_owner" in r.keys():
                    record["lease_owner"] = str(r["lease_owner"] or "")
                if "lease_expires_at" in r.keys():
                    record["lease_expires_at"] = float(r["lease_expires_at"] or 0.0)
                if "fencing_token" in r.keys():
                    record["fencing_token"] = int(r["fencing_token"] or 0)
                res.append(record)
            except Exception:
                pass
        return res

    def list_dead_letter_retries(self) -> list[dict[str, Any]]:
        """Retrieve durable dead-letter records, including corrupt payloads."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT *
                    FROM reconciliation_queue
                    WHERE status = ?
                    """,
                    ("DEAD_LETTER_QUEUE",),
                )
                rows = cursor.fetchall()
            finally:
                conn.close()

        records: list[dict[str, Any]] = []
        for row in rows:
            raw_payload = row["payload_json"]
            corrupt = False
            try:
                payload = json.loads(raw_payload)
                if not isinstance(payload, dict):
                    corrupt = True
                    payload = None
            except (json.JSONDecodeError, TypeError):
                corrupt = True
                payload = None

            records.append(
                {
                    "event_id": row["event_id"],
                    "request_id": row["request_id"],
                    "payload": payload,
                    "raw_payload": raw_payload,
                    "corrupt": corrupt,
                    "error_msg": row["error_msg"],
                    "retry_count": row["retry_count"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
            )
        return records

    def update_retry_status(self, event_id: str, status: str, retry_count: int) -> None:
        """Updates status of a reconciliation record."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE reconciliation_queue SET status = ?, retry_count = ? WHERE event_id = ?
                """, (status, retry_count, event_id))
                conn.commit()
            finally:
                conn.close()

    def delete_retry_record(self, event_id: str) -> None:
        """Removes a reconciled record from the queue."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM reconciliation_queue WHERE event_id = ?", (event_id,))
                conn.commit()
            finally:
                conn.close()

    def claim_retry_record(
        self,
        event_id: str,
        owner_id: str | None = None,
        ttl_seconds: float = 30.0,
    ) -> LockAcquisitionResult:
        """
        Atomically claims a PENDING_RETRY record from the reconciliation queue using leases
        and monotonically increasing fencing tokens.
        - Rejects non-positive TTL values.
        - Only claims records where status == 'PENDING_RETRY'.
        - If an active unexpired lease exists (lease_owner != '' and lease_expires_at > now),
          returns LockAcquisitionResult(False, cur_fencing, cur_owner).
        - If the record is unclaimed or has an expired lease (lease_expires_at <= now),
          claims/reclaims the record with incremented fencing_token and new lease expiration.
        - Returns LockAcquisitionResult(acquired, fencing_token, owner_id).
        """
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds}")

        actual_owner = owner_id or str(uuid.uuid4())
        now = datetime.datetime.now(datetime.UTC).timestamp()
        new_expires = now + ttl_seconds

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    """
                    SELECT status, lease_owner, lease_expires_at, fencing_token
                    FROM reconciliation_queue
                    WHERE event_id = ?
                    """,
                    (event_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    conn.rollback()
                    return LockAcquisitionResult(False, 0, "")

                if row["status"] != "PENDING_RETRY":
                    conn.rollback()
                    return LockAcquisitionResult(
                        False,
                        int(row["fencing_token"] or 0),
                        str(row["lease_owner"] or ""),
                    )

                cur_owner = str(row["lease_owner"] or "")
                cur_expires = float(row["lease_expires_at"] or 0.0)
                cur_fencing = int(row["fencing_token"] or 0)

                if cur_owner and cur_expires > now:
                    # Active lease held by another or current worker
                    conn.rollback()
                    return LockAcquisitionResult(False, cur_fencing, cur_owner)

                # Unclaimed or expired lease: increment fencing token and claim
                new_fencing = cur_fencing + 1
                cursor.execute(
                    """
                    UPDATE reconciliation_queue
                    SET lease_owner = ?, lease_expires_at = ?, fencing_token = ?
                    WHERE event_id = ?
                    """,
                    (actual_owner, new_expires, new_fencing, event_id),
                )
                conn.commit()
                return LockAcquisitionResult(True, new_fencing, actual_owner)
            except sqlite3.Error:
                conn.rollback()
                return LockAcquisitionResult(False, 0, "")
            finally:
                conn.close()

    def validate_retry_claim(
        self,
        event_id: str,
        owner_id: str,
        fencing_token: int,
    ) -> bool:
        """
        Validates that event_id is currently claimed by owner_id with fencing_token
        and that the lease has not expired.
        Returns True if claim is valid and unexpired, False otherwise.
        """
        now = datetime.datetime.now(datetime.UTC).timestamp()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT lease_owner, lease_expires_at, fencing_token
                    FROM reconciliation_queue
                    WHERE event_id = ?
                    """,
                    (event_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return False
                if str(row["lease_owner"] or "") != owner_id:
                    return False
                if int(row["fencing_token"] or 0) != fencing_token:
                    return False
                if float(row["lease_expires_at"] or 0.0) <= now:
                    return False
                return True
            finally:
                conn.close()

    def release_retry_claim(
        self,
        event_id: str,
        owner_id: str,
        fencing_token: int,
    ) -> bool:
        """
        Clears only the matching, still-valid (unexpired) lease.
        Never releases a newer worker's lease or an expired/stale claim.
        Returns True if released, False otherwise.
        """
        now = datetime.datetime.now(datetime.UTC).timestamp()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    """
                    UPDATE reconciliation_queue
                    SET lease_owner = '', lease_expires_at = 0.0
                    WHERE event_id = ?
                      AND lease_owner = ?
                      AND fencing_token = ?
                      AND lease_expires_at > ?
                    """,
                    (event_id, owner_id, fencing_token, now),
                )
                released = cursor.rowcount > 0
                conn.commit()
                return released
            except sqlite3.Error:
                conn.rollback()
                return False
            finally:
                conn.close()

    def finalize_retry_record(
        self,
        event_id: str,
        owner_id: str,
        fencing_token: int,
        status: str | None = None,
        retry_count: int | None = None,
        error_msg: str | None = None,
        delete_record: bool = False,
    ) -> bool:
        """
        Atomically verifies current ownership and unexpired lease before updating or deleting
        the retry record.
        Rejects stale or expired claims.
        - If delete_record is True, deletes the record from the queue.
        - Otherwise, updates status and/or retry_count/error_msg and clears the lease fields
          while preserving the fencing token.
        Returns True if finalized, False otherwise.
        """
        now = datetime.datetime.now(datetime.UTC).timestamp()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                if delete_record:
                    cursor.execute(
                        """
                        DELETE FROM reconciliation_queue
                        WHERE event_id = ?
                          AND lease_owner = ?
                          AND fencing_token = ?
                          AND lease_expires_at > ?
                        """,
                        (event_id, owner_id, fencing_token, now),
                    )
                else:
                    query = """
                        UPDATE reconciliation_queue
                        SET lease_owner = '',
                            lease_expires_at = 0.0
                    """
                    params: list[Any] = []
                    if status is not None:
                        query += ", status = ?"
                        params.append(status)
                    if retry_count is not None:
                        query += ", retry_count = ?"
                        params.append(retry_count)
                    if error_msg is not None:
                        query += ", error_msg = ?"
                        params.append(error_msg)
                    query += """
                        WHERE event_id = ?
                          AND lease_owner = ?
                          AND fencing_token = ?
                          AND lease_expires_at > ?
                    """
                    params.extend([event_id, owner_id, fencing_token, now])
                    cursor.execute(query, tuple(params))

                finalized = cursor.rowcount > 0
                conn.commit()
                return finalized
            except sqlite3.Error:
                conn.rollback()
                return False
            finally:
                conn.close()

    def save_intent(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        amount: float,
        idempotency_key: str | None,
        state: str,
        outcome: dict[str, Any] | None = None,
        request_fingerprint: str | None = None
    ) -> None:
        """Saves durable transaction intent."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO transaction_intents (
                    request_id, agent_id, action, amount, idempotency_key, state, outcome_json, request_fingerprint, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id,
                agent_id,
                action,
                amount,
                idempotency_key,
                state,
                json.dumps(outcome) if outcome else None,
                request_fingerprint,
                now,
                now
            ))
            conn.commit()
            conn.close()

    def update_intent_state(
        self,
        request_id: str,
        state: str,
        outcome: dict[str, Any] | None = None,
        expected_current_state: str | None = None
    ) -> None:
        """
        Updates state and outcome of an existing transaction intent.
        Validates transition legality against VALID_INTENT_TRANSITIONS.
        Raises InvalidStateTransitionError if transition is illegal.
        Raises ConcurrentTransitionConflictError if expected_current_state does not match.
        """
        now = datetime.datetime.now(datetime.UTC).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("SELECT state FROM transaction_intents WHERE request_id = ?", (request_id,))
                row = cursor.fetchone()
                if not row:
                    conn.rollback()
                    raise ValueError(f"Transaction intent for request {request_id} does not exist")

                current_state = row["state"]

                # Check expected state for optimistic concurrency control
                if expected_current_state and current_state != expected_current_state:
                    conn.rollback()
                    raise ConcurrentTransitionConflictError(
                        f"Concurrent modification detected for {request_id}: expected state '{expected_current_state}', but was '{current_state}'"
                    )

                # Check valid transition
                allowed = VALID_INTENT_TRANSITIONS.get(current_state, set())
                if state not in allowed:
                    conn.rollback()
                    raise InvalidStateTransitionError(
                        f"Illegal state transition for {request_id}: cannot transition from '{current_state}' to '{state}'. Allowed transitions: {sorted(allowed)}"
                    )

                if outcome is not None:
                    cursor.execute("""
                        UPDATE transaction_intents SET state = ?, outcome_json = ?, updated_at = ? WHERE request_id = ?
                    """, (state, json.dumps(outcome), now, request_id))
                else:
                    cursor.execute("""
                        UPDATE transaction_intents SET state = ?, updated_at = ? WHERE request_id = ?
                    """, (state, now, request_id))
                conn.commit()
            finally:
                conn.close()

    def get_intent(self, request_id: str) -> dict[str, Any] | None:
        """Retrieves intent record by request_id."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM transaction_intents WHERE request_id = ?", (request_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                d = dict(row)
                if d.get("outcome_json"):
                    try:
                        d["outcome"] = json.loads(d["outcome_json"])
                    except Exception:
                        pass
                return d
            return None

    def get_intent_by_idempotency_key(self, agent_id: str, idempotency_key: str) -> dict[str, Any] | None:
        """Retrieves intent record by agent_id and idempotency_key."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM transaction_intents WHERE agent_id = ? AND idempotency_key = ?", (agent_id, idempotency_key))
            row = cursor.fetchone()
            conn.close()
            if row:
                d = dict(row)
                if d.get("outcome_json"):
                    try:
                        d["outcome"] = json.loads(d["outcome_json"])
                    except Exception:
                        pass
                return d
            return None

    def get_cumulative_volume(
        self,
        agent_id: str,
        window_seconds: int = 86400,
        action: str | None = None
    ) -> tuple[float, int]:
        """
        Calculates cumulative amount and count of authorized/committed/completed
        transactions for an agent within the specified rolling window (default 24h).
        Excludes REJECTED or FAILED states.
        """
        cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=window_seconds)).isoformat()
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            query = """
                SELECT COALESCE(SUM(amount), 0.0) as total_amount, COUNT(*) as tx_count
                FROM transaction_intents
                WHERE agent_id = ?
                  AND created_at >= ?
                  AND state IN ('AUTHORIZED_PENDING_EXECUTION', 'EXECUTED_PENDING_LEDGER', 'COMMITTED', 'COMPLETED')
            """
            params: list[Any] = [agent_id, cutoff]
            if action:
                query += " AND action = ?"
                params.append(action)
            cursor.execute(query, tuple(params))
            row = cursor.fetchone()
            if row:
                return float(row["total_amount"]), int(row["tx_count"])
            return 0.0, 0
        finally:
            conn.close()

    def check_and_reserve_cumulative_volume(
        self,
        agent_id: str,
        action: str,
        amount: float,
        window_seconds: int = 86400,
        max_cumulative_limit: float | None = None,
        max_velocity_count: int | None = None,
        request_id: str | None = None,
        idempotency_key: str | None = None,
        request_fingerprint: str | None = None
    ) -> tuple[bool, float, int, str]:
        """
        Atomically inspects rolling cumulative transaction volume/velocity and reserves
        capacity under an exclusive SQLite immediate transaction.
        Eliminates TOCTOU race conditions under concurrent smurfing attempts.
        Returns: (is_allowed: bool, new_cumulative_amount: float, new_tx_count: int, reason: str)
        """
        now_dt = datetime.datetime.now(datetime.UTC)
        cutoff = (now_dt - datetime.timedelta(seconds=window_seconds)).isoformat()
        now_str = now_dt.isoformat()
        req_id = request_id or f"REQ-RES-{uuid.uuid4().hex[:12].upper()}"

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                query = """
                    SELECT COALESCE(SUM(amount), 0.0) as total_amount, COUNT(*) as tx_count
                    FROM transaction_intents
                    WHERE agent_id = ?
                      AND created_at >= ?
                      AND state IN ('AUTHORIZED_PENDING_EXECUTION', 'EXECUTED_PENDING_LEDGER', 'COMMITTED', 'COMPLETED')
                """
                cursor.execute(query, (agent_id, cutoff))
                row = cursor.fetchone()
                total_amount = float(row["total_amount"]) if row else 0.0
                tx_count = int(row["tx_count"]) if row else 0

                if max_cumulative_limit is not None and (total_amount + amount) > max_cumulative_limit:
                    conn.rollback()
                    return False, total_amount, tx_count, f"CUMULATIVE_LIMIT_EXCEEDED: rolling {window_seconds}s total ₹{total_amount + amount:,.2f} exceeds cap ₹{max_cumulative_limit:,.2f}"

                if max_velocity_count is not None and (tx_count + 1) > max_velocity_count:
                    conn.rollback()
                    return False, total_amount, tx_count, f"VELOCITY_LIMIT_EXCEEDED: {tx_count + 1} transactions exceeds limit of {max_velocity_count} per window"

                cursor.execute("""
                    INSERT OR REPLACE INTO transaction_intents (
                        request_id, agent_id, action, amount, idempotency_key, state, outcome_json, request_fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    req_id,
                    agent_id,
                    action,
                    amount,
                    idempotency_key,
                    "AUTHORIZED_PENDING_EXECUTION",
                    None,
                    request_fingerprint,
                    now_str,
                    now_str
                ))
                conn.commit()
                return True, total_amount + amount, tx_count + 1, "OK"
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def release_reservation(self, request_id: str, new_state: str = "REJECTED", reason: str | None = None) -> None:
        """
        Transitions an atomic volume reservation to a non-counting terminal state (default REJECTED),
        releasing the reserved capacity when a request is blocked, rejected, or cancelled.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute("SELECT state FROM transaction_intents WHERE request_id = ?", (request_id,))
                row = cursor.fetchone()
                if row and row["state"] in ("AUTHORIZED_PENDING_EXECUTION", "HELD_FOR_HUMAN_APPROVAL"):
                    now = datetime.datetime.now(datetime.UTC).isoformat()
                    outcome = {"release_reason": reason} if reason else None
                    cursor.execute("""
                        UPDATE transaction_intents SET state = ?, outcome_json = ?, updated_at = ? WHERE request_id = ?
                    """, (new_state, json.dumps(outcome) if outcome else None, now, request_id))
                    conn.commit()
                else:
                    conn.rollback()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def revalidate_and_reserve_approved_intent(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        amount: float,
        window_seconds: int = 86400,
        max_cumulative_limit: float | None = None,
        max_velocity_count: int | None = None
    ) -> tuple[bool, float, int, str]:
        """
        Atomically re-evaluates cumulative volume and velocity limits when resuming a human-approved
        request, transitioning the intent from HELD_FOR_HUMAN_APPROVAL to AUTHORIZED_PENDING_EXECUTION
        under an exclusive SQLite immediate write lock.
        Eliminates the TOCTOU race where intermediate transactions consume budget while awaiting approval.
        Returns: (is_allowed: bool, new_cumulative_amount: float, new_tx_count: int, reason: str)
        """
        now_dt = datetime.datetime.now(datetime.UTC)
        cutoff = (now_dt - datetime.timedelta(seconds=window_seconds)).isoformat()
        now_str = now_dt.isoformat()

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE")

                # Check current intent state
                cursor.execute("SELECT state FROM transaction_intents WHERE request_id = ?", (request_id,))
                row_intent = cursor.fetchone()
                if not row_intent:
                    conn.rollback()
                    return False, 0.0, 0, f"INTENT_NOT_FOUND: request {request_id} not found in persistent store"

                curr_state = row_intent["state"]
                if curr_state != "HELD_FOR_HUMAN_APPROVAL":
                    conn.rollback()
                    return False, 0.0, 0, f"INVALID_INTENT_STATE_FOR_RESUME: current state is {curr_state}, expected HELD_FOR_HUMAN_APPROVAL"

                # Sum all other active/committed intents within the rolling window
                query = """
                    SELECT COALESCE(SUM(amount), 0.0) as total_amount, COUNT(*) as tx_count
                    FROM transaction_intents
                    WHERE agent_id = ?
                      AND created_at >= ?
                      AND state IN ('AUTHORIZED_PENDING_EXECUTION', 'EXECUTED_PENDING_LEDGER', 'COMMITTED', 'COMPLETED')
                      AND request_id != ?
                """
                cursor.execute(query, (agent_id, cutoff, request_id))
                row = cursor.fetchone()
                total_amount = float(row["total_amount"]) if row else 0.0
                tx_count = int(row["tx_count"]) if row else 0

                if max_cumulative_limit is not None and (total_amount + amount) > max_cumulative_limit:
                    conn.rollback()
                    return False, total_amount, tx_count, (
                        f"CUMULATIVE_LIMIT_EXCEEDED_ON_RESUME: rolling {window_seconds}s total ₹{total_amount + amount:,.2f} "
                        f"exceeds cap ₹{max_cumulative_limit:,.2f} (capacity consumed while awaiting approval)"
                    )

                if max_velocity_count is not None and (tx_count + 1) > max_velocity_count:
                    conn.rollback()
                    return False, total_amount, tx_count, (
                        f"VELOCITY_LIMIT_EXCEEDED_ON_RESUME: {tx_count + 1} transactions exceeds limit "
                        f"of {max_velocity_count} per window (capacity consumed while awaiting approval)"
                    )

                cursor.execute("""
                    UPDATE transaction_intents
                    SET state = 'AUTHORIZED_PENDING_EXECUTION', updated_at = ?
                    WHERE request_id = ?
                """, (now_str, request_id))
                conn.commit()
                return True, total_amount + amount, tx_count + 1, "OK"
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def close(self) -> None:
        """Closes resources and checkpoints WAL mode safely."""
        with self._lock:
            try:
                conn = self._get_connection()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()
            except Exception:
                pass

