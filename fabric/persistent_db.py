"""
Persistent SQLite Storage Engine for AgentTrust Framework.
Provides SQLite database persistence for CA certificates, Agent Registry, Replay Protection Nonces,
Off-Chain Evidence Records, CRL Revocations, and Block Ledger State across server restarts.
"""

import datetime
import json
import sqlite3
import threading
import uuid
from typing import Any


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal transition is attempted in the transaction intent state machine."""
    pass


class ConcurrentTransitionConflictError(RuntimeError):
    """Raised when a concurrent worker modifies an intent before the current transition completes."""
    pass


class FencingTokenError(RuntimeError):
    """Raised when a worker's lock lease was preempted, stolen, or superseded by a newer fencing token."""
    pass


class LockLeaseExpiredError(RuntimeError):
    """Raised when an operation is attempted after lock lease expiry."""
    pass


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
    "AUTHORIZED_PENDING_EXECUTION": {"EXECUTED_PENDING_LEDGER", "EXECUTION_FAILED", "REJECTED"},
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

    def __init__(self, db_path: str = "agenttrust_persistent.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=15000")
        except Exception:
            pass
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # 1. Agent Registry Table
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
                    private_key TEXT
                )
            """)

            cursor.execute("PRAGMA table_info(agents)")
            existing_cols = [row["name"] for row in cursor.fetchall()]
            if "private_key" not in existing_cols:
                cursor.execute("ALTER TABLE agents ADD COLUMN private_key TEXT")

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

            # 4. Fabric Block Ledger Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS block_ledger (
                    block_number INTEGER PRIMARY KEY AUTOINCREMENT,
                    previous_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL,
                    tx_count INTEGER NOT NULL,
                    block_data_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

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
        """Persists agent record to SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO agents (
                    agent_id, agent_name, owner, status, public_key, certificate, policy_id, key_version, registered_at, private_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                agent_data.get("private_key", "")
            ))
            conn.commit()
            conn.close()

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Retrieves agent record from SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
            return None

    def list_agents(self) -> list[dict[str, Any]]:
        """Retrieves all registered agents from SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents")
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]

    def save_crl_revocation(self, fingerprint: str) -> None:
        """Persists a certificate revocation fingerprint."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO crl_revocations (fingerprint, revoked_at)
                VALUES (?, ?)
            """, (fingerprint.upper(), datetime.datetime.now(datetime.timezone.utc).isoformat()))
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
            """, (key_id, private_key_pem, certificate_pem, datetime.datetime.now(datetime.timezone.utc).isoformat()))
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

    def save_block(self, previous_hash: str, block_hash: str, tx_count: int, block_data: dict[str, Any], timestamp: str) -> int:
        """Persists committed block to SQLite block ledger."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO block_ledger (previous_hash, block_hash, tx_count, block_data_json, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                previous_hash,
                block_hash,
                tx_count,
                json.dumps(block_data),
                timestamp
            ))
            block_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return block_id or 1

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
            """, (token_id, datetime.datetime.now(datetime.timezone.utc).isoformat()))
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
        cutoff = datetime.datetime.now(datetime.timezone.utc).timestamp() - max_age_seconds
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
                    datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
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
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
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
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
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

    def close(self) -> None:
        """Closes resources and checkpoints WAL mode safely."""
        with self._lock:
            try:
                conn = self._get_connection()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()
            except Exception:
                pass

