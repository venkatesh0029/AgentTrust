"""
Persistent SQLite Storage Engine for AgentTrust Framework.
Provides SQLite database persistence for CA certificates, Agent Registry, Replay Protection Nonces,
Off-Chain Evidence Records, CRL Revocations, and Block Ledger State across server restarts.
"""

import datetime
import json
import sqlite3
import threading
from typing import Any


class PersistentStorageEngine:
    """
    SQLite Database Manager providing atomic, concurrency-safe persistence.
    """

    def __init__(self, db_path: str = "agenttrust_persistent.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
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
                    created_at TEXT NOT NULL
                )
            """)

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
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

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
        """Persists failed commit record to durable reconciliation queue."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO reconciliation_queue (
                    event_id, request_id, payload_json, error_msg, retry_count, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                request_id,
                json.dumps(payload),
                error_msg,
                retry_count,
                status,
                datetime.datetime.now(datetime.timezone.utc).isoformat()
            ))
            conn.commit()
            conn.close()

    def list_pending_retries(self) -> list[dict[str, Any]]:
        """Retrieves all pending retry records from durable reconciliation queue."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reconciliation_queue WHERE status = 'PENDING_RETRY'")
            rows = cursor.fetchall()
            conn.close()
            res = []
            for r in rows:
                try:
                    res.append({
                        "event_id": r["event_id"],
                        "request_id": r["request_id"],
                        "payload": json.loads(r["payload_json"]),
                        "error_msg": r["error_msg"],
                        "retry_count": r["retry_count"],
                        "status": r["status"],
                        "created_at": r["created_at"]
                    })
                except Exception:
                    pass
            return res

    def update_retry_status(self, event_id: str, status: str, retry_count: int) -> None:
        """Updates status of a reconciliation record."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE reconciliation_queue SET status = ?, retry_count = ? WHERE event_id = ?
            """, (status, retry_count, event_id))
            conn.commit()
            conn.close()

    def delete_retry_record(self, event_id: str) -> None:
        """Removes a reconciled record from the queue."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM reconciliation_queue WHERE event_id = ?", (event_id,))
            conn.commit()
            conn.close()

    def save_intent(self, request_id: str, agent_id: str, action: str, amount: float, idempotency_key: str | None, state: str, outcome: dict[str, Any] | None = None) -> None:
        """Saves durable transaction intent."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO transaction_intents (
                    request_id, agent_id, action, amount, idempotency_key, state, outcome_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id,
                agent_id,
                action,
                amount,
                idempotency_key,
                state,
                json.dumps(outcome) if outcome else None,
                now,
                now
            ))
            conn.commit()
            conn.close()

    def update_intent_state(self, request_id: str, state: str, outcome: dict[str, Any] | None = None) -> None:
        """Updates state and outcome of an existing transaction intent."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if outcome is not None:
                cursor.execute("""
                    UPDATE transaction_intents SET state = ?, outcome_json = ?, updated_at = ? WHERE request_id = ?
                """, (state, json.dumps(outcome), now, request_id))
            else:
                cursor.execute("""
                    UPDATE transaction_intents SET state = ?, updated_at = ? WHERE request_id = ?
                """, (state, now, request_id))
            conn.commit()
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

