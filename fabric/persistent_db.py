"""
Persistent SQLite Storage Engine for AgentTrust Framework.
Provides SQLite database persistence for CA certificates, Agent Registry, Replay Protection Nonces,
Off-Chain Evidence Records, CRL Revocations, and Block Ledger State across server restarts.
"""

import sqlite3
import json
import threading
import os
import datetime
from typing import Dict, Any, List, Optional, Set

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
                    registered_at TEXT NOT NULL
                )
            """)

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

            conn.commit()
            conn.close()

    def save_agent(self, agent_data: Dict[str, Any]) -> None:
        """Persists agent record to SQLite."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO agents (
                    agent_id, agent_name, owner, status, public_key, certificate, policy_id, key_version, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_data["agent_id"],
                agent_data["agent_name"],
                agent_data["owner"],
                agent_data["status"],
                agent_data["public_key"],
                agent_data.get("certificate", ""),
                agent_data.get("policy_id", "FIN-POLICY-001"),
                agent_data.get("key_version", 1),
                agent_data.get("registered_at", "")
            ))
            conn.commit()
            conn.close()

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
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

    def list_agents(self) -> List[Dict[str, Any]]:
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

    def get_crl_revocations(self) -> Set[str]:
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

    def get_ca_credentials(self, key_id: str = "root_ca") -> Optional[Dict[str, str]]:
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

    def save_evidence(self, evidence_id: str, request_id: str, agent_id: str, evidence_hash: str, evidence_data: Dict[str, Any]) -> None:
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

    def save_block(self, previous_hash: str, block_hash: str, tx_count: int, block_data: Dict[str, Any], timestamp: str) -> int:
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
