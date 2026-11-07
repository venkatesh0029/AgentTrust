import copy
import datetime
import hmac
import json
import os
import sqlite3
import threading
import uuid
from typing import Any

from database_config import resolve_database_path
from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager
from secret_manager.secret_models import SecretRecord, ValidationResult
from secret_manager.secret_provider import SecretProvider, get_centralized_secret_provider


class ProcurementService:
    """Finance & Procurement Database & Business Logic with thread-safe concurrency control and durable SQLite persistence."""

    def __init__(self, db_path: str | None = None):
        self._reimbursements: dict[str, dict[str, Any]] = {}
        self._purchase_orders: dict[str, dict[str, Any]] = {}
        self._fund_transfers: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._po_counter = 5000
        self._tf_counter = 2000
        self._reimb_counter = 1000
        self._db_path = resolve_database_path(db_path) if db_path else None
        if self._db_path:
            self._init_db()
            self._load_records()

    def _init_db(self) -> None:
        if not self._db_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        with sqlite3.connect(self._db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=30000;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS financial_purchase_orders (
                    po_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    supplier_id TEXT NOT NULL,
                    item_name TEXT NOT NULL,
                    amount REAL NOT NULL,
                    amount_canonical TEXT,
                    amount_minor_units INTEGER,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approval_reference TEXT,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS financial_fund_transfers (
                    transaction_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    target_account TEXT NOT NULL,
                    amount REAL NOT NULL,
                    amount_canonical TEXT,
                    amount_minor_units INTEGER,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approval_reference TEXT,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS financial_reimbursements (
                    transaction_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    employee_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    amount_canonical TEXT,
                    amount_minor_units INTEGER,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approval_reference TEXT,
                    timestamp TEXT NOT NULL
                );
            """)
            # Outbox and Intent tables for atomic transactional execution
            conn.execute("""
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
                );
            """)
            conn.execute("""
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
                );
            """)
            conn.commit()

    def _commit_financial_and_outbox(
        self,
        financial_sql: str,
        financial_params: tuple,
        outbox_record: dict[str, Any] | None,
        financial_record: dict[str, Any]
    ) -> None:
        """
        Transactional Outbox: Commits the financial database mutation AND the
        pending audit outbox event within a SINGLE atomic SQLite transaction.
        """
        if not self._db_path:
            return
        with sqlite3.connect(self._db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(financial_sql, financial_params)
            if outbox_record:
                ev_id = outbox_record.get("event_id") or f"EVENT-{uuid.uuid4().hex[:12].upper()}"
                req_id = outbox_record.get("request_id") or financial_record.get("request_id", "")
                ag_id = outbox_record.get("agent_id") or financial_record.get("agent_id", "")
                action = outbox_record.get("action", "FINANCIAL_ACTION")
                amount = float(outbox_record.get("amount") or financial_record.get("amount", 0.0))
                idemp_k = outbox_record.get("idempotency_key")
                fp = outbox_record.get("request_fingerprint")
                payload = copy.deepcopy(outbox_record.get("payload") or {})
                payload["transaction_data"] = financial_record
                payload["event_id"] = ev_id
                payload["request_id"] = req_id
                payload["agent_id"] = ag_id
                payload["action"] = action
                now_iso = datetime.datetime.now(datetime.UTC).isoformat()

                # Atomically insert pending audit event into reconciliation_queue
                cursor.execute("""
                    INSERT OR REPLACE INTO reconciliation_queue (
                        event_id, request_id, payload_json, error_msg, retry_count, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev_id,
                    req_id,
                    json.dumps(payload),
                    outbox_record.get("error_msg", "TRANSACTIONAL_OUTBOX_PENDING_DISPATCH"),
                    0,
                    "PENDING_RETRY",
                    now_iso
                ))

                # Atomically update transaction_intents state in the same SQLite transaction
                cursor.execute("""
                    INSERT OR REPLACE INTO transaction_intents (
                        request_id, agent_id, action, amount, idempotency_key, state, outcome_json, request_fingerprint, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    req_id,
                    ag_id,
                    action,
                    amount,
                    idemp_k,
                    "EXECUTED_PENDING_LEDGER",
                    json.dumps({"financial_record": financial_record}),
                    fp,
                    now_iso,
                    now_iso
                ))
            conn.commit()

    def _load_records(self) -> None:
        if not self._db_path or not os.path.exists(self._db_path):
            return
        with sqlite3.connect(self._db_path, timeout=30.0) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Load purchase orders
            cursor.execute("SELECT * FROM financial_purchase_orders")
            for r in cursor.fetchall():
                rec = dict(r)
                self._purchase_orders[rec["po_id"]] = rec
                p_id = rec.get("po_id", "")
                if p_id.startswith("PO-") and p_id[3:].isdigit():
                    self._po_counter = max(self._po_counter, int(p_id[3:]))

            # Load fund transfers
            cursor.execute("SELECT * FROM financial_fund_transfers")
            for r in cursor.fetchall():
                rec = dict(r)
                self._fund_transfers[rec["transaction_id"]] = rec
                t_id = rec.get("transaction_id", "")
                if t_id.startswith("TX-TRANSFER-") and t_id[12:].isdigit():
                    self._tf_counter = max(self._tf_counter, int(t_id[12:]))

            # Load reimbursements
            cursor.execute("SELECT * FROM financial_reimbursements")
            for r in cursor.fetchall():
                rec = dict(r)
                self._reimbursements[rec["transaction_id"]] = rec
                rb_id = rec.get("transaction_id", "")
                if rb_id.startswith("TX-REIMB-") and rb_id[9:].isdigit():
                    self._reimb_counter = max(self._reimb_counter, int(rb_id[9:]))

    def create_purchase_order(
        self,
        request_id: str,
        agent_id: str,
        supplier_id: str,
        item_name: str,
        amount: float,
        approval_ref: str | None = None,
        amount_canonical: str | None = None,
        amount_minor_units: int | None = None,
        currency: str = "INR",
        outbox_record: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        with self._lock:
            self._po_counter += 1
            po_id = f"PO-{self._po_counter}"
            record = {
                "po_id": po_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "supplier_id": supplier_id,
                "item_name": item_name,
                "amount": amount,
                "amount_canonical": amount_canonical or str(amount),
                "amount_minor_units": amount_minor_units,
                "currency": currency,
                "status": "ISSUED",
                "approval_reference": approval_ref,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
            }
            self._purchase_orders[po_id] = record
            if self._db_path:
                sql = """
                    INSERT OR REPLACE INTO financial_purchase_orders (
                        po_id, request_id, agent_id, supplier_id, item_name,
                        amount, amount_canonical, amount_minor_units, currency,
                        status, approval_reference, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = (
                    record["po_id"], record["request_id"], record["agent_id"],
                    record["supplier_id"], record["item_name"], record["amount"],
                    record["amount_canonical"], record["amount_minor_units"],
                    record["currency"], record["status"], record["approval_reference"],
                    record["timestamp"]
                )
                try:
                    self._commit_financial_and_outbox(sql, params, outbox_record, record)
                except Exception:
                    pass
            return record

    def get_purchase_order(self, po_id: str) -> dict[str, Any] | None:
        with self._lock:
            if po_id in self._purchase_orders:
                return self._purchase_orders[po_id]
            if self._db_path:
                try:
                    with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM financial_purchase_orders WHERE po_id = ?", (po_id,))
                        row = cursor.fetchone()
                        if row:
                            rec = dict(row)
                            self._purchase_orders[po_id] = rec
                            return rec
                except Exception:
                    pass
            return None

    def create_fund_transfer(
        self,
        request_id: str,
        agent_id: str,
        target_account: str,
        amount: float,
        approval_ref: str | None = None,
        amount_canonical: str | None = None,
        amount_minor_units: int | None = None,
        currency: str = "INR",
        outbox_record: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        with self._lock:
            self._tf_counter += 1
            tx_id = f"TX-TRANSFER-{self._tf_counter}"
            record = {
                "transaction_id": tx_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "target_account": target_account,
                "amount": amount,
                "amount_canonical": amount_canonical or str(amount),
                "amount_minor_units": amount_minor_units,
                "currency": currency,
                "status": "TRANSFERRED",
                "approval_reference": approval_ref,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
            }
            self._fund_transfers[tx_id] = record
            if self._db_path:
                sql = """
                    INSERT OR REPLACE INTO financial_fund_transfers (
                        transaction_id, request_id, agent_id, target_account,
                        amount, amount_canonical, amount_minor_units, currency,
                        status, approval_reference, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = (
                    record["transaction_id"], record["request_id"], record["agent_id"],
                    record["target_account"], record["amount"], record["amount_canonical"],
                    record["amount_minor_units"], record["currency"], record["status"],
                    record["approval_reference"], record["timestamp"]
                )
                try:
                    self._commit_financial_and_outbox(sql, params, outbox_record, record)
                except Exception:
                    pass
            return record

    def get_fund_transfer(self, tx_id: str) -> dict[str, Any] | None:
        with self._lock:
            if tx_id in self._fund_transfers:
                return self._fund_transfers[tx_id]
            if self._db_path:
                try:
                    with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM financial_fund_transfers WHERE transaction_id = ?", (tx_id,))
                        row = cursor.fetchone()
                        if row:
                            rec = dict(row)
                            self._fund_transfers[tx_id] = rec
                            return rec
                except Exception:
                    pass
            return None

    def create_reimbursement(
        self,
        request_id: str,
        agent_id: str,
        employee_id: str,
        amount: float,
        approval_ref: str | None = None,
        amount_canonical: str | None = None,
        amount_minor_units: int | None = None,
        currency: str = "INR",
        outbox_record: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        with self._lock:
            self._reimb_counter += 1
            tx_id = f"TX-REIMB-{self._reimb_counter}"
            record = {
                "transaction_id": tx_id,
                "request_id": request_id,
                "agent_id": agent_id,
                "employee_id": employee_id,
                "amount": amount,
                "amount_canonical": amount_canonical or str(amount),
                "amount_minor_units": amount_minor_units,
                "currency": currency,
                "status": "PROCESSED",
                "approval_reference": approval_ref,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
            }
            self._reimbursements[tx_id] = record
            if self._db_path:
                sql = """
                    INSERT OR REPLACE INTO financial_reimbursements (
                        transaction_id, request_id, agent_id, employee_id,
                        amount, amount_canonical, amount_minor_units, currency,
                        status, approval_reference, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = (
                    record["transaction_id"], record["request_id"], record["agent_id"],
                    record["employee_id"], record["amount"], record["amount_canonical"],
                    record["amount_minor_units"], record["currency"], record["status"],
                    record["approval_reference"], record["timestamp"]
                )
                try:
                    self._commit_financial_and_outbox(sql, params, outbox_record, record)
                except Exception:
                    pass
            return record

    def get_reimbursement(self, tx_id: str) -> dict[str, Any] | None:
        with self._lock:
            if tx_id in self._reimbursements:
                return self._reimbursements[tx_id]
            if self._db_path:
                try:
                    with sqlite3.connect(self._db_path, timeout=30.0) as conn:
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM financial_reimbursements WHERE transaction_id = ?", (tx_id,))
                        row = cursor.fetchone()
                        if row:
                            rec = dict(row)
                            self._reimbursements[tx_id] = rec
                            return rec
                except Exception:
                    pass
            return None


class _ProtectedFinanceAPIMeta(type):
    """Metaclass allowing dynamic resolution of GATEWAY_SECRET via centralized SecretProvider."""

    @property
    def GATEWAY_SECRET(cls) -> str:
        provider = getattr(cls, "_shared_secret_provider", None)
        if provider:
            return provider.get_active_secret().secret_value
        active = getattr(cls, "_active_secret", None)
        if active:
            return active
        provider = get_centralized_secret_provider()
        cls._shared_secret_provider = provider
        active_val = provider.get_active_secret().secret_value
        cls._active_secret = active_val
        return active_val

    @GATEWAY_SECRET.setter
    def GATEWAY_SECRET(cls, value: str) -> None:
        cls._active_secret = value
        provider = getattr(cls, "_shared_secret_provider", None)
        if provider:
            provider.rotate_secret(new_secret=value)


class ProtectedFinanceAPI(metaclass=_ProtectedFinanceAPIMeta):
    """
    Protected Procurement & Finance API Wrapper enforcing Gateway Service Authentication & Direct Access Denial.
    Requires:
    1. Internal Gateway Secret Token (validated via centralized SecretProvider in constant time)
    2. Action Gateway Service Identity ('AgentTrust-ActionGateway-Service')
    3. Action Gateway Service RSA Signature verification.
    4. Idempotency Key check.
    5. Side-Effect Fencing Token check (Downstream boundary protection).
    """

    def __init__(
        self,
        persistent_db_path: str | None = None,
        gateway_secret: str | None = None,
        secret_provider: SecretProvider | None = None
    ):
        self._persistent_db_path = (
            resolve_database_path(persistent_db_path)
            if (persistent_db_path is not None or os.environ.get("AGENTTRUST_DB_PATH"))
            else None
        )
        # Centralized secret provider integration
        if secret_provider is not None:
            self._secret_provider = secret_provider
        elif gateway_secret:
            self._secret_provider = get_centralized_secret_provider(explicit_secret=gateway_secret)
        elif getattr(ProtectedFinanceAPI, "_shared_secret_provider", None) is not None:
            self._secret_provider = ProtectedFinanceAPI._shared_secret_provider
        else:
            self._secret_provider = get_centralized_secret_provider()

        ProtectedFinanceAPI._shared_secret_provider = self._secret_provider
        active_rec = self._secret_provider.get_active_secret()
        self._gateway_secret = active_rec.secret_value
        ProtectedFinanceAPI._active_secret = active_rec.secret_value

        self.service = ProcurementService(db_path=self._persistent_db_path)
        self._idempotency_cache: dict[str, dict[str, Any]] = {}
        self._idempotency_lock = threading.Lock()
        self._fencing_tokens: dict[str, int] = {}
        self._fencing_lock = threading.Lock()
        if self._persistent_db_path:
            self._init_fencing_db()
            self._load_fencing_tokens()
        # Generate Gateway Service RSA Keypair for Service-to-Service mTLS/Signing
        self.gateway_service_private_key = KeyManager.generate_key_pair(2048)
        self.gateway_service_public_key_pem = KeyManager.public_key_to_pem(
            self.gateway_service_private_key.public_key()
        )
        self.gateway_service_private_key_pem = KeyManager.private_key_to_pem(
            self.gateway_service_private_key
        )

    @property
    def secret_provider(self) -> SecretProvider:
        return self._secret_provider

    @property
    def gateway_secret(self) -> str:
        if self._secret_provider:
            return self._secret_provider.get_active_secret().secret_value
        return self._gateway_secret

    @gateway_secret.setter
    def gateway_secret(self, value: str) -> None:
        self._gateway_secret = value
        ProtectedFinanceAPI._active_secret = value
        if self._secret_provider:
            self._secret_provider.rotate_secret(new_secret=value)

    @property
    def GATEWAY_SECRET(self) -> str:
        return self.gateway_secret

    @GATEWAY_SECRET.setter
    def GATEWAY_SECRET(self, value: str) -> None:
        self.gateway_secret = value

    def validate_gateway_token(self, candidate_token: str) -> ValidationResult:
        """Validates candidate token against active and permitted previous secret versions in constant time."""
        if not candidate_token or not isinstance(candidate_token, str):
            return ValidationResult(is_valid=False, error="INVALID_SECRET")
        if self._secret_provider:
            return self._secret_provider.validate_secret(candidate_token)
        is_match = hmac.compare_digest(candidate_token, self._gateway_secret)
        return ValidationResult(is_valid=is_match, error=None if is_match else "INVALID_SECRET")

    def rotate_secret(self, new_secret: str | None = None, grace_period_seconds: int = 3600) -> SecretRecord:
        """Rotates gateway secret with a configured grace period for previous credentials."""
        rec = self._secret_provider.rotate_secret(new_secret=new_secret, grace_period_seconds=grace_period_seconds)
        self._gateway_secret = rec.secret_value
        ProtectedFinanceAPI._active_secret = rec.secret_value
        return rec

    def revoke_secret(self, key_id: str, reason: str = "EMERGENCY_REVOCATION") -> bool:
        """Immediately revokes a compromised secret version."""
        return self._secret_provider.revoke_secret(key_id=key_id, reason=reason)

    def get_secret_metadata(self) -> dict[str, Any]:
        """Returns safe, non-sensitive secret metadata."""
        return self._secret_provider.get_metadata()

    def _init_fencing_db(self) -> None:
        if not self._persistent_db_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self._persistent_db_path)), exist_ok=True)
        with sqlite3.connect(self._persistent_db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=30000;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS downstream_fencing_tokens (
                    scope TEXT PRIMARY KEY,
                    fencing_token INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.commit()

    def _load_fencing_tokens(self) -> None:
        if not self._persistent_db_path or not os.path.exists(self._persistent_db_path):
            return
        with sqlite3.connect(self._persistent_db_path, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT scope, fencing_token FROM downstream_fencing_tokens")
            for row in cursor.fetchall():
                self._fencing_tokens[row[0]] = int(row[1])

    def _persist_fencing_token(self, scope: str, token: int) -> None:
        self._persist_fencing_tokens([(scope, token)])

    def _persist_fencing_tokens(self, updates: list[tuple[str, int]]) -> None:
        if not self._persistent_db_path or not updates:
            return
        now_iso = datetime.datetime.now(datetime.UTC).isoformat()
        with sqlite3.connect(self._persistent_db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA busy_timeout=30000;")
            conn.executemany("""
                INSERT INTO downstream_fencing_tokens (scope, fencing_token, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(scope) DO UPDATE SET
                    fencing_token = MAX(fencing_token, excluded.fencing_token),
                    updated_at = excluded.updated_at
            """, [(sc, tok, now_iso) for sc, tok in updates])
            conn.commit()

    def register_active_fencing_token(self, agent_id: str, scope: str, fencing_token: int) -> None:
        """Registers or advances active fencing token for a specific scope at downstream boundary."""
        with self._fencing_lock:
            scopes = [
                f"{agent_id}:{scope}",
                f"idemp:{agent_id}:{scope}",
                f"agent_resource:{agent_id}:{scope}",
                f"resource:{scope}"
            ]
            to_persist = []
            for sc in scopes:
                if fencing_token > self._fencing_tokens.get(sc, 0):
                    self._fencing_tokens[sc] = fencing_token
                    to_persist.append((sc, fencing_token))
            if to_persist:
                self._persist_fencing_tokens(to_persist)

    def create_gateway_auth_headers(self, request_id: str) -> dict[str, str]:
        """Helper for Action Gateway to generate signed service-to-service headers."""
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        payload = {
            "gateway_service": "AgentTrust-ActionGateway-Service",
            "request_id": request_id,
            "timestamp": timestamp
        }
        sig = SignatureManager.sign_request(payload, self.gateway_service_private_key_pem)

        return {
            "X-Gateway-Token": self.gateway_secret,
            "X-Gateway-Service": "AgentTrust-ActionGateway-Service",
            "X-Gateway-Timestamp": timestamp,
            "X-Gateway-Signature": sig
        }


    def execute_action(
        self,
        action: str,
        parameters: dict[str, Any],
        gateway_token: str,
        request_id: str,
        agent_id: str,
        approval_ref: str | None = None,
        auth_headers: dict[str, str] | None = None,
        idempotency_key: str | None = None,
        fencing_token: int | None = None,
        outbox_record: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Executes protected business API operation.
        Verifies gateway token and service-to-service signature.
        Enforces downstream fencing token validation to reject stale workers.
        Checks idempotency cache to prevent duplicate business executions.
        """
        # 1. Direct Access Check (Constant-time token validation against active/grace-period secrets)
        val_result = self.validate_gateway_token(gateway_token)
        if not val_result.is_valid:
            return {
                "success": False,
                "error": "DIRECT_ACCESS_DENIED",
                "message": f"Direct access forbidden. Gateway token validation failed: {val_result.error or 'INVALID_SECRET'}.",
                "secret_validation": {
                    "is_valid": False,
                    "error": val_result.error,
                    "key_id": val_result.key_id,
                    "version": val_result.version
                }
            }

        # 2. Service Signature Verification (Mandatory Signed Headers Required)
        if not auth_headers or not isinstance(auth_headers, dict):
            return {
                "success": False,
                "error": "DIRECT_ACCESS_DENIED",
                "message": "Missing mandatory Gateway Service Auth Headers."
            }

        gw_service = auth_headers.get("X-Gateway-Service")
        gw_ts = auth_headers.get("X-Gateway-Timestamp")
        gw_sig = auth_headers.get("X-Gateway-Signature")

        if gw_service != "AgentTrust-ActionGateway-Service" or not gw_sig or not gw_ts:
            return {
                "success": False,
                "error": "DIRECT_ACCESS_DENIED",
                "message": "Invalid Gateway Service Identity."
            }

        payload = {
            "gateway_service": gw_service,
            "request_id": request_id,
            "timestamp": gw_ts
        }
        if not SignatureManager.verify_signature(payload, gw_sig, self.gateway_service_public_key_pem):
            return {
                "success": False,
                "error": "DIRECT_ACCESS_DENIED",
                "message": "Gateway Service Signature Verification Failed."
            }

        # 2.5 Downstream Side-Effect Fencing Protection (Check A)
        # Prevents stale workers that paused and lost their lease from executing financial side effects.
        if fencing_token is not None:
            raw_key = idempotency_key or request_id
            target_scope = (
                parameters.get("target_account")
                or parameters.get("destination_account")
                or parameters.get("destination")
                or parameters.get("supplier_id")
                or parameters.get("employee_id")
                or parameters.get("resource")
            )
            scopes = [f"{agent_id}:{raw_key}", f"idemp:{agent_id}:{raw_key}"]
            if target_scope:
                scopes.append(f"{agent_id}:{target_scope}")
                scopes.append(f"agent_resource:{agent_id}:{target_scope}")
                scopes.append(f"resource:{target_scope}")

            with self._fencing_lock:
                if self._persistent_db_path and os.path.exists(self._persistent_db_path):
                    try:
                        with sqlite3.connect(self._persistent_db_path, timeout=30.0) as conn:
                            cursor = conn.cursor()
                            placeholders = ",".join("?" for _ in scopes)
                            cursor.execute(
                                f"SELECT scope, fencing_token FROM downstream_fencing_tokens WHERE scope IN ({placeholders})",
                                tuple(scopes)
                            )
                            for r_scope, r_tok in cursor.fetchall():
                                self._fencing_tokens[r_scope] = max(self._fencing_tokens.get(r_scope, 0), int(r_tok))
                    except Exception:
                        pass

                for sc in scopes:
                    active_token = self._fencing_tokens.get(sc, 0)
                    if fencing_token < active_token:
                        return {
                            "success": False,
                            "error": "STALE_FENCING_TOKEN",
                            "message": (
                                f"Side-effect rejected at downstream boundary: provided fencing token "
                                f"({fencing_token}) is lower than current active fencing token "
                                f"({active_token}) for scope '{sc}'."
                            )
                        }
                to_persist = []
                for sc in scopes:
                    if fencing_token > self._fencing_tokens.get(sc, 0):
                        self._fencing_tokens[sc] = fencing_token
                        to_persist.append((sc, fencing_token))
                if to_persist:
                    self._persist_fencing_tokens(to_persist)


        # 3. Scoped Idempotency Check per (agent_id, idempotency_key) with thread lock
        raw_key = idempotency_key or request_id
        cache_key = f"{agent_id}:{raw_key}"

        with self._idempotency_lock:
            if cache_key in self._idempotency_cache:
                cached_res = self._idempotency_cache[cache_key].copy()
                cached_res["idempotent_replay"] = True
                return cached_res

            # Execute business logic
            action_upper = action.upper()
            amt_canon = parameters.get("amount_canonical")
            amt_minor = parameters.get("amount_minor_units")
            curr = parameters.get("currency", "INR")

            if action_upper == "CREATE_PURCHASE_ORDER":
                supplier_id = parameters.get("supplier_id") or parameters.get("resource") or "SUPPLIER-001"
                item_name = parameters.get("item_name", "Procurement Office Supplies")
                amount = float(parameters.get("amount", 0))

                po_record = self.service.create_purchase_order(
                    request_id=request_id,
                    agent_id=agent_id,
                    supplier_id=supplier_id,
                    item_name=item_name,
                    amount=amount,
                    approval_ref=approval_ref,
                    amount_canonical=amt_canon,
                    amount_minor_units=amt_minor,
                    currency=curr,
                    outbox_record=outbox_record
                )
                res = {
                    "success": True,
                    "api_result": "EXECUTED",
                    "transaction_data": po_record
                }
                self._idempotency_cache[cache_key] = res
                return res

            elif action_upper == "TRANSFER_FUNDS":
                target_account = parameters.get("target_account") or parameters.get("resource") or "ACC-99901"
                amount = float(parameters.get("amount", 0))

                tf_record = self.service.create_fund_transfer(
                    request_id=request_id,
                    agent_id=agent_id,
                    target_account=target_account,
                    amount=amount,
                    approval_ref=approval_ref,
                    amount_canonical=amt_canon,
                    amount_minor_units=amt_minor,
                    currency=curr,
                    outbox_record=outbox_record
                )
                res = {
                    "success": True,
                    "api_result": "EXECUTED",
                    "transaction_data": tf_record
                }
                self._idempotency_cache[cache_key] = res
                return res

            elif action_upper == "CREATE_REIMBURSEMENT":
                employee_id = parameters.get("employee_id", "EMP-001")
                amount = float(parameters.get("amount", 0))

                tx_record = self.service.create_reimbursement(
                    request_id=request_id,
                    agent_id=agent_id,
                    employee_id=employee_id,
                    amount=amount,
                    approval_ref=approval_ref,
                    amount_canonical=amt_canon,
                    amount_minor_units=amt_minor,
                    currency=curr,
                    outbox_record=outbox_record
                )
                res = {
                    "success": True,
                    "api_result": "EXECUTED",
                    "transaction_data": tx_record
                }
                self._idempotency_cache[cache_key] = res
                return res

            elif action_upper == "READ_ACCOUNT":
                account_id = parameters.get("resource", "ACC-001")
                res = {
                    "success": True,
                    "api_result": "EXECUTED",
                    "transaction_data": {
                        "account_id": account_id,
                        "account_name": "Corporate Procurement Account",
                        "balance": 1500000.0,
                        "currency": "INR",
                        "status": "ACTIVE"
                    }
                }
                self._idempotency_cache[cache_key] = res
                return res

            else:
                return {
                    "success": False,
                    "error": "UNKNOWN_ACTION",
                    "message": f"Action '{action}' is not supported by Procurement/Finance API."
                }

    def query_transaction_status(
        self,
        agent_id: str,
        idempotency_key: str | None = None,
        request_id: str | None = None
    ) -> dict[str, Any] | None:
        """
        Authoritative external status check for uncertain outcomes (e.g. caller timeouts).
        Queries transaction status by idempotency_key or request_id without repeating the transfer.
        """
        raw_key = idempotency_key or request_id
        if not raw_key:
            return None
        cache_key = f"{agent_id}:{raw_key}"
        with self._idempotency_lock:
            if cache_key in self._idempotency_cache:
                return self._idempotency_cache[cache_key].copy()

        # Query service records directly for matching request_id / agent_id
        with self.service._lock:
            if request_id:
                for tx in self.service._fund_transfers.values():
                    if tx.get("request_id") == request_id and tx.get("agent_id") == agent_id:
                        return {"success": True, "api_result": "EXECUTED", "transaction_data": tx}
                for po in self.service._purchase_orders.values():
                    if po.get("request_id") == request_id and po.get("agent_id") == agent_id:
                        return {"success": True, "api_result": "EXECUTED", "transaction_data": po}
                for reimb in self.service._reimbursements.values():
                    if reimb.get("request_id") == request_id and reimb.get("agent_id") == agent_id:
                        return {"success": True, "api_result": "EXECUTED", "transaction_data": reimb}
        return None
