import datetime
import os
import sqlite3
import threading
from typing import Any

from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager


class ProcurementService:
    """Mock Finance & Procurement Database & Business Logic with thread-safe concurrency control."""

    def __init__(self):
        self._reimbursements: dict[str, dict[str, Any]] = {}
        self._purchase_orders: dict[str, dict[str, Any]] = {}
        self._fund_transfers: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._po_counter = 5000
        self._tf_counter = 2000
        self._reimb_counter = 1000

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
        currency: str = "INR"
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
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            self._purchase_orders[po_id] = record
            return record

    def get_purchase_order(self, po_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._purchase_orders.get(po_id)

    def create_fund_transfer(
        self,
        request_id: str,
        agent_id: str,
        target_account: str,
        amount: float,
        approval_ref: str | None = None,
        amount_canonical: str | None = None,
        amount_minor_units: int | None = None,
        currency: str = "INR"
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
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            self._fund_transfers[tx_id] = record
            return record

    def create_reimbursement(
        self,
        request_id: str,
        agent_id: str,
        employee_id: str,
        amount: float,
        approval_ref: str | None = None,
        amount_canonical: str | None = None,
        amount_minor_units: int | None = None,
        currency: str = "INR"
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
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            self._reimbursements[tx_id] = record
            return record


class ProtectedFinanceAPI:
    """
    Protected Procurement & Finance API Wrapper enforcing Gateway Service Authentication & Direct Access Denial.
    Requires:
    1. Internal Gateway Secret Token
    2. Action Gateway Service Identity ('AgentTrust-ActionGateway-Service')
    3. Action Gateway Service RSA Signature verification.
    4. Idempotency Key check.
    5. Side-Effect Fencing Token check (Downstream boundary protection).
    """

    GATEWAY_SECRET = "AGT-GATEWAY-INTERNAL-SECRET-KEY-98765"

    def __init__(self, persistent_db_path: str | None = None):
        self.service = ProcurementService()
        self._idempotency_cache: dict[str, dict[str, Any]] = {}
        self._idempotency_lock = threading.Lock()
        self._fencing_tokens: dict[str, int] = {}
        self._fencing_lock = threading.Lock()
        self._persistent_db_path = persistent_db_path
        if persistent_db_path:
            self._init_fencing_db()
            self._load_fencing_tokens()
        # Generate Gateway Service RSA Keypair for Service-to-Service mTLS/Signing
        self.gateway_service_private_key = KeyManager.generate_key_pair(2048)
        self.gateway_service_public_key_pem = KeyManager.public_key_to_pem(
            self.gateway_service_private_key.public_key()
        )

    def _init_fencing_db(self) -> None:
        if not self._persistent_db_path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self._persistent_db_path)), exist_ok=True)
        with sqlite3.connect(self._persistent_db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
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
        with sqlite3.connect(self._persistent_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT scope, fencing_token FROM downstream_fencing_tokens")
            for row in cursor.fetchall():
                self._fencing_tokens[row[0]] = int(row[1])

    def _persist_fencing_token(self, scope: str, token: int) -> None:
        if not self._persistent_db_path:
            return
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(self._persistent_db_path) as conn:
            conn.execute("""
                INSERT INTO downstream_fencing_tokens (scope, fencing_token, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(scope) DO UPDATE SET
                    fencing_token = MAX(fencing_token, excluded.fencing_token),
                    updated_at = excluded.updated_at
            """, (scope, token, now_iso))
            conn.commit()

    def register_active_fencing_token(self, agent_id: str, scope: str, fencing_token: int) -> None:
        """Registers or advances active fencing token for a specific scope at downstream boundary."""
        with self._fencing_lock:
            scopes = [
                f"{agent_id}:{scope}",
                f"agent_resource:{agent_id}:{scope}",
                f"resource:{scope}"
            ]
            for sc in scopes:
                if fencing_token > self._fencing_tokens.get(sc, 0):
                    self._fencing_tokens[sc] = fencing_token
                    self._persist_fencing_token(sc, fencing_token)

    def create_gateway_auth_headers(self, request_id: str) -> dict[str, str]:
        """Helper for Action Gateway to generate signed service-to-service headers."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = {
            "gateway_service": "AgentTrust-ActionGateway-Service",
            "request_id": request_id,
            "timestamp": timestamp
        }
        priv_pem = KeyManager.private_key_to_pem(self.gateway_service_private_key)
        sig = SignatureManager.sign_request(payload, priv_pem)

        return {
            "X-Gateway-Token": self.GATEWAY_SECRET,
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
        fencing_token: int | None = None
    ) -> dict[str, Any]:
        """
        Executes protected business API operation.
        Verifies gateway token and service-to-service signature.
        Enforces downstream fencing token validation to reject stale workers.
        Checks idempotency cache to prevent duplicate business executions.
        """
        # 1. Direct Access Check (Gateway Token)
        if gateway_token != self.GATEWAY_SECRET:
            return {
                "success": False,
                "error": "DIRECT_ACCESS_DENIED",
                "message": "Direct access forbidden. Requests must originate from authorized AgentTrust Gateway."
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
                for sc in scopes:
                    if fencing_token > self._fencing_tokens.get(sc, 0):
                        self._fencing_tokens[sc] = fencing_token
                        self._persist_fencing_token(sc, fencing_token)

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
                    currency=curr
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
                    currency=curr
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
                    currency=curr
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
