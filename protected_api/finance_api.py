import datetime
from typing import Dict, Any, List, Optional
from identity_manager.key_manager import KeyManager
from identity_manager.signature_manager import SignatureManager

class ProcurementService:
    """Mock Finance & Procurement Database & Business Logic."""

    def __init__(self):
        self._reimbursements: Dict[str, Dict[str, Any]] = {}
        self._purchase_orders: Dict[str, Dict[str, Any]] = {}
        self._fund_transfers: Dict[str, Dict[str, Any]] = {}

    def create_purchase_order(
        self, request_id: str, agent_id: str, supplier_id: str, item_name: str, amount: float, approval_ref: Optional[str] = None
    ) -> Dict[str, Any]:
        po_id = f"PO-{len(self._purchase_orders) + 5001}"
        record = {
            "po_id": po_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "supplier_id": supplier_id,
            "item_name": item_name,
            "amount": amount,
            "currency": "INR",
            "status": "ISSUED",
            "approval_reference": approval_ref,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._purchase_orders[po_id] = record
        return record

    def get_purchase_order(self, po_id: str) -> Optional[Dict[str, Any]]:
        return self._purchase_orders.get(po_id)

    def create_fund_transfer(
        self, request_id: str, agent_id: str, target_account: str, amount: float, approval_ref: Optional[str] = None
    ) -> Dict[str, Any]:
        tx_id = f"TX-TRANSFER-{len(self._fund_transfers) + 2001}"
        record = {
            "transaction_id": tx_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "target_account": target_account,
            "amount": amount,
            "currency": "INR",
            "status": "TRANSFERRED",
            "approval_reference": approval_ref,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self._fund_transfers[tx_id] = record
        return record

    def create_reimbursement(
        self, request_id: str, agent_id: str, employee_id: str, amount: float, approval_ref: Optional[str] = None
    ) -> Dict[str, Any]:
        tx_id = f"TX-REIMB-{len(self._reimbursements) + 1001}"
        record = {
            "transaction_id": tx_id,
            "request_id": request_id,
            "agent_id": agent_id,
            "employee_id": employee_id,
            "amount": amount,
            "currency": "INR",
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
    """

    GATEWAY_SECRET = "AGT-GATEWAY-INTERNAL-SECRET-KEY-98765"

    def __init__(self):
        self.service = ProcurementService()
        self._idempotency_cache: Dict[str, Dict[str, Any]] = {}
        # Generate Gateway Service RSA Keypair for Service-to-Service mTLS/Signing
        self.gateway_service_private_key = KeyManager.generate_key_pair(2048)
        self.gateway_service_public_key_pem = KeyManager.public_key_to_pem(
            self.gateway_service_private_key.public_key()
        )

    def create_gateway_auth_headers(self, request_id: str) -> Dict[str, str]:
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
        parameters: Dict[str, Any],
        gateway_token: str,
        request_id: str,
        agent_id: str,
        approval_ref: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes protected business API operation.
        Verifies gateway token and service-to-service signature.
        Checks idempotency cache to prevent duplicate business executions.
        """
        # 1. Direct Access Check (Gateway Token)
        if gateway_token != self.GATEWAY_SECRET:
            return {
                "success": False,
                "error": "DIRECT_ACCESS_DENIED",
                "message": "Direct access forbidden. Requests must originate from authorized AgentTrust Gateway."
            }

        # 2. Service Signature Verification
        if auth_headers:
            gw_service = auth_headers.get("X-Gateway-Service")
            gw_ts = auth_headers.get("X-Gateway-Timestamp")
            gw_sig = auth_headers.get("X-Gateway-Signature")

            if gw_service != "AgentTrust-ActionGateway-Service" or not gw_sig:
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

        # 3. Idempotency Check
        cache_key = idempotency_key or request_id
        if cache_key in self._idempotency_cache:
            cached_res = self._idempotency_cache[cache_key].copy()
            cached_res["idempotent_replay"] = True
            return cached_res

        # Execute business logic
        action_upper = action.upper()

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
                approval_ref=approval_ref
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
                approval_ref=approval_ref
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
                approval_ref=approval_ref
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
