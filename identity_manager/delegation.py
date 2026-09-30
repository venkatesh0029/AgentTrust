"""
Delegation with Attenuation Service for AgentTrust Framework.
Provides capability delegation tokens allowing a primary AI agent to delegate
narrower sub-scope permissions to secondary sub-agents with non-reexpandable attenuation.
"""

import time
import json
import hashlib
from typing import Dict, Any, List, Optional
from identity_manager.signature_manager import SignatureManager

class DelegationTokenManager:

    @staticmethod
    def create_delegated_token(
        issuer_agent_id: str,
        delegate_agent_id: str,
        allowed_actions: List[str],
        maximum_amount: float,
        issuer_private_key: str,
        parent_token: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600
    ) -> Dict[str, Any]:
        """
        Creates a signed capability delegation token.
        If a parent_token is provided, enforces strict scope attenuation:
        sub-token allowed_actions MUST be a subset of parent, and maximum_amount MUST be <= parent.
        """
        if parent_token:
            # Validate attenuation invariant: scope must shrink or remain equal, never widen
            parent_actions = parent_token.get("allowed_actions", [])
            for action in allowed_actions:
                if action not in parent_actions:
                    raise ValueError(f"Scope Attenuation Violation: Action '{action}' not present in parent token")

            parent_max = float(parent_token.get("maximum_amount", 0.0))
            if maximum_amount > parent_max:
                raise ValueError(f"Scope Attenuation Violation: Amount {maximum_amount} exceeds parent max {parent_max}")

        now = int(time.time())
        token_body = {
            "token_id": f"DEL-TOK-{hashlib.sha256(f'{issuer_agent_id}:{delegate_agent_id}:{now}'.encode()).hexdigest()[:12].upper()}",
            "issuer_agent_id": issuer_agent_id,
            "delegate_agent_id": delegate_agent_id,
            "allowed_actions": allowed_actions,
            "maximum_amount": maximum_amount,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "parent_token_id": parent_token.get("token_id") if parent_token else None,
            "delegation_depth": (parent_token.get("delegation_depth", 0) + 1) if parent_token else 1
        }

        # Sign token body with issuer private key
        signature = SignatureManager.sign_request(token_body, issuer_private_key)
        token_body["signature"] = signature
        return token_body

    @staticmethod
    def verify_delegation_chain(
        token: Dict[str, Any],
        action: str,
        amount: float,
        issuer_public_key: str
    ) -> Dict[str, Any]:
        """
        Verifies token signature, expiration, action scope, and monetary amount limit.
        """
        if int(time.time()) > token.get("expires_at", 0):
            return {"valid": False, "reason": "DELEGATION_TOKEN_EXPIRED"}

        token_to_verify = token.copy()
        sig = token_to_verify.pop("signature", None)
        if not SignatureManager.verify_signature(token_to_verify, sig, issuer_public_key):
            return {"valid": False, "reason": "INVALID_DELEGATION_TOKEN_SIGNATURE"}

        if action not in token.get("allowed_actions", []):
            return {"allowed": False, "reason": f"ACTION_EXCEEDS_DELEGATED_SCOPE: '{action}' not in delegated permissions"}

        if amount > float(token.get("maximum_amount", 0.0)):
            return {"allowed": False, "reason": f"AMOUNT_EXCEEDS_DELEGATED_LIMIT: {amount} > delegated limit {token.get('maximum_amount')}"}

        return {"valid": True, "allowed": True, "reason": "DELEGATED_SCOPE_VALIDATED"}
