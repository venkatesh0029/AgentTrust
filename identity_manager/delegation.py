"""
Delegation with Attenuation Service for AgentTrust Framework.
Provides capability delegation tokens allowing a primary AI agent to delegate
narrower sub-scope permissions to secondary sub-agents with non-reexpandable attenuation,
audience binding, depth caps, and revocation checks.
"""

import time
import json
import uuid
import hashlib
from typing import Dict, Any, List, Optional, Set
from identity_manager.signature_manager import SignatureManager

MAX_DELEGATION_DEPTH = 3
_REVOKED_TOKENS: Set[str] = set()

class DelegationTokenManager:

    @staticmethod
    def revoke_token(token_id: str) -> None:
        """Revokes a capability delegation token ID."""
        _REVOKED_TOKENS.add(token_id)

    @staticmethod
    def is_token_revoked(token_id: str) -> bool:
        """Checks if delegation token ID is revoked."""
        return token_id in _REVOKED_TOKENS

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
        Enforces:
        - Non-negative maximum_amount
        - Max delegation depth cap
        - Scope attenuation (allowed_actions subset of parent, max_amount <= parent)
        - Unique UUID-based token ID
        """
        if maximum_amount < 0:
            raise ValueError(f"Invalid Delegation Limit: maximum_amount cannot be negative ({maximum_amount})")

        current_depth = (parent_token.get("delegation_depth", 0) + 1) if parent_token else 1
        if current_depth > MAX_DELEGATION_DEPTH:
            raise ValueError(f"Delegation Depth Exceeded: Depth {current_depth} exceeds MAX_DELEGATION_DEPTH ({MAX_DELEGATION_DEPTH})")

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
        token_id = f"DEL-TOK-{uuid.uuid4().hex[:12].upper()}"

        token_body = {
            "token_id": token_id,
            "issuer_agent_id": issuer_agent_id,
            "delegate_agent_id": delegate_agent_id,
            "allowed_actions": allowed_actions,
            "maximum_amount": maximum_amount,
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "parent_token_id": parent_token.get("token_id") if parent_token else None,
            "delegation_depth": current_depth
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
        issuer_public_key: str,
        requesting_agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verifies token signature, revocation, audience binding, depth cap, expiration, action scope, and monetary amount limit.
        """
        token_id = token.get("token_id", "")
        if DelegationTokenManager.is_token_revoked(token_id):
            return {"valid": False, "allowed": False, "reason": "DELEGATION_TOKEN_REVOKED"}

        if int(time.time()) > token.get("expires_at", 0):
            return {"valid": False, "allowed": False, "reason": "DELEGATION_TOKEN_EXPIRED"}

        # Audience Binding: delegate_agent_id in token MUST match the caller
        if requesting_agent_id and token.get("delegate_agent_id") != requesting_agent_id:
            return {
                "valid": False,
                "allowed": False,
                "reason": f"DELEGATION_AUDIENCE_MISMATCH: Token target '{token.get('delegate_agent_id')}' != requesting agent '{requesting_agent_id}'"
            }

        # Depth Cap Enforcement
        if token.get("delegation_depth", 1) > MAX_DELEGATION_DEPTH:
            return {"valid": False, "allowed": False, "reason": f"DELEGATION_DEPTH_EXCEEDED: Depth {token.get('delegation_depth')} > max {MAX_DELEGATION_DEPTH}"}

        # Amount bounds check
        if amount < 0:
            return {"valid": False, "allowed": False, "reason": "INVALID_NEGATIVE_AMOUNT"}

        if amount > float(token.get("maximum_amount", 0.0)):
            return {"valid": False, "allowed": False, "reason": f"AMOUNT_EXCEEDS_DELEGATED_LIMIT: {amount} > delegated limit {token.get('maximum_amount')}"}

        if action not in token.get("allowed_actions", []):
            return {"valid": False, "allowed": False, "reason": f"ACTION_EXCEEDS_DELEGATED_SCOPE: '{action}' not in delegated permissions"}

        # Verify signature
        token_to_verify = token.copy()
        sig = token_to_verify.pop("signature", None)
        if not SignatureManager.verify_signature(token_to_verify, sig, issuer_public_key):
            return {"valid": False, "allowed": False, "reason": "INVALID_DELEGATION_TOKEN_SIGNATURE"}

        return {"valid": True, "allowed": True, "reason": "DELEGATED_SCOPE_VALIDATED"}
