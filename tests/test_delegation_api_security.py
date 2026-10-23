import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from server import app, agent_registry, policy_loader, AGENT_PRIVATE_KEYS


client = TestClient(app)


def test_delegation_requires_admin_authorization():
    """Verify that issuing a delegation token requires admin authorization (fails with 403 if missing or unauthorized)."""
    payload = {
        "issuer_agent_id": "FINANCE-AGENT-001",
        "delegate_agent_id": "PROCUREMENT-AGENT-002",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 1000.0,
        "ttl_seconds": 3600,
    }

    # No role header returns 401 Unauthorized
    res_no_auth = client.post("/identity/delegation/issue", json=payload)
    assert res_no_auth.status_code == 401

    # Auditor role has no issue_delegation permission -> returns 403 Forbidden
    res_auditor = client.post(
        "/identity/delegation/issue",
        json=payload,
        headers={"X-Admin-Role": "AUDITOR"},
    )
    assert res_auditor.status_code == 403


def test_delegation_rejects_same_issuer_and_delegate():
    """Verify that an agent cannot delegate capabilities to itself."""
    payload = {
        "issuer_agent_id": "FINANCE-AGENT-001",
        "delegate_agent_id": "FINANCE-AGENT-001",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 1000.0,
        "ttl_seconds": 3600,
    }
    res = client.post(
        "/identity/delegation/issue",
        json=payload,
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res.status_code == 422
    assert "different" in res.json()["detail"].lower()


def test_delegation_rejects_unregistered_agents():
    """Verify that unknown issuers or delegates return 404 and prevent using global default signing keys."""
    # Unknown issuer
    payload_unknown_issuer = {
        "issuer_agent_id": "UNKNOWN-ISSUER-999",
        "delegate_agent_id": "PROCUREMENT-AGENT-002",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 1000.0,
        "ttl_seconds": 3600,
    }
    res_issuer = client.post(
        "/identity/delegation/issue",
        json=payload_unknown_issuer,
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res_issuer.status_code == 404

    # Unknown delegate
    payload_unknown_delegate = {
        "issuer_agent_id": "FINANCE-AGENT-001",
        "delegate_agent_id": "UNKNOWN-DELEGATE-999",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 1000.0,
        "ttl_seconds": 3600,
    }
    res_delegate = client.post(
        "/identity/delegation/issue",
        json=payload_unknown_delegate,
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res_delegate.status_code == 404


def test_delegation_rejects_inactive_agents():
    """Verify that non-ACTIVE agents cannot issue or receive delegation tokens."""
    # Mock suspended issuer
    mock_issuer = {
        "agent_id": "SUSPENDED-AGENT-001",
        "status": "SUSPENDED",
        "policy_id": "FIN-POL-001",
        "capabilities": ["CREATE_PURCHASE_ORDER"],
    }
    mock_delegate = {
        "agent_id": "ACTIVE-DELEGATE-002",
        "status": "ACTIVE",
        "policy_id": "FIN-POL-001",
        "capabilities": ["CREATE_PURCHASE_ORDER"],
    }

    def mock_get_agent(aid):
        if aid == "SUSPENDED-AGENT-001":
            return mock_issuer
        if aid == "ACTIVE-DELEGATE-002":
            return mock_delegate
        return None

    with patch.object(agent_registry, "get_agent", side_effect=mock_get_agent):
        res = client.post(
            "/identity/delegation/issue",
            json={
                "issuer_agent_id": "SUSPENDED-AGENT-001",
                "delegate_agent_id": "ACTIVE-DELEGATE-002",
                "allowed_actions": ["CREATE_PURCHASE_ORDER"],
                "maximum_amount": 1000.0,
                "ttl_seconds": 3600,
            },
            headers={"X-Admin-Role": "SYSTEM_ADMIN"},
        )
        assert res.status_code == 409


def test_delegation_rejects_missing_signing_key():
    """Verify that an issuer without an available private key cannot issue tokens."""
    mock_issuer = {
        "agent_id": "KEYLESS-AGENT-001",
        "status": "ACTIVE",
        "policy_id": "FIN-POL-001",
        "capabilities": ["CREATE_PURCHASE_ORDER"],
    }
    mock_delegate = {
        "agent_id": "ACTIVE-DELEGATE-002",
        "status": "ACTIVE",
        "policy_id": "FIN-POL-001",
        "capabilities": ["CREATE_PURCHASE_ORDER"],
    }

    def mock_get_agent(aid):
        if aid == "KEYLESS-AGENT-001":
            return mock_issuer
        if aid == "ACTIVE-DELEGATE-002":
            return mock_delegate
        return None

    with patch.object(agent_registry, "get_agent", side_effect=mock_get_agent):
        with patch.dict(AGENT_PRIVATE_KEYS, {}, clear=True):
            res = client.post(
                "/identity/delegation/issue",
                json={
                    "issuer_agent_id": "KEYLESS-AGENT-001",
                    "delegate_agent_id": "ACTIVE-DELEGATE-002",
                    "allowed_actions": ["CREATE_PURCHASE_ORDER"],
                    "maximum_amount": 1000.0,
                    "ttl_seconds": 3600,
                },
                headers={"X-Admin-Role": "SYSTEM_ADMIN"},
            )
            assert res.status_code == 400
            assert "key" in res.json()["detail"].lower()


def test_delegation_rejects_scope_exceeding_capabilities_or_policy():
    """Verify that delegation rejects actions beyond issuer capabilities or amounts exceeding policy limits."""
    # Actions exceeding policy
    res_bad_action = client.post(
        "/identity/delegation/issue",
        json={
            "issuer_agent_id": "FINANCE-AGENT-001",
            "delegate_agent_id": "PROCUREMENT-AGENT-002",
            "allowed_actions": ["DROP_DATABASE_ADMIN"],
            "maximum_amount": 1000.0,
            "ttl_seconds": 3600,
        },
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res_bad_action.status_code == 403

    # Amount exceeding policy limit (FIN-POL-001 has max 100,000.0)
    res_excess_amount = client.post(
        "/identity/delegation/issue",
        json={
            "issuer_agent_id": "FINANCE-AGENT-001",
            "delegate_agent_id": "PROCUREMENT-AGENT-002",
            "allowed_actions": ["CREATE_PURCHASE_ORDER"],
            "maximum_amount": 999999999.0,
            "ttl_seconds": 3600,
        },
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res_excess_amount.status_code == 403


def test_valid_delegation_issuance_and_retrieval():
    """Verify that a valid delegation request succeeds and is retrievable via GET /identity/delegation."""
    payload = {
        "issuer_agent_id": "FINANCE-AGENT-001",
        "delegate_agent_id": "PROCUREMENT-AGENT-002",
        "allowed_actions": ["CREATE_PURCHASE_ORDER"],
        "maximum_amount": 4500.0,
        "ttl_seconds": 1800,
    }

    res_issue = client.post(
        "/identity/delegation/issue",
        json=payload,
        headers={"X-Admin-Role": "SYSTEM_ADMIN"},
    )
    assert res_issue.status_code == 200
    data = res_issue.json()
    assert data["status"] == "SUCCESS"
    assert "token" in data
    token = data["token"]
    assert token["issuer_agent_id"] == "FINANCE-AGENT-001"
    assert token["delegate_agent_id"] == "PROCUREMENT-AGENT-002"
    assert token["maximum_amount"] == 4500.0
    assert "signature" in token

    # Check listing endpoint
    res_list = client.get("/identity/delegation")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] >= 1
    assert any(t["token_id"] == token["token_id"] for t in list_data["tokens"])
