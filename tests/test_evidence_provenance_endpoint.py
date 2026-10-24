from unittest.mock import patch
from fastapi.testclient import TestClient

from server import app, evidence_store, chain_writer
from evidence_manager.merkle_tree import MerkleTree


client = TestClient(app)


def test_missing_evidence_returns_404():
    """Verify that requesting provenance for non-existent evidence returns 404 rather than fallback data."""
    req_id = "NON_EXISTENT_REQ_FOR_PROVENANCE_TEST"
    response = client.get(f"/evidence/provenance/{req_id}")
    assert response.status_code == 404
    assert f"Evidence record not found for request ID '{req_id}'." in response.json()["detail"]


def test_existing_evidence_provenance_returns_200():
    """Verify that requesting provenance for an existing evidence record returns 200 with lineage."""
    req_id = "REQ-EXISTING-EVIDENCE-TEST"
    ev_record = {
        "evidence_id": f"EVIDENCE-{req_id}",
        "request_id": req_id,
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_PURCHASE_ORDER",
        "resource": "FINANCE_API",
        "parameters": {"amount": 5000.0, "supplier_id": "SUPPLIER-101"},
        "decision": "ALLOWED",
        "reason": "POLICY_PASSED",
        "policy_id": "FIN-POL-001",
        "policy_version": "1.0",
        "input_hash": "a" * 64,
        "output_hash": "b" * 64,
    }

    with patch.object(evidence_store, "get_evidence", return_value=ev_record):
        response = client.get(f"/evidence/provenance/{req_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == req_id
        assert data["provenance_record"]["evidence_id"] == f"EVIDENCE-{req_id}"
        assert len(data["lineage"]) == 5
        assert data["lineage"][0]["step"] == "AGENT_SIGNED_INPUT"


def test_missing_merkle_event_returns_404():
    """Verify that requesting a Merkle proof for a request not in audit events returns 404."""
    req_id = "NON_EXISTENT_REQ_FOR_MERKLE_TEST"
    with patch.object(chain_writer, "get_chain_events", return_value=[]):
        response = client.get(f"/audit/merkle-proof/{req_id}")
        assert response.status_code == 404
        assert f"Merkle inclusion proof for request '{req_id}' could not be generated." in response.json()["detail"]


def test_existing_merkle_proof_uses_correct_target_hash():
    """Verify that an existing event generates a proof matching its exact event hash."""
    target_req_id = "REQ-TARGET-EVENT-001"
    other_req_id = "REQ-OTHER-EVENT-002"
    target_hash = "1" * 64
    other_hash = "2" * 64

    mock_events = [
        {"request_id": other_req_id, "event_hash": other_hash},
        {"request_id": target_req_id, "event_hash": target_hash},
    ]

    with patch.object(chain_writer, "get_chain_events", return_value=mock_events):
        response = client.get(f"/audit/merkle-proof/{target_req_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == target_req_id
        assert data["leaf_hash"] == target_hash
        assert "merkle_root" in data
        assert "proof" in data
        assert MerkleTree.verify_inclusion_proof(data["leaf_hash"], data["proof"], data["merkle_root"]) is True
