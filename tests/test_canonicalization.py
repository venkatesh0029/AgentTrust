import json
import pytest
from evidence_manager.hash_manager import HashManager
from evidence_manager.provenance import ProvenanceBuilder

def test_canonical_serialization_key_ordering_invariance():
    """
    Evidence A with different JSON key orderings must produce the EXACT SAME canonical SHA-256 hash.
    """
    ev1 = {
        "evidence_id": "EVIDENCE-REQ-001",
        "agent_id": "FINANCE-AGENT-001",
        "action": "CREATE_REIMBURSEMENT",
        "input": {"amount": 7500.0, "employee_id": "EMP-001"}
    }

    ev2 = {
        "input": {"employee_id": "EMP-001", "amount": 7500.0},
        "action": "CREATE_REIMBURSEMENT",
        "evidence_id": "EVIDENCE-REQ-001",
        "agent_id": "FINANCE-AGENT-001"
    }

    hash1 = HashManager.calculate_evidence_hash(ev1)
    hash2 = HashManager.calculate_evidence_hash(ev2)

    assert hash1 == hash2

def test_canonical_serialization_single_field_modification_causes_mismatch():
    """
    Modifying even a single field must cause a hash mismatch (H1 != H2).
    """
    ev_original = ProvenanceBuilder.build_evidence(
        request_id="REQ-CANON-001",
        agent_id="FINANCE-AGENT-001",
        action="CREATE_REIMBURSEMENT",
        resource="FINANCE_API",
        parameters={"employee_id": "EMP-001", "amount": 7500.0},
        decision="ALLOWED",
        reason="WITHIN_AUTHORITY_LIMIT",
        policy_id="FIN-POLICY-001",
        policy_version="1.0",
        agent_version="1.0",
        api_result="EXECUTED"
    )

    ev_modified = ev_original.copy()
    ev_modified["input"] = {"employee_id": "EMP-001", "amount": 75000.0}  # Changed 7,500 to 75,000

    hash_orig = HashManager.calculate_evidence_hash(ev_original)
    hash_mod = HashManager.calculate_evidence_hash(ev_modified)

    assert hash_orig != hash_mod
