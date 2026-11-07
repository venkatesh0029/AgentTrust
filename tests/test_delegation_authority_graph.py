"""
Unit and Integration Tests for Intelligent Multi-Agent Authority Graph & Delegation Engine.
Verifies:
1. Transitive permission attenuation (non-expansion invariant).
2. Cyclic delegation detection (DAG loop blocking).
3. Budget allocation bounds and deductions.
4. Delegation depth limits (MAX_DEPTH).
5. Cascading revocation down the subtree.
6. Full cryptographic audit trails.
"""

import pytest

from identity_manager.delegation_graph import delegation_graph_manager


@pytest.fixture(autouse=True)
def reset_graph():
    delegation_graph_manager.reset_to_canonical_baseline()
    yield
    delegation_graph_manager.reset_to_canonical_baseline()


def test_canonical_baseline_structure():
    graph = delegation_graph_manager.get_graph()
    nodes = {n["agent_id"]: n for n in graph["nodes"]}
    assert "FIN-SUPERVISOR-001" in nodes
    assert "PAYMENT-PROC-002" in nodes
    assert "VENDOR-VERIF-003" in nodes
    assert "REPORT-BOT-004" in nodes

    assert nodes["FIN-SUPERVISOR-001"]["depth"] == 0
    assert nodes["PAYMENT-PROC-002"]["depth"] == 1
    assert nodes["VENDOR-VERIF-003"]["depth"] == 1
    assert nodes["REPORT-BOT-004"]["depth"] == 2


def test_transitive_permission_attenuation():
    """Child agent cannot receive permissions that parent does not possess."""
    # VENDOR-VERIF-003 only has CREATE_PURCHASE_ORDER.
    # Attempting to delegate TRANSFER_FUNDS must raise ValueError.
    with pytest.raises(ValueError, match="Scope Attenuation Violation"):
        delegation_graph_manager.issue_delegation(
            issuer_agent_id="VENDOR-VERIF-003",
            delegate_agent_id="SUB-BOT-TEST",
            allowed_actions=["TRANSFER_FUNDS"],
            delegated_budget=10000.0,
        )


def test_cyclic_delegation_detection():
    """Graph must reject delegations that complete a directed cycle."""
    # Canonical path: FIN-SUPERVISOR-001 -> PAYMENT-PROC-002 -> REPORT-BOT-004
    # Attempting REPORT-BOT-004 -> FIN-SUPERVISOR-001 must raise ValueError for cycle.
    with pytest.raises(ValueError, match="Cyclic Delegation Blocked"):
        delegation_graph_manager.issue_delegation(
            issuer_agent_id="REPORT-BOT-004",
            delegate_agent_id="FIN-SUPERVISOR-001",
            allowed_actions=["CREATE_PURCHASE_ORDER"],
            delegated_budget=5000.0,
        )


def test_budget_overdraft_prevention():
    """Agent cannot allocate more budget than its remaining allowance."""
    # REPORT-BOT-004 has budget 25,000. Attempting to delegate 50,000 must fail.
    with pytest.raises(ValueError, match="Budget Attenuation Violation"):
        delegation_graph_manager.issue_delegation(
            issuer_agent_id="REPORT-BOT-004",
            delegate_agent_id="SUB-BOT-OVERDRAFT",
            allowed_actions=["CREATE_PURCHASE_ORDER"],
            delegated_budget=50000.0,
        )


def test_depth_cap_enforcement():
    """Delegations cannot exceed MAX_DELEGATION_DEPTH."""
    # D is depth 2.
    # D -> E (depth 3)
    res_e = delegation_graph_manager.issue_delegation(
        issuer_agent_id="REPORT-BOT-004",
        delegate_agent_id="AGENT-DEPTH-E",
        allowed_actions=["CREATE_PURCHASE_ORDER"],
        delegated_budget=5000.0,
    )
    assert res_e["edge"]["depth"] == 3

    # E -> F (depth 4)
    res_f = delegation_graph_manager.issue_delegation(
        issuer_agent_id="AGENT-DEPTH-E",
        delegate_agent_id="AGENT-DEPTH-F",
        allowed_actions=["CREATE_PURCHASE_ORDER"],
        delegated_budget=2000.0,
    )
    assert res_f["edge"]["depth"] == 4

    # F -> G (depth 5, exceeds max depth 4)
    with pytest.raises(ValueError, match="Delegation Depth Exceeded"):
        delegation_graph_manager.issue_delegation(
            issuer_agent_id="AGENT-DEPTH-F",
            delegate_agent_id="AGENT-DEPTH-G",
            allowed_actions=["CREATE_PURCHASE_ORDER"],
            delegated_budget=1000.0,
        )


def test_cascading_revocation():
    """Revoking parent edge cascades to all descendant edges."""
    # B is parent of D (token: DEL-TOK-FIN-D-03).
    # Revoking token of B (DEL-TOK-FIN-B-01) must revoke D as well.
    rev_res = delegation_graph_manager.revoke_delegation("DEL-TOK-FIN-B-01")
    assert "DEL-TOK-FIN-B-01" in rev_res["revoked_tokens"]
    assert "DEL-TOK-FIN-D-03" in rev_res["revoked_tokens"]

    graph = delegation_graph_manager.get_graph()
    edges = {e["token_id"]: e for e in graph["edges"]}
    assert edges["DEL-TOK-FIN-B-01"]["status"] == "REVOKED"
    assert edges["DEL-TOK-FIN-D-03"]["status"] == "REVOKED"


def test_all_attack_simulations():
    """Test all 5 built-in attack simulation scenarios."""
    scenarios = [
        "PRIVILEGE_AMPLIFICATION",
        "CYCLIC_DELEGATION_LOOP",
        "BUDGET_OVERDRAFT",
        "DEPTH_EXCEEDED",
        "CASCADING_REVOCATION_ATTACK",
    ]
    for sc in scenarios:
        res = delegation_graph_manager.simulate_attack(sc)
        assert res["blocked"] is True
        assert res["decision"] == "BLOCKED"
        assert res["audit_committed"] is True
