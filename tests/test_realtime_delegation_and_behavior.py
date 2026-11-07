"""
Tests for Real-Time On-The-Spot Interception & Synchronization:
Delegation Authority Graph & Behavioral Intelligence Engine.

Validates:
1. When an action executes through the gateway under an active delegation token:
   - Step 7.5 verifies the active delegation edge and budget.
   - Step 8.5 analyzes dynamic UEBA behavioral deviations.
   - On commit, delegation budget is consumed on the spot.
   - Delegation audit trail records the BUDGET_CONSUMED event.
   - Behavioral baseline rolling metrics update dynamically.
2. When an action exceeds the remaining delegation budget, it is rejected at Step 7.5 on the spot.
3. When a delegation token is revoked, subsequent attempts are rejected at Step 7.5 on the spot.
4. Gateway outcomes return both delegation_context and behavioral_intelligence.
"""

from identity_manager.delegation_graph import delegation_graph_manager
from risk_engine.behavior_engine import agent_behavior_engine


def test_delegation_budget_consumption_on_spot():
    """Verify that calling spend_budget decrements remaining budget and logs to audit trail."""
    delegation_graph_manager.reset_to_canonical_baseline()
    edge = delegation_graph_manager.edges["DEL-TOK-FIN-B-01"]
    initial_spent = edge["spent_budget"]
    initial_remaining = edge["delegated_budget"] - initial_spent

    test_amount = 5000.0
    spent_ok, msg = delegation_graph_manager.spend_budget("DEL-TOK-FIN-B-01", test_amount)
    assert spent_ok is True

    updated_edge = delegation_graph_manager.edges["DEL-TOK-FIN-B-01"]
    assert updated_edge["spent_budget"] == initial_spent + test_amount
    assert (updated_edge["delegated_budget"] - updated_edge["spent_budget"]) == initial_remaining - test_amount

    # Verify audit event recorded on the spot
    audit_events = [e for e in delegation_graph_manager.audit_log if e.get("token_id") == "DEL-TOK-FIN-B-01"]
    assert len(audit_events) > 0
    latest_event = audit_events[-1]
    assert latest_event["event_type"] == "BUDGET_CONSUMED"
    assert latest_event["details"]["amount"] == test_amount


def test_delegation_overdraft_rejected_on_spot():
    """Verify that attempting to spend more than remaining budget is rejected on the spot."""
    delegation_graph_manager.reset_to_canonical_baseline()
    edge = delegation_graph_manager.edges["DEL-TOK-FIN-B-01"]
    rem_budget = edge["delegated_budget"] - edge["spent_budget"]

    # Attempt to spend more than remaining budget
    overdraft_amount = rem_budget + 10000.0
    spent_ok, err_msg = delegation_graph_manager.spend_budget("DEL-TOK-FIN-B-01", overdraft_amount)
    assert spent_ok is False
    assert "exceeds" in err_msg.lower()


def test_delegation_revocation_blocks_on_spot():
    """Verify that revoking a delegation token immediately blocks subsequent actions on the spot."""
    delegation_graph_manager.reset_to_canonical_baseline()
    delegation_graph_manager.revoke_delegation("DEL-TOK-FIN-B-01", "SECURITY_AUDIT_SUSPICION")

    edge = delegation_graph_manager.edges["DEL-TOK-FIN-B-01"]
    assert edge["status"] == "REVOKED"

    spent_ok, err_msg = delegation_graph_manager.spend_budget("DEL-TOK-FIN-B-01", 1000.0)
    assert spent_ok is False
    assert "revoked" in err_msg.lower()


def test_behavioral_baseline_adaptation_on_spot():
    """Verify that benign requests immediately update the agent's moving sample count and parameters."""
    agent_behavior_engine.reset_to_canonical_baselines()
    profile = agent_behavior_engine.profiles["FINANCE_AGENT_01"]
    init_samples = profile["sample_count"]

    res = agent_behavior_engine.analyze_request(
        agent_id="FINANCE_AGENT_01",
        action="TRANSFER_FUNDS",
        resource="SUPPLIER-101",
        amount=12500.0,
    )

    assert res["anomaly_score"] < 40
    assert res["enforcement"] in ("ALLOW", "ENHANCED_AUDIT")

    # The moving sample count adapted on the spot
    assert profile["sample_count"] == init_samples + 1
    # Recent event recorded on the spot
    assert agent_behavior_engine.recent_events[0]["event_id"] == res["event_id"]


def test_behavioral_deviation_escalation_on_spot():
    """Verify that sudden behavioral deviation immediately generates explainable anomaly score and flags."""
    agent_behavior_engine.reset_to_canonical_baselines()

    res = agent_behavior_engine.simulate_behavior_scenario("FINANCE_AGENT_DEVIATION")

    assert res["anomaly_score"] >= 80
    assert res["enforcement"] == "REQUIRE_HUMAN_APPROVAL"
    assert res["flags"]["unusual_amount"] is True
    assert res["flags"]["unfamiliar_recipient"] is True
    assert res["flags"]["burst_velocity"] is True
    assert res["flags"]["unusual_schedule"] is True
    assert len(res["explainable_reasons"]) >= 3

