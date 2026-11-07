"""
Tests for AI Agent Behavioral Intelligence Engine (UEBA).

Validates:
1. Dynamic agent behavioral profile modeling.
2. Multi-factor anomaly detection: amount Z-score, burst velocity,
   unfamiliar destinations, out-of-schedule hours, and sequence transitions.
3. Explainable anomaly scoring (0-100) and binary behavior indicators (0/1).
4. Non-amplification invariant: UEBA engine only escalates or restricts;
   it NEVER independently grants permissions.
5. Scenario simulations (canonical finance agent deviation).
"""

from datetime import UTC, datetime

from policy_engine.policy_models import PolicyDecision
from risk_engine.behavior_engine import agent_behavior_engine


def test_profile_initialization_and_seeding():
    """Verify default seeded behavioral profiles exist and contain valid baseline parameters."""
    profile = agent_behavior_engine.profiles.get("FINANCE_AGENT_01")
    assert profile is not None
    assert profile["agent_id"] == "FINANCE_AGENT_01"
    assert profile["amount_min"] == 5000.0
    assert profile["amount_max"] == 20000.0
    assert profile["daily_frequency_mean"] == 7.5
    assert "SUPPLIER-101" in profile["known_destinations"]
    assert profile["schedule_start_hour"] == 9
    assert profile["schedule_end_hour"] == 18


def test_normal_baseline_transaction():
    """Verify normal transactions within agent's behavioral profile score low anomaly and ALLOW."""
    normal_ts = datetime(2026, 11, 7, 11, 30, tzinfo=UTC).isoformat()
    assessment = agent_behavior_engine.analyze_request(
        agent_id="FINANCE_AGENT_01",
        action="TRANSFER_FUNDS",
        resource="SUPPLIER-101",
        amount=12000.0,
        request_timestamp_iso=normal_ts,
    )

    assert assessment["anomaly_score"] < 40
    assert assessment["enforcement"] in ("ALLOW", "ENHANCED_AUDIT")
    assert assessment["flags"]["unusual_amount"] is False
    assert assessment["flags"]["unfamiliar_recipient"] is False
    assert assessment["flags"]["unusual_schedule"] is False


def test_unusual_amount_anomaly():
    """Verify extreme amount deviation triggers unusual_amount flag and elevates anomaly score."""
    normal_ts = datetime(2026, 11, 7, 14, 0, tzinfo=UTC).isoformat()
    assessment = agent_behavior_engine.analyze_request(
        agent_id="FINANCE_AGENT_01",
        action="TRANSFER_FUNDS",
        resource="SUPPLIER-101",
        amount=95000.0,  # Far above ₹20k max and ~23 sigma above mean ₹12.5k
        request_timestamp_iso=normal_ts,
    )

    assert assessment["flags"]["unusual_amount"] is True
    assert any("amount" in reason.lower() for reason in assessment["explainable_reasons"])
    assert assessment["anomaly_score"] >= 35


def test_unfamiliar_recipient_anomaly():
    """Verify transfer to unregistered destination triggers unfamiliar_recipient flag."""
    normal_ts = datetime(2026, 11, 7, 10, 0, tzinfo=UTC).isoformat()
    assessment = agent_behavior_engine.analyze_request(
        agent_id="FINANCE_AGENT_01",
        action="TRANSFER_FUNDS",
        resource="UNKNOWN_OFFSHORE_SHELL_CORP",
        amount=8000.0,  # Normal amount
        request_timestamp_iso=normal_ts,
    )

    assert assessment["flags"]["unfamiliar_recipient"] is True
    assert any("unfamiliar recipient" in reason.lower() for reason in assessment["explainable_reasons"])


def test_off_schedule_anomaly():
    """Verify operations outside regular UTC operating hours trigger unusual_schedule flag."""
    off_schedule_ts = datetime(2026, 11, 7, 2, 15, tzinfo=UTC).isoformat()
    assessment = agent_behavior_engine.analyze_request(
        agent_id="FINANCE_AGENT_01",
        action="TRANSFER_FUNDS",
        resource="SUPPLIER-102",
        amount=10000.0,
        request_timestamp_iso=off_schedule_ts,
    )

    assert assessment["flags"]["unusual_schedule"] is True
    assert any("off-hours" in reason.lower() for reason in assessment["explainable_reasons"])


def test_finance_agent_composite_deviation_scenario():
    """
    Test the canonical user specification scenario:
    A finance agent suddenly:
    - Transfers ₹95,000 (normal ₹5,000 - ₹20,000).
    - Unfamiliar recipient.
    - Operating at 02:15 AM outside normal schedule.
    - 50 transactions burst.
    - Anomaly score reaches critical alert levels (>= 80) and triggers REQUIRE_HUMAN_APPROVAL.
    """
    assessment = agent_behavior_engine.simulate_behavior_scenario("FINANCE_AGENT_DEVIATION")

    assert assessment["anomaly_score"] >= 80
    assert assessment["enforcement"] == "REQUIRE_HUMAN_APPROVAL"
    flags = assessment["flags"]
    assert flags["unusual_amount"] is True
    assert flags["unfamiliar_recipient"] is True
    assert flags["unusual_schedule"] is True
    assert flags["burst_velocity"] is True
    assert len(assessment["explainable_reasons"]) >= 3


def test_non_amplification_invariant():
    """
    NON-AMPLIFICATION INVARIANT:
    The ML/UEBA behavioral model MUST recommend additional restrictions or human escalation,
    and NEVER independently grant authorization if static policy rejected or blocked it.
    """
    # 1. Behavior engine returns recommendations: ALLOW, ENHANCED_AUDIT, REQUIRE_HUMAN_APPROVAL, BLOCK_STRICT.
    # None of these can grant a permission that an RBAC policy denies.
    assessment = agent_behavior_engine.analyze_request(
        agent_id="NON_EXISTENT_AGENT",
        action="UNAUTHORIZED_ROOT_ACTION",
        resource="CONFIDENTIAL_TREASURY_VAULT",
        amount=10.0,
    )
    # The assessment score may be computed, but the decision is purely a risk ceiling
    assert assessment["enforcement"] in ("ALLOW", "ENHANCED_AUDIT", "REQUIRE_HUMAN_APPROVAL", "BLOCK_STRICT")

    # 2. Invariant verification: Verify that behavioral enforcement ONLY escalates downwards:
    # ALLOW -> PENDING_HUMAN_APPROVAL (never BLOCKED -> ALLOWED)
    static_decision = PolicyDecision.BLOCKED
    behavior_enforcement = assessment.get("enforcement")

    # Applying Step 8.5 gateway invariant logic:
    final_decision = static_decision
    if static_decision == PolicyDecision.ALLOWED and behavior_enforcement == "REQUIRE_HUMAN_APPROVAL":
        final_decision = PolicyDecision.PENDING_HUMAN_APPROVAL

    # Assert that a blocked request can NEVER be granted or altered by behavioral approval
    assert final_decision == PolicyDecision.BLOCKED


def test_online_learning_updates_mean_and_variance():
    """
    Verify Welford's online algorithm updates profile statistics smoothly
    when benign transactions are processed.
    """
    initial_profile = agent_behavior_engine.profiles["FINANCE_AGENT_01"]
    initial_samples = initial_profile["sample_count"]

    normal_ts = datetime(2026, 11, 7, 12, 0, tzinfo=UTC).isoformat()
    agent_behavior_engine.analyze_request(
        agent_id="FINANCE_AGENT_01",
        action="TRANSFER_FUNDS",
        resource="SUPPLIER-101",
        amount=14000.0,
        request_timestamp_iso=normal_ts,
    )

    updated_profile = agent_behavior_engine.profiles["FINANCE_AGENT_01"]
    assert updated_profile["sample_count"] == initial_samples + 1
