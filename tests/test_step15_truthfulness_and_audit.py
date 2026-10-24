"""
Regression Test Suite for Step 15 Truthfulness & Integration Audit.
Covers:
- Empty vs. tampered ledger integrity verification
- Benchmark percentiles and concurrency scaling metrics
- Attack matrix genuine pass/fail calculations & repeated execution immutability
- Scenarios router delegation without import errors
"""

import pytest
from fastapi.testclient import TestClient

from server import app, run_all_attack_scenarios
from audit_writer.chain_writer import AuditChainWriter
from benchmarks.benchmark_engine import calculate_percentiles
from routers.scenarios import run_attack_matrix as router_run_attack_matrix


client = TestClient(app)


def test_empty_chain_integrity_verification():
    """Verify that an empty audit chain returns valid=False with reason='EMPTY_CHAIN' rather than false tampering."""
    writer = AuditChainWriter()
    writer._records.clear()  # Simulate empty chain before genesis or initialization
    res = writer.verify_chain_integrity()
    assert res["valid"] is False
    assert res.get("reason") == "EMPTY_CHAIN"


def test_intact_chain_integrity_verification():
    """Verify that an untampered audit chain returns valid=True with status='VERIFIED_INTACT' and total_records."""
    writer = AuditChainWriter()
    writer.write_event(
        event_type="ACTION_ALLOWED",
        request_id="REQ-TEST-CHAIN-001",
        agent_id="FINANCE-AGENT-001",
        request_hash="hash001",
        risk_score=5.0,
        policy_version="1.0",
        decision="ALLOWED",
        execution_result="SUCCESS",
    )
    res = writer.verify_chain_integrity()
    assert res["valid"] is True
    assert res["status"] == "VERIFIED_INTACT"
    assert res["total_records"] == 2  # Genesis + 1 event
    assert "latest_record_hash" in res


def test_tampered_chain_integrity_verification():
    """Verify that tampering with an audit record produces TAMPERING_DETECTED with tampered sequence info."""
    writer = AuditChainWriter()
    writer.write_event(
        event_type="ACTION_ALLOWED",
        request_id="REQ-TEST-CHAIN-002",
        agent_id="FINANCE-AGENT-001",
        request_hash="hash002",
        risk_score=10.0,
        policy_version="1.0",
        decision="ALLOWED",
        execution_result="SUCCESS",
    )
    tampered = writer.simulate_tamper_record(1, "decision", "TAMPERED_FORGERY")
    assert tampered is True

    res = writer.verify_chain_integrity()
    assert res["valid"] is False
    assert res["status"] == "TAMPERING_DETECTED"
    assert res["tampered_sequence"] == 1
    assert "reason" in res


def test_benchmark_percentiles_calculation():
    """Verify calculate_percentiles computes genuine mean, p95, p50, min, max, stddev without estimation multipliers."""
    sample_data = [10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 22.0, 24.0, 26.0, 30.0]
    metrics = calculate_percentiles(sample_data)

    assert metrics["mean"] == pytest.approx(19.2, 0.01)
    assert metrics["min"] == 10.0
    assert metrics["max"] == 30.0
    assert "p95" in metrics
    assert metrics["p95"] > metrics["mean"]
    assert "stddev" in metrics
    assert metrics["stddev"] > 0

    # Empty data handling
    empty_metrics = calculate_percentiles([])
    assert empty_metrics["mean"] == 0
    assert empty_metrics["p95"] == 0


def test_attack_matrix_dynamic_calculation():
    """Verify that run_all_attack_scenarios dynamically computes passed/failed/pass_rate from real decisions."""
    result = run_all_attack_scenarios()
    summary = result["summary"]
    details = result["details"]

    assert summary["total"] == 20
    assert len(details) == 20
    assert summary["passed"] + summary["failed"] == 20
    expected_rate = f"{(summary['passed'] / 20 * 100.0):.1f}%"
    assert summary["pass_rate"] == expected_rate

    for item in details:
        assert "scenario_id" in item
        assert "expected" in item
        assert "actual" in item
        assert "status" in item
        if item["actual"] == item["expected"]:
            assert "PASSED" in item["status"]
            assert item["error"] is None
        else:
            assert "FAILED" in item["status"]


def test_repeated_attack_matrix_execution():
    """Verify running the attack matrix consecutively succeeds without Fabric immutability collisions."""
    res1 = client.post("/scenarios/attack-matrix/run-all")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["summary"]["total"] == 20

    res2 = client.post("/scenarios/attack-matrix/run-all")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["summary"]["total"] == 20
    assert data2["summary"]["passed"] == 20


def test_scenarios_router_delegation():
    """Verify that routers.scenarios.run_attack_matrix cleanly delegates without ImportError."""
    result = router_run_attack_matrix()
    assert result["summary"]["total"] == 20
    assert len(result["details"]) == 20
