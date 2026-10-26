"""Unit tests for AgentTrust Fabric lifecycle safety and readiness helpers."""
from scripts.fabric_lifecycle import (
    _has_gossip_membership_event,
    bridge_health_ready,
    build_down_args,
    build_parser,
    is_running_state,
    is_successful_one_shot_state,
)


def test_normal_down_preserves_named_volumes() -> None:
    args = build_down_args(["docker", "compose"], destroy_volumes=False)
    assert args == ["docker", "compose", "down"]
    assert "--volumes" not in args
    assert "-v" not in args


def test_destroy_volumes_is_added_only_when_explicitly_requested() -> None:
    args = build_down_args(["docker", "compose"], destroy_volumes=True)
    assert args == ["docker", "compose", "down", "--volumes"]


def test_force_alias_requires_explicit_destroy_flag() -> None:
    parsed = build_parser().parse_args(["down", "-Force"])
    assert parsed.destroy_volumes is True
    default_parsed = build_parser().parse_args(["down"])
    assert default_parsed.destroy_volumes is False


def test_bridge_requires_online_and_fabric_ready() -> None:
    assert bridge_health_ready(True, {"status": "ONLINE", "fabric": "READY"})
    assert not bridge_health_ready(False, {"status": "ONLINE", "fabric": "READY"})
    assert not bridge_health_ready(True, {"status": "UNAVAILABLE", "fabric": "READY"})
    assert not bridge_health_ready(True, {"status": "ONLINE", "fabric": "SIMULATION"})
    assert not bridge_health_ready(True, None)


def test_service_state_classification() -> None:
    assert is_running_state({"Status": "running"})
    assert not is_running_state({"Status": "exited"})
    assert not is_running_state(None)
    assert is_successful_one_shot_state({"Status": "exited", "ExitCode": 0})
    assert not is_successful_one_shot_state({"Status": "exited", "ExitCode": 1})
    assert not is_successful_one_shot_state({"Status": "running", "ExitCode": 0})


def test_gossip_requires_a_real_membership_change_line() -> None:
    log = "peer0.org1.agenttrust.com | Membership view has changed. peers went online: [[peer0.org2.agenttrust.com:9051]]"
    assert _has_gossip_membership_event(log, "peer0.org2.agenttrust.com")
    assert not _has_gossip_membership_event("configured peer0.org2.agenttrust.com", "peer0.org2.agenttrust.com")
